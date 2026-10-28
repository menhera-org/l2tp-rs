// SPDX-License-Identifier: MIT

//! Blocking counterparts of the async API.
//!
//! [`L2tpHandle`] runs a dedicated thread with its own current-thread Tokio
//! runtime that owns the async [`crate::L2tpHandle`]. Every blocking call
//! hands its work to that thread and waits on a channel, so it never blocks
//! on or nests inside the caller's runtime: calling it from a plain thread,
//! from `tokio::task::spawn_blocking`, or from inside another runtime all
//! work. Calling it from an async task blocks that task's thread, as any
//! blocking call would.
//!
//! The handles returned here own their async counterparts and hand them back
//! to the worker thread when dropped, so the best-effort deletion on drop
//! keeps working. The worker thread stops once the last [`L2tpHandle`] clone
//! and every handle created from it are gone, after pending deletions have
//! completed.

use std::{
    future::Future,
    os::fd::{AsFd, BorrowedFd},
    pin::Pin,
    sync::{Arc, Mutex, mpsc},
    thread::{JoinHandle, ThreadId},
};

use futures::{
    StreamExt,
    future::{self, Either},
};

use crate::{
    EventSocket, IpEndpoint, L2tpEvent, L2tpIfName, NetNs, SessionConfig,
    SessionId, SessionInfo, SessionModify, SessionStats, TunnelConfig,
    TunnelId, TunnelInfo, TunnelSocket, TunnelStats, UdpEndpoint,
};

type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type Task = Box<dyn FnOnce(crate::L2tpHandle) -> BoxFuture + Send + 'static>;

struct Worker {
    tasks: Option<tokio::sync::mpsc::UnboundedSender<Task>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    thread_id: ThreadId,
}

impl Worker {
    fn send(&self, task: Task) -> crate::Result<()> {
        self.tasks
            .as_ref()
            .and_then(|tasks| tasks.send(task).ok())
            .ok_or_else(|| crate::Error::other("the l2tp worker has stopped"))
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Closing the channel lets the worker finish pending deletions and
        // exit; joining it is only possible from another thread.
        drop(self.tasks.take());
        if std::thread::current().id() != self.thread_id
            && let Ok(mut thread) = self.thread.lock()
            && let Some(thread) = thread.take()
        {
            let _ = thread.join();
        }
    }
}

/// Blocking counterpart of [`crate::L2tpHandle`].
///
/// Clones share the worker thread and its netlink connection.
#[derive(Clone)]
pub struct L2tpHandle {
    worker: Arc<Worker>,
}

impl std::fmt::Debug for L2tpHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("blocking::L2tpHandle")
            .field("thread_id", &self.worker.thread_id)
            .finish_non_exhaustive()
    }
}

impl L2tpHandle {
    /// Starts the worker thread and opens the netlink connection in the
    /// calling thread's network namespace.
    pub fn new() -> crate::Result<Self> {
        Self::start(None)
    }

    /// Starts the worker thread with its netlink connection in `netns`,
    /// which needs `CAP_SYS_ADMIN`; see [`NetNs`].
    pub fn new_in(netns: &NetNs) -> crate::Result<Self> {
        Self::start(Some(netns.try_clone()?))
    }

    fn start(netns: Option<NetNs>) -> crate::Result<Self> {
        let (task_tx, mut task_rx) =
            tokio::sync::mpsc::unbounded_channel::<Task>();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<crate::Result<()>>(1);
        let thread = std::thread::Builder::new()
            .name("l2tp-blocking".to_string())
            .spawn(move || {
                let runtime =
                    match tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(err) => {
                            let _ = ready_tx.send(Err(err.into()));
                            return;
                        }
                    };
                runtime.block_on(async move {
                    let handle = match &netns {
                        None => crate::L2tpHandle::new().await,
                        Some(netns) => crate::L2tpHandle::new_in(netns).await,
                    };
                    let handle = match handle {
                        Ok(handle) => handle,
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                            return;
                        }
                    };
                    if ready_tx.send(Ok(())).is_err() {
                        return;
                    }
                    let mut tasks = tokio::task::JoinSet::new();
                    loop {
                        // Reap finished tasks while accepting new ones, so
                        // the set holds only the work in flight.
                        let task = if tasks.is_empty() {
                            task_rx.recv().await
                        } else {
                            let recv = task_rx.recv();
                            futures::pin_mut!(recv);
                            let join = tasks.join_next();
                            futures::pin_mut!(join);
                            match future::select(recv, join).await {
                                Either::Left((task, _)) => task,
                                Either::Right(_) => continue,
                            }
                        };
                        match task {
                            Some(task) => {
                                tasks.spawn(task(handle.clone()));
                            }
                            None => break,
                        }
                    }
                    // Let deletions queued by dropped handles finish.
                    while tasks.join_next().await.is_some() {}
                });
            })?;
        let thread_id = thread.thread().id();
        ready_rx.recv().map_err(|_| {
            crate::Error::other("the l2tp worker stopped during startup")
        })??;
        Ok(Self {
            worker: Arc::new(Worker {
                tasks: Some(task_tx),
                thread: Mutex::new(Some(thread)),
                thread_id,
            }),
        })
    }

    /// Runs `f` on the worker and waits for its result.
    fn call<T, F, Fut>(&self, f: F) -> crate::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(crate::L2tpHandle) -> Fut + Send + 'static,
        Fut: Future<Output = crate::Result<T>> + Send + 'static,
    {
        let (tx, rx) = mpsc::sync_channel(1);
        self.worker.send(Box::new(move |handle| {
            Box::pin(async move {
                let _ = tx.send(f(handle).await);
            })
        }))?;
        rx.recv().unwrap_or_else(|_| {
            Err(crate::Error::other("the l2tp worker dropped the request"))
        })
    }

    /// Runs `f` on the worker without waiting for it.
    fn detach<F, Fut>(&self, f: F)
    where
        F: FnOnce(crate::L2tpHandle) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let _ = self
            .worker
            .send(Box::new(move |handle| Box::pin(f(handle))));
    }

    /// See [`crate::L2tpHandle::create_tunnel`].
    pub fn create_tunnel(
        &self,
        config: TunnelConfig,
        socket: TunnelSocket,
    ) -> crate::Result<TunnelHandle> {
        let inner = self.call(move |handle| async move {
            handle.create_tunnel(config, socket).await
        })?;
        Ok(TunnelHandle::new(inner, self.clone()))
    }

    /// See [`crate::L2tpHandle::create_unmanaged_tunnel`].
    pub fn create_unmanaged_tunnel(
        &self,
        config: TunnelConfig,
    ) -> crate::Result<TunnelHandle> {
        let inner = self.call(move |handle| async move {
            handle.create_unmanaged_tunnel(config).await
        })?;
        Ok(TunnelHandle::new(inner, self.clone()))
    }

    /// See [`crate::L2tpHandle::open_tunnel`].
    pub fn open_tunnel(
        &self,
        tunnel_id: TunnelId,
    ) -> crate::Result<TunnelHandle> {
        let inner = self.call(move |handle| async move {
            handle.open_tunnel(tunnel_id).await
        })?;
        Ok(TunnelHandle::new(inner, self.clone()))
    }

    /// See [`crate::L2tpHandle::create_session`].
    pub fn create_session(
        &self,
        config: SessionConfig,
    ) -> crate::Result<SessionHandle> {
        let inner = self.call(move |handle| async move {
            handle.create_session(config).await
        })?;
        Ok(SessionHandle::new(inner, self.clone()))
    }

    /// See [`crate::L2tpHandle::open_session`].
    pub fn open_session(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
    ) -> crate::Result<SessionHandle> {
        let inner = self.call(move |handle| async move {
            handle.open_session(tunnel_id, session_id).await
        })?;
        Ok(SessionHandle::new(inner, self.clone()))
    }

    /// See [`crate::L2tpHandle::open_session_by_ifname`].
    pub fn open_session_by_ifname(
        &self,
        ifname: L2tpIfName,
    ) -> crate::Result<SessionHandle> {
        let inner = self.call(move |handle| async move {
            handle.open_session_by_ifname(&ifname).await
        })?;
        Ok(SessionHandle::new(inner, self.clone()))
    }

    /// See [`crate::L2tpHandle::get_tunnel`].
    pub fn get_tunnel(&self, tunnel_id: TunnelId) -> crate::Result<TunnelInfo> {
        self.call(
            move |handle| async move { handle.get_tunnel(tunnel_id).await },
        )
    }

    /// See [`crate::L2tpHandle::get_session`].
    pub fn get_session(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
    ) -> crate::Result<SessionInfo> {
        self.call(move |handle| async move {
            handle.get_session(tunnel_id, session_id).await
        })
    }

    /// See [`crate::L2tpHandle::get_session_by_ifname`].
    pub fn get_session_by_ifname(
        &self,
        ifname: L2tpIfName,
    ) -> crate::Result<SessionInfo> {
        self.call(move |handle| async move {
            handle.get_session_by_ifname(&ifname).await
        })
    }

    /// See [`crate::L2tpHandle::list_tunnels`].
    pub fn list_tunnels(&self) -> crate::Result<Vec<TunnelInfo>> {
        self.call(|handle| async move { handle.list_tunnels().await })
    }

    /// See [`crate::L2tpHandle::list_sessions`].
    pub fn list_sessions(
        &self,
        tunnel_id: TunnelId,
    ) -> crate::Result<Vec<SessionInfo>> {
        self.call(
            move |handle| async move { handle.list_sessions(tunnel_id).await },
        )
    }

    /// See [`crate::L2tpHandle::list_all_sessions`].
    pub fn list_all_sessions(&self) -> crate::Result<Vec<SessionInfo>> {
        self.call(|handle| async move { handle.list_all_sessions().await })
    }

    /// See [`crate::L2tpHandle::delete_tunnel`].
    pub fn delete_tunnel(&self, tunnel_id: TunnelId) -> crate::Result<()> {
        self.call(
            move |handle| async move { handle.delete_tunnel(tunnel_id).await },
        )
    }

    /// See [`crate::L2tpHandle::delete_session`].
    pub fn delete_session(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
    ) -> crate::Result<()> {
        self.call(move |handle| async move {
            handle.delete_session(tunnel_id, session_id).await
        })
    }

    /// See [`crate::L2tpHandle::delete_session_by_ifname`].
    pub fn delete_session_by_ifname(
        &self,
        ifname: L2tpIfName,
    ) -> crate::Result<()> {
        self.call(move |handle| async move {
            handle.delete_session_by_ifname(&ifname).await
        })
    }

    /// See [`crate::L2tpHandle::tunnel_stats`].
    pub fn tunnel_stats(
        &self,
        tunnel_id: TunnelId,
    ) -> crate::Result<TunnelStats> {
        self.call(
            move |handle| async move { handle.tunnel_stats(tunnel_id).await },
        )
    }

    /// See [`crate::L2tpHandle::session_stats`].
    pub fn session_stats(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
    ) -> crate::Result<SessionStats> {
        self.call(move |handle| async move {
            handle.session_stats(tunnel_id, session_id).await
        })
    }

    /// See [`crate::L2tpHandle::session_stats_by_ifname`].
    pub fn session_stats_by_ifname(
        &self,
        ifname: L2tpIfName,
    ) -> crate::Result<SessionStats> {
        self.call(move |handle| async move {
            handle.session_stats_by_ifname(&ifname).await
        })
    }

    /// See [`crate::L2tpHandle::modify_session`].
    pub fn modify_session(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
        params: SessionModify,
    ) -> crate::Result<()> {
        self.call(move |handle| async move {
            handle.modify_session(tunnel_id, session_id, params).await
        })
    }

    /// See [`crate::L2tpHandle::modify_session_by_ifname`].
    pub fn modify_session_by_ifname(
        &self,
        ifname: L2tpIfName,
        params: SessionModify,
    ) -> crate::Result<()> {
        self.call(move |handle| async move {
            handle.modify_session_by_ifname(&ifname, params).await
        })
    }

    /// Subscribes to kernel notifications; see
    /// [`crate::L2tpHandle::events`].
    ///
    /// The returned iterator blocks in `next` until an event arrives and
    /// ends when the subscription's connection closes. It keeps the worker
    /// alive while it exists. On kernels that multicast across namespaces,
    /// events may describe objects outside this handle's namespace; use them
    /// as hints to query local state, as described by [`crate::L2tpEvent`].
    pub fn events(&self) -> crate::Result<EventIter> {
        // A std channel carries the events, so `next` blocks without
        // touching any Tokio context; the oneshot tells the forwarder that
        // the iterator is gone.
        let (event_tx, event_rx) = mpsc::channel();
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<crate::Result<()>>(1);
        self.detach(move |handle| async move {
            let mut events = match handle.events().await {
                Ok(events) => events,
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                    return;
                }
            };
            if ready_tx.send(Ok(())).is_err() {
                return;
            }
            // Stop as soon as the iterator is dropped, so the worker never
            // waits on this task at shutdown.
            loop {
                match future::select(&mut stop_rx, events.next()).await {
                    Either::Left(_) => break,
                    Either::Right((Some(item), _)) => {
                        if event_tx.send(item).is_err() {
                            break;
                        }
                    }
                    Either::Right((None, _)) => break,
                }
            }
        });
        ready_rx.recv().map_err(|_| {
            crate::Error::other("the l2tp worker dropped the subscription")
        })??;
        Ok(EventIter {
            receiver: event_rx,
            _stop: stop_tx,
            _worker: self.clone(),
        })
    }

    /// Subscribes to kernel notifications with no queue between the socket
    /// and the iterator; see [`crate::L2tpHandle::events_bounded`] and
    /// [`BoundedEventIter`].
    pub fn events_bounded(&self) -> crate::Result<BoundedEventIter> {
        let socket = self.event_socket()?.into_blocking()?;
        Ok(BoundedEventIter { socket })
    }

    /// Opens a non-blocking [`EventSocket`] in the handle's original
    /// namespace; see [`crate::L2tpHandle::event_socket`]. The socket needs
    /// neither the worker nor a Tokio context and outlives the handle.
    pub fn event_socket(&self) -> crate::Result<EventSocket> {
        self.call(|handle| async move { handle.event_socket().await })
    }
}

/// Blocking iterator over kernel notifications read straight from the
/// socket; see [`crate::BoundedEvents`] for the bound and how loss is
/// reported.
///
/// `next` blocks in `recvmsg` until a notification or an error arrives and
/// never returns `None`. The iterator needs neither the worker nor a Tokio
/// context, and works on after the handle is dropped. Dropping it leaves
/// the multicast group.
#[derive(Debug)]
pub struct BoundedEventIter {
    /// Made blocking, so `try_next` waits rather than returning `None`.
    socket: EventSocket,
}

impl Iterator for BoundedEventIter {
    type Item = crate::Result<L2tpEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        self.socket.try_next()
    }
}

impl AsFd for BoundedEventIter {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

/// Blocking iterator over kernel notifications; see [`L2tpHandle::events`].
///
/// `next` blocks the calling thread without depending on a Tokio context,
/// so it also works from `spawn_blocking` or an async task, where it blocks
/// that task's thread. Dropping the iterator leaves the multicast group.
#[derive(Debug)]
pub struct EventIter {
    receiver: mpsc::Receiver<crate::Result<L2tpEvent>>,
    _stop: tokio::sync::oneshot::Sender<()>,
    _worker: L2tpHandle,
}

impl Iterator for EventIter {
    type Item = crate::Result<L2tpEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.recv().ok()
    }
}

/// Blocking counterpart of [`crate::TunnelHandle`].
///
/// The handle owns the async handle and its managed socket. On drop it is
/// returned to the worker thread, which performs the best-effort deletion
/// when auto-delete is enabled.
#[derive(Debug)]
pub struct TunnelHandle {
    tunnel_id: TunnelId,
    inner: Option<crate::TunnelHandle>,
    l2tp: L2tpHandle,
}

impl TunnelHandle {
    fn new(inner: crate::TunnelHandle, l2tp: L2tpHandle) -> Self {
        Self {
            tunnel_id: inner.tunnel_id(),
            inner: Some(inner),
            l2tp,
        }
    }

    /// Returns this handle's tunnel identifier.
    pub fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    /// Returns the managed socket, if the tunnel was created as managed.
    pub fn socket(&self) -> Option<&TunnelSocket> {
        self.inner.as_ref().and_then(|inner| inner.socket())
    }

    /// Returns a mutable managed socket reference, if present.
    pub fn socket_mut(&mut self) -> Option<&mut TunnelSocket> {
        self.inner.as_mut().and_then(|inner| inner.socket_mut())
    }

    /// See [`crate::TunnelHandle::auto_delete`].
    pub fn auto_delete(&self) -> bool {
        self.inner.as_ref().is_some_and(|inner| inner.auto_delete())
    }

    /// See [`crate::TunnelHandle::set_auto_delete`].
    pub fn set_auto_delete(&mut self, v: bool) {
        if let Some(inner) = &mut self.inner {
            inner.set_auto_delete(v);
        }
    }

    /// Fetches current tunnel information from the kernel.
    pub fn get(&self) -> crate::Result<TunnelInfo> {
        self.l2tp.get_tunnel(self.tunnel_id)
    }

    /// Fetches tunnel statistics from the kernel.
    pub fn stats(&self) -> crate::Result<TunnelStats> {
        self.l2tp.tunnel_stats(self.tunnel_id)
    }

    /// Deletes the tunnel and waits until the kernel has removed it; see
    /// [`crate::L2tpHandle::delete_tunnel`].
    pub fn delete(mut self) -> crate::Result<()> {
        let Some(inner) = self.inner.take() else {
            return Err(crate::Error::other("the tunnel handle was consumed"));
        };
        self.l2tp.call(move |_| inner.delete())
    }

    /// Reconnects a managed UDP tunnel socket to a new remote endpoint.
    pub fn reconnect_udp(&self, new_remote: &UdpEndpoint) -> crate::Result<()> {
        self.socket()
            .ok_or(crate::Error::UnmanagedSocket)?
            .reconnect_udp(new_remote)
    }

    /// Reconnects a managed IP tunnel socket to a new remote endpoint.
    pub fn reconnect_ip(&self, new_remote: &IpEndpoint) -> crate::Result<()> {
        self.socket()
            .ok_or(crate::Error::UnmanagedSocket)?
            .reconnect_ip(new_remote)
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        // Delete on the worker and await it there, so the worker's shutdown
        // waits for the deletion instead of abandoning a task the async
        // handle's own drop would merely spawn.
        if let Some(inner) = self.inner.take()
            && inner.auto_delete()
        {
            self.l2tp.detach(move |_| async move {
                let _ = inner.delete().await;
            });
        }
    }
}

/// Blocking counterpart of [`crate::SessionHandle`].
#[derive(Debug)]
pub struct SessionHandle {
    tunnel_id: TunnelId,
    session_id: SessionId,
    ifname: Option<L2tpIfName>,
    ifindex: Option<u32>,
    inner: Option<crate::SessionHandle>,
    l2tp: L2tpHandle,
}

impl SessionHandle {
    fn new(inner: crate::SessionHandle, l2tp: L2tpHandle) -> Self {
        Self {
            tunnel_id: inner.tunnel_id(),
            session_id: inner.session_id(),
            ifname: inner.ifname().copied(),
            ifindex: inner.ifindex(),
            inner: Some(inner),
            l2tp,
        }
    }

    /// Returns the parent tunnel identifier.
    pub fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    /// Returns this handle's session identifier.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the interface name the session was created with; see
    /// [`crate::SessionHandle::ifname`].
    pub fn ifname(&self) -> Option<&L2tpIfName> {
        self.ifname.as_ref()
    }

    /// Returns the interface index of the session's device; see
    /// [`crate::SessionHandle::ifindex`].
    pub fn ifindex(&self) -> Option<u32> {
        self.ifindex
    }

    /// See [`crate::SessionHandle::auto_delete`].
    pub fn auto_delete(&self) -> bool {
        self.inner.as_ref().is_some_and(|inner| inner.auto_delete())
    }

    /// See [`crate::SessionHandle::set_auto_delete`].
    pub fn set_auto_delete(&mut self, v: bool) {
        if let Some(inner) = &mut self.inner {
            inner.set_auto_delete(v);
        }
    }

    /// Fetches current session information from the kernel.
    pub fn get(&self) -> crate::Result<SessionInfo> {
        self.l2tp.get_session(self.tunnel_id, self.session_id)
    }

    /// Fetches session statistics from the kernel.
    pub fn stats(&self) -> crate::Result<SessionStats> {
        self.l2tp.session_stats(self.tunnel_id, self.session_id)
    }

    /// Applies mutable session parameters.
    pub fn modify(&self, params: SessionModify) -> crate::Result<()> {
        self.l2tp
            .modify_session(self.tunnel_id, self.session_id, params)
    }

    /// Deletes the session and waits for the kernel to acknowledge it.
    pub fn delete(mut self) -> crate::Result<()> {
        let Some(inner) = self.inner.take() else {
            return Err(crate::Error::other("the session handle was consumed"));
        };
        self.l2tp.call(move |_| inner.delete())
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take()
            && inner.auto_delete()
        {
            self.l2tp.detach(move |_| async move {
                let _ = inner.delete().await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ENODEV as root, EPERM unprivileged, or no `l2tp` family at all where
    /// the module is not loaded (CI runners).
    fn permission_or_missing(err: &crate::Error) {
        let errno = err.raw_os_error();
        assert!(
            errno == Some(libc::EPERM)
                || errno == Some(libc::ENODEV)
                || matches!(err, crate::Error::FamilyResolution(_)),
            "{err:?}"
        );
    }

    #[test]
    fn requests_complete_from_a_plain_thread() {
        let handle = L2tpHandle::new().unwrap();
        let err = handle.get_tunnel(TunnelId(u32::MAX)).unwrap_err();
        permission_or_missing(&err);
        let clone = handle.clone();
        let err = std::thread::spawn(move || {
            clone.open_tunnel(TunnelId(u32::MAX)).unwrap_err()
        })
        .join()
        .unwrap();
        permission_or_missing(&err);
    }

    #[test]
    fn requests_complete_inside_spawn_blocking() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let err = runtime.block_on(async {
            // A nested `block_on` would panic here; the worker thread does
            // not need the caller's runtime at all.
            tokio::task::spawn_blocking(|| {
                let handle = L2tpHandle::new().unwrap();
                // Fails as root (no such tunnel) and unprivileged (EPERM).
                handle
                    .open_tunnel(TunnelId(u32::MAX))
                    .map(|_| ())
                    .unwrap_err()
            })
            .await
            .unwrap()
        });
        permission_or_missing(&err);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = runtime.block_on(async {
            tokio::task::spawn_blocking(|| {
                L2tpHandle::new()
                    .unwrap()
                    .get_session(TunnelId(u32::MAX), SessionId(1))
                    .unwrap_err()
            })
            .await
            .unwrap()
        });
        permission_or_missing(&err);
    }

    #[test]
    fn worker_stops_when_the_last_handle_drops() {
        let handle = L2tpHandle::new().unwrap();
        let worker = Arc::downgrade(&handle.worker);
        drop(handle);
        assert!(worker.upgrade().is_none());
    }

    #[test]
    fn event_iterator_blocks_without_a_tokio_context() {
        let handle = L2tpHandle::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        tx.send(Err(crate::Error::other("probe"))).unwrap();
        drop(tx);
        let mut iter = EventIter {
            receiver: rx,
            _stop: stop_tx,
            _worker: handle,
        };
        // Inside an async context a Tokio blocking receive would panic.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let (first, second) = runtime
            .block_on(async { (iter.next().is_some(), iter.next().is_none()) });
        assert!(first);
        assert!(second);
        // Dropping the iterator tells the forwarder to stop.
        drop(iter);
        assert!(runtime.block_on(stop_rx).is_err());
    }

    #[test]
    fn event_subscription_can_be_opened_and_dropped() {
        let handle = L2tpHandle::new().unwrap();
        match handle.events() {
            Ok(events) => drop(events),
            // Without the l2tp family (module not loaded) resolution fails.
            Err(crate::Error::FamilyResolution(_)) => {}
            Err(err) => panic!("unexpected error: {err:?}"),
        }
        match handle.events_bounded() {
            // The iterator outlives the handle and its worker.
            Ok(events) => {
                drop(handle);
                drop(events);
            }
            Err(crate::Error::FamilyResolution(_)) => {}
            Err(err) => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn event_socket_outlives_the_handle_without_blocking() {
        let handle = L2tpHandle::new().unwrap();
        match handle.event_socket() {
            Ok(mut socket) => {
                drop(handle);
                assert!(!matches!(socket.try_next(), Some(Err(_))));
            }
            Err(crate::Error::FamilyResolution(_)) => {}
            Err(err) => panic!("unexpected error: {err:?}"),
        }
    }
}

// SPDX-License-Identifier: MIT

use std::{
    fmt, io,
    os::fd::{AsFd, AsRawFd},
    sync::{Arc, PoisonError},
};

use futures::{Stream, StreamExt, channel::mpsc::UnboundedReceiver};
use genetlink::{GenetlinkHandle, message::RawGenlMessage};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_MULTIPART, NLM_F_REQUEST,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_l2tp::{L2tpAttribute, L2tpMessage};
use netlink_proto::{
    Connection,
    sys::{AsyncSocket, SocketAddr},
};

use crate::{
    Events, L2tpIfName, L2tpIfNameExt, L2tpVersion, NetNs, PseudowireType,
    SessionConfig, SessionHandle, SessionId, SessionInfo, SessionModify,
    SessionStats, TunnelConfig, TunnelHandle, TunnelId, TunnelInfo,
    TunnelSocket, TunnelStats,
    link::LinkMonitor,
    netlink::{self, SessionRef},
    netns::Owner,
};

/// Name of the generic-netlink multicast group the kernel announces L2TP
/// changes on (`L2TP_GENL_MCGROUP`).
const EVENTS_GROUP: &str = "l2tp";

type Unsolicited =
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>;

/// Shared async handle for L2TP generic-netlink operations.
#[derive(Clone)]
pub struct L2tpHandle {
    inner: Arc<L2tpInner>,
}

struct L2tpInner {
    genl: GenetlinkHandle,
    /// The resolved family, refreshed when the kernel no longer knows its
    /// identifier (the `l2tp_netlink` module was reloaded).
    family: std::sync::Mutex<Option<FamilyInfo>>,
    /// Namespace the connection was opened in, for further connections.
    netns: Owner,
}

impl L2tpInner {
    fn cached_family(&self) -> Option<FamilyInfo> {
        *self.family.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_family(&self, family: FamilyInfo) {
        *self.family.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(family);
    }
}

#[derive(Debug, Clone, Copy)]
struct FamilyInfo {
    id: u16,
    events_group: Option<u32>,
}

impl fmt::Debug for L2tpHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L2tpHandle")
            .field("family", &self.inner.cached_family())
            .field("netns", &self.inner.netns)
            .finish_non_exhaustive()
    }
}

type Opened = (Connection<RawGenlMessage>, GenetlinkHandle, Unsolicited);

/// Opens a generic-netlink connection on whichever thread runs it, and
/// registers it with this runtime's I/O driver.
fn opener() -> impl FnOnce() -> io::Result<Opened> + Send + 'static {
    let runtime = tokio::runtime::Handle::current();
    move || {
        let _guard = runtime.enter();
        // netlink-sys registers its socket with Tokio's I/O driver through
        // `AsyncFd`, which panics instead of failing when the runtime has no
        // I/O driver. Tokio offers no way to check for the driver first.
        std::panic::catch_unwind(genetlink::new_connection).map_err(|_| {
            io::Error::other(
                "tokio runtime with I/O enabled is required for L2tpHandle",
            )
        })?
    }
}

/// Opens a generic-netlink connection in its owning namespace. Avoids
/// setns when already there, including inside a container; otherwise the
/// socket is created on a temporary namespace thread.
fn open_connection(netns: &Owner) -> crate::Result<Opened> {
    Ok(netns.run_in(opener())??)
}

impl L2tpHandle {
    /// Create a new L2TP Generic Netlink handle.
    ///
    /// The calling thread's network namespace is retained, including when
    /// inherited from a container. Further event connections use that same
    /// namespace; opening them from a thread in another namespace requires
    /// the privileges needed by `setns(2)` and a descriptor of the namespace,
    /// which is kept only when `/proc` was readable here. Without one, that
    /// fails with an [`Unsupported`](io::ErrorKind::Unsupported) I/O error;
    /// use [`new_in`](Self::new_in) instead. `/proc` is not needed otherwise.
    ///
    /// This must be awaited while running inside a Tokio runtime with I/O
    /// enabled, because the internal Generic Netlink connection task is
    /// spawned onto the current Tokio executor. Without a runtime, or with a
    /// runtime built without `enable_io`, this returns
    /// [`Error::Io`](crate::Error::Io). Tokio reports a missing I/O driver by
    /// panicking inside the netlink socket registration; that panic is caught
    /// and turned into the error, so the panic hook still runs. The handle is
    /// cheap to clone; clones share one netlink connection.
    ///
    /// Requests that refer to a tunnel or session the kernel does not know
    /// fail with [`Error::KernelError`](crate::Error::KernelError) carrying
    /// `ENODEV`. Every L2TP command needs `CAP_NET_ADMIN`; without it the
    /// kernel replies `EPERM`.
    pub async fn new() -> crate::Result<Self> {
        Self::connect(None).await
    }

    /// Like [`new`](Self::new), but controls the L2TP subsystem of the
    /// network namespace `netns`.
    ///
    /// Entering a different namespace needs `CAP_SYS_ADMIN`; see [`NetNs`].
    /// When `/proc` is unavailable, `netns` cannot be told apart from the
    /// calling thread's own and is always entered. Tunnel sockets for managed tunnels must be created in the same
    /// namespace, for example inside [`NetNs::run`].
    pub async fn new_in(netns: &NetNs) -> crate::Result<Self> {
        Self::connect(Some(netns.try_clone()?)).await
    }

    async fn connect(netns: Option<NetNs>) -> crate::Result<Self> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            io::Error::other("tokio runtime is required for L2tpHandle")
        })?;
        let open = opener();
        let (netns, (mut connection, genl, _unsolicited)) = match netns {
            None => (None, open()?),
            // Telling the current namespace apart needs `/proc`; without it
            // `new_in` always enters the namespace.
            Some(ns) if ns.is_current() => (Some(ns), open()?),
            Some(ns) => {
                let opened = ns.run(open)??;
                (Some(ns), opened)
            }
        };
        // The identity is that of the socket actually created.
        let async_socket = connection.socket_mut();
        let socket = async_socket.socket_mut();
        let socket = socket.as_fd();
        let netns = match netns {
            None => Owner::here(Some(socket))?,
            Some(ns) => Owner::of(ns, socket)?,
        };
        connection.set_forward_ack(true);
        connection.set_forward_done(true);
        runtime.spawn(connection);

        Ok(Self {
            inner: Arc::new(L2tpInner {
                genl,
                family: std::sync::Mutex::new(None),
                netns,
            }),
        })
    }

    /// Creates a managed tunnel using an owned socket fd.
    ///
    /// The returned [`TunnelHandle`] owns `socket`; when
    /// that socket is dropped, the kernel tears down the tunnel.
    /// UDP checksum settings from `config` are applied to `socket` before
    /// registering it with the kernel.
    ///
    /// For IP encapsulation, `socket` must be bound to the same tunnel ID as
    /// `config`; otherwise this returns
    /// [`Error::TunnelIdMismatch`](crate::Error::TunnelIdMismatch).
    /// [`TunnelSocket::for_config`] creates a matching socket, and
    /// [`TunnelConfig::for_socket`] describes an existing one.
    ///
    /// Once started inside a Tokio runtime, creation continues through the
    /// kernel's acknowledgement even if the caller cancels this future. The
    /// socket stays owned until then; an unclaimed tunnel is dropped with
    /// auto-delete enabled. The runtime must keep running for cleanup to
    /// finish.
    pub async fn create_tunnel(
        &self,
        config: TunnelConfig,
        socket: TunnelSocket,
    ) -> crate::Result<TunnelHandle> {
        socket.configure(&config.encapsulation)?;
        if let Some(conn_id) = socket.conn_id()
            && conn_id != config.tunnel_id.0
        {
            return Err(crate::Error::TunnelIdMismatch {
                socket: TunnelId(conn_id),
                config: config.tunnel_id,
            });
        }
        let message =
            netlink::encode_tunnel_create(&config, Some(socket.as_raw_fd()))?;
        let handle = self.clone();
        run_creation(async move {
            handle.send_ack(message).await?;
            Ok(TunnelHandle {
                tunnel_id: config.tunnel_id,
                socket: Some(socket),
                auto_delete: true,
                handle,
            })
        })
        .await
    }

    /// Creates an unmanaged tunnel (no owned socket fd in this process).
    ///
    /// The kernel creates/manages the underlying socket using netlink tunnel
    /// address attributes. The tunnel outlives this process; it is removed
    /// when the returned handle is dropped (unless auto-delete is disabled),
    /// by [`TunnelHandle::delete`], or by [`L2tpHandle::delete_tunnel`].
    /// Disabling UDP checksums for an IPv4-mapped peer returns
    /// [`Error::UnmanagedUdpChecksum`](crate::Error::UnmanagedUdpChecksum),
    /// and link-local endpoints
    /// [`Error::UnmanagedLinkLocal`](crate::Error::UnmanagedLinkLocal); use a
    /// managed socket for these.
    ///
    /// Once started inside a Tokio runtime, creation continues through the
    /// kernel's acknowledgement even if the caller cancels this future. An
    /// unclaimed tunnel is dropped with auto-delete enabled. The runtime must
    /// keep running for this best-effort cleanup to finish.
    pub async fn create_unmanaged_tunnel(
        &self,
        config: TunnelConfig,
    ) -> crate::Result<TunnelHandle> {
        let message = netlink::encode_tunnel_create(&config, None)?;
        let handle = self.clone();
        run_creation(async move {
            handle.send_ack(message).await?;
            Ok(TunnelHandle {
                tunnel_id: config.tunnel_id,
                socket: None,
                auto_delete: true,
                handle,
            })
        })
        .await
    }

    /// Returns a handle for an existing tunnel after checking that the
    /// kernel knows it.
    ///
    /// The handle has auto-delete disabled and no socket, so dropping it
    /// leaves the tunnel alone; enable auto-delete or call
    /// [`TunnelHandle::delete`] to take ownership.
    pub async fn open_tunnel(
        &self,
        tunnel_id: TunnelId,
    ) -> crate::Result<TunnelHandle> {
        self.get_tunnel(tunnel_id).await?;
        Ok(TunnelHandle {
            tunnel_id,
            socket: None,
            auto_delete: false,
            handle: self.clone(),
        })
    }

    /// Creates a session in an existing tunnel.
    ///
    /// Session identifiers above `65535` are rejected with
    /// [`Error::V2IdTooLarge`](crate::Error::V2IdTooLarge) when the parent
    /// tunnel uses L2TPv2. Such identifiers require a parent-tunnel lookup
    /// before creation; L2TPv3 accepts the full 32-bit range.
    ///
    /// Once started inside a Tokio runtime, creation continues through the
    /// kernel's acknowledgement and follow-up lookup even if the caller cancels
    /// this future. An unclaimed session is dropped with auto-delete enabled.
    /// The runtime must keep running for this best-effort cleanup to finish.
    ///
    /// For Ethernet pseudowires the handle also carries the interface index
    /// of the new `l2tpeth` device, captured from the kernel's registration
    /// broadcast; see [`SessionHandle::ifindex`]. Give the session an
    /// explicit, unique [`SessionConfig::ifname`] where interfaces may be
    /// renamed by other software.
    pub async fn create_session(
        &self,
        config: SessionConfig,
    ) -> crate::Result<SessionHandle> {
        let message = netlink::encode_session_create(&config)?;
        let handle = self.clone();
        // Subscribe before the request: the kernel queues the device's
        // registration before it acknowledges the session.
        let monitor = match config.pseudowire_type {
            PseudowireType::Eth | PseudowireType::EthVlan => {
                match LinkMonitor::open(&self.inner.netns) {
                    Ok(monitor) => Some(monitor),
                    Err(err) => {
                        log::debug!(
                            "l2tp: cannot watch link registrations, the \
                             interface index will be looked up by name: {err}"
                        );
                        None
                    }
                }
            }
            _ => None,
        };
        run_creation(async move {
            // The kernel stores 32-bit session IDs even for V2, whose wire
            // format truncates them to 16 bits. Only query the parent when an
            // ID is outside the range shared by both protocol versions.
            if let Some(id) = [config.session_id, config.peer_session_id]
                .into_iter()
                .find(|id| u16::try_from(id.0).is_err())
                && handle.get_tunnel(config.tunnel_id).await?.version
                    == L2tpVersion::V2
            {
                return Err(crate::Error::V2IdTooLarge(id.0));
            }
            handle.send_ack(message).await?;
            handle.get_created_session(config, monitor).await
        })
        .await
    }

    async fn get_created_session(
        &self,
        config: SessionConfig,
        monitor: Option<LinkMonitor>,
    ) -> crate::Result<SessionHandle> {
        // Own the acknowledged session before the next await, so cancellation
        // also triggers best-effort deletion.
        let mut session = SessionHandle {
            tunnel_id: config.tunnel_id,
            session_id: config.session_id,
            ifname: None,
            ifindex: None,
            auto_delete: true,
            handle: self.clone(),
        };
        match self.get_session(config.tunnel_id, config.session_id).await {
            Ok(info) => {
                session.ifname = info.ifname;
                session.ifindex = match (monitor, &info.ifname) {
                    (Some(monitor), Some(ifname)) => {
                        self.registered_index(&monitor, ifname)
                    }
                    (None, Some(ifname)) => self.index_by_name(ifname),
                    (_, None) => None,
                };
                Ok(session)
            }
            Err(err) => {
                let _ = session.delete().await;
                Err(err)
            }
        }
    }

    /// The index the registration broadcast reported for `ifname`, or the
    /// index the name resolves to now if the notification was lost.
    fn registered_index(
        &self,
        monitor: &LinkMonitor,
        ifname: &L2tpIfName,
    ) -> Option<u32> {
        match monitor.registered_index(ifname) {
            Ok(Some(index)) => return Some(index),
            Ok(None) => log::debug!(
                "l2tp: no registration notification for {ifname:?}; looking \
                 the index up by name"
            ),
            Err(err) => log::debug!(
                "l2tp: link notifications were lost ({err}); looking the \
                 index of {ifname:?} up by name"
            ),
        }
        // The monitor's socket lives in the handle's namespace.
        match crate::socket::interface_index(monitor.as_raw_fd(), ifname) {
            Ok(index) => Some(index),
            Err(err) => {
                log::debug!("l2tp: cannot resolve {ifname:?}: {err}");
                None
            }
        }
    }

    /// Resolves `ifname` in the handle's namespace, which is only correct
    /// while the interface still bears that name.
    fn index_by_name(&self, ifname: &L2tpIfName) -> Option<u32> {
        let name = *ifname;
        match self.inner.netns.run_in(move || name.index()) {
            Ok(Ok(index)) => Some(index),
            Ok(Err(err)) => {
                log::debug!("l2tp: cannot resolve {ifname:?}: {err}");
                None
            }
            Err(err) => {
                log::debug!(
                    "l2tp: cannot enter the namespace to resolve {ifname:?}: \
                     {err}"
                );
                None
            }
        }
    }

    /// Returns a handle for an existing session after checking that the
    /// kernel knows it; auto-delete is disabled.
    ///
    /// The interface index is looked up by the session's creation-time
    /// name; see [`SessionHandle::ifindex`].
    pub async fn open_session(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
    ) -> crate::Result<SessionHandle> {
        let info = self.get_session(tunnel_id, session_id).await?;
        Ok(SessionHandle {
            tunnel_id,
            session_id,
            ifindex: info.ifname.as_ref().and_then(|n| self.index_by_name(n)),
            ifname: info.ifname,
            auto_delete: false,
            handle: self.clone(),
        })
    }

    /// Returns a handle for the existing Ethernet pseudowire session whose
    /// interface is `ifname`; auto-delete is disabled.
    ///
    /// `ifname` is the name the interface had when the session was created;
    /// see [`get_session_by_ifname`](Self::get_session_by_ifname). The
    /// interface index is looked up by that name too.
    pub async fn open_session_by_ifname(
        &self,
        ifname: &L2tpIfName,
    ) -> crate::Result<SessionHandle> {
        let info = self.get_session_by_ifname(ifname).await?;
        Ok(SessionHandle {
            tunnel_id: info.tunnel_id,
            session_id: info.session_id,
            ifindex: info.ifname.as_ref().and_then(|n| self.index_by_name(n)),
            ifname: info.ifname,
            auto_delete: false,
            handle: self.clone(),
        })
    }

    /// Returns information for a single tunnel.
    pub async fn get_tunnel(
        &self,
        tunnel_id: TunnelId,
    ) -> crate::Result<TunnelInfo> {
        let replies = self
            .send_and_collect(
                netlink::encode_tunnel_get(tunnel_id),
                NLM_F_REQUEST,
            )
            .await?;
        let attrs = first_attributes(&replies, "empty reply to tunnel get")?;
        netlink::decode_tunnel_info(attrs)
    }

    /// Returns information for a single session.
    pub async fn get_session(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
    ) -> crate::Result<SessionInfo> {
        self.get_session_ref(SessionRef::Ids(tunnel_id, session_id))
            .await
    }

    /// Returns information for the Ethernet pseudowire session whose
    /// interface is `ifname`.
    ///
    /// The kernel matches `ifname` against the name it recorded when the
    /// session was created. It does not follow later renames of the
    /// `l2tpeth` device, so a renamed interface is still found under its
    /// original name and never under its current one. An application that
    /// renames interfaces should resolve the reported name to its interface
    /// index right after creation with
    /// [`L2tpIfNameExt::index`](crate::L2tpIfNameExt::index) and address
    /// the device by that index from then on. Only L2TPv3 sessions are
    /// searched.
    pub async fn get_session_by_ifname(
        &self,
        ifname: &L2tpIfName,
    ) -> crate::Result<SessionInfo> {
        self.get_session_ref(SessionRef::IfName(*ifname)).await
    }

    async fn get_session_ref(
        &self,
        session: SessionRef,
    ) -> crate::Result<SessionInfo> {
        let replies = self
            .send_and_collect(
                netlink::encode_session_get(session),
                NLM_F_REQUEST,
            )
            .await?;
        let attrs = first_attributes(&replies, "empty reply to session get")?;
        netlink::decode_session_info(attrs)
    }

    /// Lists all tunnels.
    ///
    /// If the kernel's tables change during the dump, this fails with an error
    /// whose [`kind`](crate::Error::kind) is [`io::ErrorKind::Interrupted`];
    /// retrying usually succeeds.
    pub async fn list_tunnels(&self) -> crate::Result<Vec<TunnelInfo>> {
        let replies = self
            .send_and_collect(
                netlink::encode_tunnel_get_dump(),
                NLM_F_REQUEST | NLM_F_DUMP,
            )
            .await?;
        let mut out = Vec::with_capacity(replies.len());
        for reply in replies {
            out.push(netlink::decode_tunnel_info(&reply.payload.attributes)?);
        }
        Ok(out)
    }

    /// Lists all sessions that belong to a tunnel.
    pub async fn list_sessions(
        &self,
        tunnel_id: TunnelId,
    ) -> crate::Result<Vec<SessionInfo>> {
        // The kernel's session dump ignores L2TP_ATTR_CONN_ID, so filter here.
        let mut sessions = self.list_all_sessions().await?;
        sessions.retain(|session| session.tunnel_id == tunnel_id);
        Ok(sessions)
    }

    /// Lists all sessions across all tunnels.
    ///
    /// If the kernel's tables change during the dump, this fails with an error
    /// whose [`kind`](crate::Error::kind) is [`io::ErrorKind::Interrupted`];
    /// retrying usually succeeds.
    pub async fn list_all_sessions(&self) -> crate::Result<Vec<SessionInfo>> {
        let replies = self
            .send_and_collect(
                netlink::encode_session_get_dump(),
                NLM_F_REQUEST | NLM_F_DUMP,
            )
            .await?;
        let mut out = Vec::with_capacity(replies.len());
        for reply in replies {
            out.push(netlink::decode_session_info(&reply.payload.attributes)?);
        }
        Ok(out)
    }

    /// Deletes a tunnel and its sessions.
    ///
    /// The kernel acknowledges the request and then tears the tunnel down
    /// on a work queue, during which lookups still find it and creating a
    /// tunnel with the same identifier fails with `EEXIST`. This therefore
    /// also waits, for up to about two seconds, until a lookup reports
    /// `ENODEV`. Once the deletion is acknowledged it is not undone: a
    /// lookup that fails otherwise is returned as is, and a tunnel still
    /// listed after the wait is reported as
    /// [`Error::DeletionPending`](crate::Error::DeletionPending), which
    /// callers should treat as deleted, because repeating the request then
    /// fails with `ENODEV`. The wait needs neither a Tokio timer nor a free
    /// blocking thread.
    pub async fn delete_tunnel(
        &self,
        tunnel_id: TunnelId,
    ) -> crate::Result<()> {
        self.send_ack(netlink::encode_tunnel_delete(tunnel_id))
            .await?;
        self.wait_tunnel_removed(tunnel_id).await
    }

    async fn wait_tunnel_removed(
        &self,
        tunnel_id: TunnelId,
    ) -> crate::Result<()> {
        const POLLS: u32 = 200;
        const INTERVAL: std::time::Duration =
            std::time::Duration::from_millis(10);
        // Most tunnels are gone by the first lookup; only pace the rest.
        if self.tunnel_removed(tunnel_id).await? {
            return Ok(());
        }
        // A thread of its own paces the polls and exits once the receiver is
        // gone, so the wait depends neither on the runtime's timer driver
        // nor on a spare thread in its blocking pool.
        let (tick_tx, mut tick_rx) = tokio::sync::mpsc::unbounded_channel();
        std::thread::Builder::new()
            .name("l2tp-delete-wait".to_string())
            .spawn(move || {
                loop {
                    std::thread::sleep(INTERVAL);
                    if tick_tx.send(()).is_err() {
                        break;
                    }
                }
            })?;
        for _ in 1..POLLS {
            if tick_rx.recv().await.is_none() {
                return Err(crate::Error::other("the deletion wait stopped"));
            }
            if self.tunnel_removed(tunnel_id).await? {
                return Ok(());
            }
        }
        Err(crate::Error::DeletionPending(tunnel_id))
    }

    async fn tunnel_removed(&self, tunnel_id: TunnelId) -> crate::Result<bool> {
        match self.get_tunnel(tunnel_id).await {
            Ok(_) => Ok(false),
            Err(err) if err.raw_os_error() == Some(libc::ENODEV) => Ok(true),
            Err(err) => Err(err),
        }
    }

    /// Deletes a session from a tunnel.
    pub async fn delete_session(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
    ) -> crate::Result<()> {
        self.send_ack(netlink::encode_session_delete(SessionRef::Ids(
            tunnel_id, session_id,
        )))
        .await
    }

    /// Deletes the Ethernet pseudowire session whose interface is `ifname`.
    ///
    /// `ifname` is the name the interface had when the session was created;
    /// see [`get_session_by_ifname`](Self::get_session_by_ifname).
    pub async fn delete_session_by_ifname(
        &self,
        ifname: &L2tpIfName,
    ) -> crate::Result<()> {
        self.send_ack(netlink::encode_session_delete(SessionRef::IfName(
            *ifname,
        )))
        .await
    }

    /// Returns tunnel statistics.
    pub async fn tunnel_stats(
        &self,
        tunnel_id: TunnelId,
    ) -> crate::Result<TunnelStats> {
        let replies = self
            .send_and_collect(
                netlink::encode_tunnel_get(tunnel_id),
                NLM_F_REQUEST,
            )
            .await?;
        let attrs = first_attributes(&replies, "empty reply to tunnel get")?;
        netlink::decode_tunnel_stats(attrs)
    }

    /// Returns session statistics.
    pub async fn session_stats(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
    ) -> crate::Result<SessionStats> {
        self.session_stats_ref(SessionRef::Ids(tunnel_id, session_id))
            .await
    }

    /// Returns the statistics of the Ethernet pseudowire session whose
    /// interface is `ifname`.
    ///
    /// `ifname` is the name the interface had when the session was created;
    /// see [`get_session_by_ifname`](Self::get_session_by_ifname).
    pub async fn session_stats_by_ifname(
        &self,
        ifname: &L2tpIfName,
    ) -> crate::Result<SessionStats> {
        self.session_stats_ref(SessionRef::IfName(*ifname)).await
    }

    async fn session_stats_ref(
        &self,
        session: SessionRef,
    ) -> crate::Result<SessionStats> {
        let replies = self
            .send_and_collect(
                netlink::encode_session_get(session),
                NLM_F_REQUEST,
            )
            .await?;
        let attrs = first_attributes(&replies, "empty reply to session get")?;
        netlink::decode_session_stats(attrs)
    }

    /// Applies mutable session parameters.
    pub async fn modify_session(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
        params: SessionModify,
    ) -> crate::Result<()> {
        self.send_ack(netlink::encode_session_modify(
            SessionRef::Ids(tunnel_id, session_id),
            &params,
        ))
        .await
    }

    /// Applies mutable session parameters to the Ethernet pseudowire session
    /// whose interface is `ifname`.
    ///
    /// `ifname` is the name the interface had when the session was created;
    /// see [`get_session_by_ifname`](Self::get_session_by_ifname).
    pub async fn modify_session_by_ifname(
        &self,
        ifname: &L2tpIfName,
        params: SessionModify,
    ) -> crate::Result<()> {
        self.send_ack(netlink::encode_session_modify(
            SessionRef::IfName(*ifname),
            &params,
        ))
        .await
    }

    /// Subscribes to the kernel's L2TP notifications.
    ///
    /// The stream reports kernel multicast notifications about tunnels and
    /// sessions created, modified or deleted through netlink commands.
    /// Its socket belongs to the handle's original network namespace.
    ///
    /// Some kernels, including Linux 6.8, multicast L2TP events into every
    /// network namespace, including containers, without identifying the
    /// originating namespace. Such events cannot be reliably filtered by
    /// tunnel/session IDs, which can collide across namespaces. Treat events
    /// as hints to reconcile state through this handle's query methods,
    /// rather than instructions to mutate the named objects.
    ///
    /// The kernel announces nothing for the teardown it performs
    /// on its own: a tunnel whose managed socket was closed, the sessions
    /// removed together with a deleted tunnel, or a PPP session whose
    /// `PPPoL2TP` socket was released. Reconcile with
    /// [`list_tunnels`](Self::list_tunnels) and
    /// [`list_all_sessions`](Self::list_all_sessions) to catch those.
    ///
    /// The stream uses its own netlink connection on the current runtime;
    /// dropping it leaves the multicast group. Joining needs no privilege.
    /// Opening the socket from another namespace requires permission to
    /// enter the handle's original namespace. The subscription is bound to
    /// the family and group identifiers of the loaded `l2tp_netlink`
    /// module; if the module is reloaded, subscribe again.
    pub async fn events(&self) -> crate::Result<Events> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            io::Error::other("tokio runtime is required for events")
        })?;
        let family = self.resolve_family().await?;
        let group = family.events_group.ok_or_else(|| {
            crate::Error::FamilyResolution(format!(
                "the l2tp family has no `{EVENTS_GROUP}` multicast group"
            ))
        })?;
        let (mut connection, genl, receiver) =
            open_connection(&self.inner.netns)?;
        // The kernel sends these notifications without a sender port and
        // skips every socket whose own port is 0, so the socket must be
        // bound before it can receive them; it never sends, so nothing else
        // would bind it.
        let socket = connection.socket_mut().socket_mut();
        socket.bind_auto()?;
        socket.add_membership(group)?;
        // Requests are never sent on this connection; it only listens.
        drop(genl);
        let task = runtime.spawn(connection);
        Ok(Events::new(receiver, task, family.id))
    }

    async fn resolve_family(&self) -> crate::Result<FamilyInfo> {
        match self.inner.cached_family() {
            Some(family) => Ok(family),
            None => self.refresh_family().await,
        }
    }

    /// Queries the family again, bypassing every cache. Generic netlink
    /// assigns family identifiers dynamically, so a reloaded `l2tp_netlink`
    /// module may come back under a different one.
    async fn refresh_family(&self) -> crate::Result<FamilyInfo> {
        self.inner.genl.clear_family_cache().await;
        let family = self
            .inner
            .genl
            .resolve_family::<L2tpMessage>()
            .await
            .map_err(|e| crate::Error::FamilyResolution(e.to_string()))?;
        let info = FamilyInfo {
            id: family.id,
            events_group: family.multicast_groups.get(EVENTS_GROUP).copied(),
        };
        self.inner.set_family(info);
        Ok(info)
    }

    async fn send_ack(&self, payload: L2tpMessage) -> crate::Result<()> {
        let _ = self
            .send_and_collect(payload, NLM_F_REQUEST | NLM_F_ACK)
            .await?;
        Ok(())
    }

    async fn send_and_collect(
        &self,
        payload: L2tpMessage,
        flags: u16,
    ) -> crate::Result<Vec<GenlMessage<L2tpMessage>>> {
        let family_id = self.resolve_family().await?.id;
        match self.send_to_family(payload.clone(), flags, family_id).await {
            // Generic netlink answers ENOENT for a family identifier it no
            // longer knows. The L2TP commands themselves never produce it,
            // but only retry once the identifier has actually changed.
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                let refreshed = self.refresh_family().await?.id;
                if refreshed == family_id {
                    return Err(err);
                }
                log::debug!(
                    "l2tp: family id {family_id} became {refreshed}; retrying"
                );
                self.send_to_family(payload, flags, refreshed).await
            }
            result => result,
        }
    }

    async fn send_to_family(
        &self,
        payload: L2tpMessage,
        flags: u16,
        family_id: u16,
    ) -> crate::Result<Vec<GenlMessage<L2tpMessage>>> {
        let cmd = payload.cmd;
        log::debug!("l2tp: sending {cmd:?} with flags {flags:#06x}");
        let mut genl = GenlMessage::from_payload(payload);
        genl.set_resolved_family_id(family_id);

        let mut request = NetlinkMessage::from(genl);
        request.header.flags = flags;
        request.finalize();

        let mut handle = self.inner.genl.clone();
        let mut stream = handle.send_request(request).map_err(to_io_error)?;

        match collect_responses(&mut stream, flags).await {
            Ok(replies) => {
                log::trace!("l2tp: {cmd:?} returned {} replies", replies.len());
                Ok(replies)
            }
            Err(err) => {
                log::debug!("l2tp: {cmd:?} failed: {err}");
                Err(err)
            }
        }
    }
}

async fn collect_responses<S>(
    stream: S,
    flags: u16,
) -> crate::Result<Vec<GenlMessage<L2tpMessage>>>
where
    S: Stream<
        Item = Result<
            NetlinkMessage<GenlMessage<L2tpMessage>>,
            netlink_packet_core::DecodeError,
        >,
    >,
{
    futures::pin_mut!(stream);
    let expect_ack = flags & NLM_F_ACK != 0;
    let mut expect_done = flags & NLM_F_DUMP == NLM_F_DUMP;
    let mut responses = Vec::new();
    while let Some(item) = stream.next().await {
        let message = item?;
        if message.header.flags & NLM_F_DUMP_INTR != 0 {
            // The kernel changed its tables mid-dump; a retry usually works.
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "netlink dump was interrupted by concurrent changes",
            )
            .into());
        }
        let multipart = message.header.flags & NLM_F_MULTIPART != 0;
        match message.payload {
            NetlinkPayload::InnerMessage(inner) => {
                responses.push(inner);
                expect_done |= multipart;
                if !expect_ack && !expect_done {
                    return Ok(responses);
                }
            }
            NetlinkPayload::Error(err) => {
                if let Some(code) = err.code {
                    return Err(crate::Error::KernelError {
                        code: normalize_errno(code.get()),
                        message: err.to_string(),
                    });
                }
                if expect_ack && !expect_done {
                    return Ok(responses);
                }
            }
            NetlinkPayload::Done(done) => {
                if done.code != 0 {
                    return Err(crate::Error::KernelError {
                        code: normalize_errno(done.code),
                        message: format!("netlink dump failed: {}", done.code),
                    });
                }
                if expect_done {
                    return Ok(responses);
                }
                return Err(crate::Error::UnexpectedReply(
                    "unexpected netlink DONE".to_string(),
                ));
            }
            NetlinkPayload::Overrun(_) => {
                return Err(crate::Error::Netlink(
                    "netlink overrun: reply was truncated".to_string(),
                ));
            }
            _ => {}
        }
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "netlink reply stream closed before request completion",
    )
    .into())
}

struct CreationResult<T> {
    value: Option<crate::Result<T>>,
    runtime: tokio::runtime::Handle,
}

impl<T> Drop for CreationResult<T> {
    fn drop(&mut self) {
        // A completed JoinHandle's output can be dropped by a cancelling
        // caller outside Tokio. Restore the creating runtime so an unclaimed
        // tunnel/session can still schedule its best-effort deletion.
        let _guard = self.runtime.enter();
        drop(self.value.take());
    }
}

// The task owns the socket/request until ACK, then owns the resulting RAII
// handle. Dropping the caller's JoinHandle detaches the task; its unclaimed
// result is dropped with auto-delete enabled. Do not construct that handle
// before a successful ACK: deleting after EEXIST could remove someone else's
// tunnel or session.
async fn run_creation<F, T>(creation: F) -> crate::Result<T>
where
    F: std::future::Future<Output = crate::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
        io::Error::other("tokio runtime is required for creation")
    })?;
    let cleanup_runtime = runtime.clone();
    let mut result = runtime
        .spawn(async move {
            CreationResult {
                value: Some(creation.await),
                runtime: cleanup_runtime,
            }
        })
        .await
        .map_err(|err| io::Error::other(err.to_string()))?;
    result.value.take().unwrap_or_else(|| {
        Err(crate::Error::other("creation task lost its result"))
    })
}

// Keep the owning handle in a separate task: cancelling the caller must not
// cancel a deletion after ownership has been consumed.
pub(crate) async fn run_cleanup<F>(cleanup: F) -> crate::Result<()>
where
    F: std::future::Future<Output = crate::Result<()>> + Send + 'static,
{
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
        io::Error::other("tokio runtime is required for deletion")
    })?;
    runtime
        .spawn(cleanup)
        .await
        .map_err(|err| io::Error::other(err.to_string()))?
}

fn first_attributes<'a>(
    replies: &'a [GenlMessage<L2tpMessage>],
    context: &str,
) -> crate::Result<&'a [L2tpAttribute]> {
    replies
        .first()
        .map(|msg| msg.payload.attributes.as_slice())
        .ok_or_else(|| crate::Error::UnexpectedReply(context.to_string()))
}

fn to_io_error(err: genetlink::GenetlinkError) -> crate::Error {
    io::Error::other(err.to_string()).into()
}

fn normalize_errno(code: i32) -> i32 {
    if code < 0 { -code } else { code }
}

#[cfg(test)]
mod tests {
    use netlink_packet_core::{DoneMessage, ErrorMessage};
    use netlink_packet_l2tp::L2tpCmd;

    use super::*;

    type Reply = NetlinkMessage<GenlMessage<L2tpMessage>>;

    fn reply() -> Reply {
        NetlinkMessage::from(GenlMessage::from_payload(L2tpMessage::new(
            L2tpCmd::TunnelGet,
        )))
    }

    fn ack() -> Reply {
        NetlinkMessage::new(
            Default::default(),
            NetlinkPayload::Error(ErrorMessage::default()),
        )
    }

    fn done(code: i32) -> Reply {
        let mut message = DoneMessage::default();
        message.code = code;
        NetlinkMessage::new(Default::default(), NetlinkPayload::Done(message))
    }

    fn collect(
        messages: Vec<Reply>,
        flags: u16,
    ) -> crate::Result<Vec<GenlMessage<L2tpMessage>>> {
        futures::executor::block_on(collect_responses(
            futures::stream::iter(messages.into_iter().map(Ok)),
            flags,
        ))
    }

    pub(super) const TEST_FAMILY_ID: u16 = 1234;

    pub(super) fn test_handle(genl: GenetlinkHandle) -> L2tpHandle {
        L2tpHandle {
            inner: Arc::new(L2tpInner {
                genl,
                family: std::sync::Mutex::new(Some(FamilyInfo {
                    id: TEST_FAMILY_ID,
                    events_group: None,
                })),
                netns: Owner::here(None).unwrap(),
            }),
        }
    }

    #[test]
    fn missing_ack_or_dump_completion_is_an_error() {
        for flags in [
            NLM_F_REQUEST,
            NLM_F_REQUEST | NLM_F_ACK,
            NLM_F_REQUEST | NLM_F_DUMP,
        ] {
            let err = collect(vec![], flags).unwrap_err();
            assert_eq!(err.kind(), Some(io::ErrorKind::UnexpectedEof));
        }
        // An ordinary reply cannot substitute for the requested ACK.
        assert!(collect(vec![reply()], NLM_F_REQUEST | NLM_F_ACK).is_err());
        // A partial dump cannot substitute for DONE.
        let mut partial = reply();
        partial.header.flags = NLM_F_MULTIPART;
        assert!(
            collect(vec![partial.clone()], NLM_F_REQUEST | NLM_F_DUMP).is_err()
        );
        assert!(collect(vec![partial], NLM_F_REQUEST).is_err());
    }

    #[test]
    fn request_completion_matches_request_type() {
        assert!(
            collect(vec![ack()], NLM_F_REQUEST | NLM_F_ACK)
                .unwrap()
                .is_empty()
        );
        assert_eq!(collect(vec![reply()], NLM_F_REQUEST).unwrap().len(), 1);
        let mut partial = reply();
        partial.header.flags = NLM_F_MULTIPART;
        assert_eq!(
            collect(vec![partial, done(0)], NLM_F_REQUEST | NLM_F_DUMP)
                .unwrap()
                .len(),
            1
        );
        assert!(
            collect(vec![done(0)], NLM_F_REQUEST | NLM_F_DUMP)
                .unwrap()
                .is_empty()
        );
        assert!(collect(vec![ack()], NLM_F_REQUEST | NLM_F_DUMP).is_err());
        assert!(collect(vec![done(0)], NLM_F_REQUEST | NLM_F_ACK).is_err());
    }

    #[test]
    fn dump_errors_and_interruptions_are_not_success() {
        assert_eq!(
            collect(vec![done(-libc::EIO)], NLM_F_REQUEST | NLM_F_DUMP)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
        for mut message in [reply(), done(0)] {
            message.header.flags = NLM_F_DUMP_INTR;
            assert_eq!(
                collect(vec![message], NLM_F_REQUEST | NLM_F_DUMP)
                    .unwrap_err()
                    .kind(),
                Some(io::ErrorKind::Interrupted)
            );
        }
    }

    #[test]
    fn kernel_ack_errors_are_preserved() {
        let mut error = ErrorMessage::default();
        error.code = std::num::NonZeroI32::new(-libc::EPERM);
        let message = NetlinkMessage::new(
            Default::default(),
            NetlinkPayload::Error(error),
        );
        assert_eq!(
            collect(vec![message], NLM_F_REQUEST | NLM_F_ACK)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
    }

    #[test]
    fn deletion_continues_after_caller_cancellation() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
            let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
            let mut deletion = Box::pin(run_cleanup(async move {
                started_tx.send(()).unwrap();
                finish_rx.await.unwrap();
                completed_tx.send(()).unwrap();
                Ok(())
            }));
            assert!(futures::poll!(deletion.as_mut()).is_pending());
            started_rx.await.unwrap();
            drop(deletion);
            finish_tx.send(()).unwrap();
            completed_rx
                .await
                .expect("deletion must finish after cancellation");
        });
    }

    #[test]
    fn deletion_propagates_failure() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let err = run_cleanup(async {
                Err(crate::Error::KernelError {
                    code: libc::EPERM,
                    message: "denied".into(),
                })
            })
            .await
            .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EPERM));
        });
    }

    #[test]
    fn connection_shutdown_does_not_acknowledge_request() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (connection, genl, _unsolicited) =
                match genetlink::new_connection() {
                    Ok(connection) => connection,
                    Err(err)
                        if err.kind() == io::ErrorKind::PermissionDenied =>
                    {
                        return;
                    }
                    Err(err) => panic!("{err}"),
                };
            let handle = test_handle(genl);
            let mut request = Box::pin(handle.delete_tunnel(TunnelId(123)));
            assert!(futures::poll!(request.as_mut()).is_pending());
            // No connection task ran, so the request never reached the kernel.
            drop(connection);
            assert_eq!(
                request.await.unwrap_err().kind(),
                Some(io::ErrorKind::UnexpectedEof)
            );
        });
    }

    #[test]
    fn cancelled_session_lookup_keeps_cleanup_ownership() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (_connection, genl, _unsolicited) =
                match genetlink::new_connection() {
                    Ok(connection) => connection,
                    Err(err)
                        if err.kind() == io::ErrorKind::PermissionDenied =>
                    {
                        return;
                    }
                    Err(err) => panic!("{err}"),
                };
            let handle = test_handle(genl);
            // This is the post-ACK phase; the idle connection leaves GET
            // pending.
            let mut lookup = Box::pin(handle.get_created_session(
                SessionConfig::eth(TunnelId(1), SessionId(2), SessionId(3)),
                None,
            ));
            assert!(futures::poll!(lookup.as_mut()).is_pending());
            drop(lookup);
            // On this single-thread runtime the cleanup task cannot run until
            // we yield. Its reference proves Drop scheduled cleanup rather than
            // discarding ownership of the acknowledged session.
            assert_eq!(Arc::strong_count(&handle.inner), 2);
        });
    }

    #[test]
    fn normalize_errno_converts_negative_to_positive() {
        assert_eq!(normalize_errno(-libc::EEXIST), libc::EEXIST);
        assert_eq!(normalize_errno(-libc::EINVAL), libc::EINVAL);
    }

    #[test]
    fn normalize_errno_keeps_non_negative_unchanged() {
        assert_eq!(normalize_errno(0), 0);
        assert_eq!(normalize_errno(libc::ENOENT), libc::ENOENT);
    }

    #[test]
    fn new_fails_without_tokio_runtime() {
        let result = futures::executor::block_on(L2tpHandle::new());
        match result {
            Ok(_) => panic!("expected failure without tokio runtime"),
            Err(crate::Error::Io(e)) => {
                assert!(
                    e.to_string().contains("tokio runtime is required"),
                    "unexpected error message: {e}"
                );
            }
            Err(e) => panic!("unexpected error type: {e:?}"),
        }
    }

    #[test]
    fn new_fails_without_io_driver() {
        // No `enable_io`: Tokio panics when the netlink socket registers.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        match runtime.block_on(L2tpHandle::new()) {
            Ok(_) => panic!("expected failure without an I/O driver"),
            Err(crate::Error::Io(e)) => {
                assert!(
                    e.to_string().contains("I/O enabled"),
                    "unexpected error message: {e}"
                );
            }
            Err(e) => panic!("unexpected error type: {e:?}"),
        }
    }

    #[tokio::test]
    async fn events_subscription_joins_the_multicast_group() {
        let handle = L2tpHandle::new().await.unwrap();
        match handle.events().await {
            Ok(events) => drop(events),
            // Without the l2tp module the family cannot be resolved.
            Err(crate::Error::FamilyResolution(_)) => {}
            Err(err) => panic!("unexpected error: {err:?}"),
        }
    }

    #[tokio::test]
    async fn opening_unknown_objects_fails_without_a_handle() {
        // ENODEV as root, EPERM unprivileged, or no `l2tp` family at all
        // where the module is not loaded (CI runners).
        fn refused(err: &crate::Error) -> bool {
            err.kind().is_some()
                || matches!(err, crate::Error::FamilyResolution(_))
        }
        let handle = L2tpHandle::new().await.unwrap();
        let err = handle.open_tunnel(TunnelId(u32::MAX)).await.unwrap_err();
        assert!(refused(&err), "{err:?}");
        let name = L2tpIfName::new("l2tp-no-such0").unwrap();
        let err = handle.open_session_by_ifname(&name).await.unwrap_err();
        assert!(refused(&err), "{err:?}");
    }

    #[test]
    fn new_in_the_current_namespace_needs_no_setns_privileges() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let netns = NetNs::current().unwrap();
            let handle = L2tpHandle::new_in(&netns).await.unwrap();
            let here = Owner::here(None).unwrap();
            assert_eq!(handle.inner.netns.same_as(&here), Some(true));
        });
    }
}

#[cfg(test)]
mod creation_tests;

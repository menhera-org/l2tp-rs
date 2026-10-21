// SPDX-License-Identifier: MIT

use std::{fmt, io, os::fd::AsRawFd, sync::Arc};

use futures::{Stream, StreamExt};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_MULTIPART, NLM_F_REQUEST,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_l2tp::{L2tpAttribute, L2tpMessage};

use crate::{
    SessionConfig, SessionHandle, SessionId, SessionInfo, SessionModify,
    SessionStats, TunnelConfig, TunnelHandle, TunnelId, TunnelInfo,
    TunnelSocket, TunnelStats, netlink,
};

/// Shared async handle for L2TP generic-netlink operations.
#[derive(Clone)]
pub struct L2tpHandle {
    inner: Arc<L2tpInner>,
}

struct L2tpInner {
    genl: genetlink::GenetlinkHandle,
    family_id: tokio::sync::OnceCell<u16>,
}

impl fmt::Debug for L2tpHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L2tpHandle")
            .field("family_id", &self.inner.family_id.get())
            .finish_non_exhaustive()
    }
}

impl L2tpHandle {
    /// Create a new L2TP Generic Netlink handle.
    ///
    /// This must be awaited while running inside a Tokio runtime with I/O
    /// enabled, because the internal Generic Netlink connection task is
    /// spawned onto the current Tokio executor. The handle is cheap to clone;
    /// clones share one netlink connection.
    ///
    /// Requests that refer to a tunnel or session the kernel does not know
    /// fail with [`Error::KernelError`](crate::Error::KernelError) carrying
    /// `ENODEV`.
    pub async fn new() -> crate::Result<Self> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            io::Error::other("tokio runtime is required for L2tpHandle::new()")
        })?;
        let (mut connection, genl, _unsolicited) = genetlink::new_connection()?;
        connection.set_forward_ack(true);
        connection.set_forward_done(true);
        runtime.spawn(connection);

        Ok(Self {
            inner: Arc::new(L2tpInner {
                genl,
                family_id: tokio::sync::OnceCell::new(),
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
    /// For IP encapsulation, `socket` must have been created by
    /// [`TunnelSocket::ip`] with the same tunnel ID as `config`.
    pub async fn create_tunnel(
        &self,
        config: TunnelConfig,
        socket: TunnelSocket,
    ) -> crate::Result<TunnelHandle> {
        socket.configure(&config.encapsulation)?;
        let message =
            netlink::encode_tunnel_create(&config, Some(socket.as_raw_fd()))?;
        self.send_ack(message).await?;

        Ok(TunnelHandle {
            tunnel_id: config.tunnel_id,
            socket: Some(socket),
            auto_delete: true,
            handle: self.clone(),
        })
    }

    /// Creates an unmanaged tunnel (no owned socket fd in this process).
    ///
    /// The kernel creates/manages the underlying socket using netlink tunnel
    /// address attributes. The tunnel outlives this process; it is removed
    /// when the returned handle is dropped (unless auto-delete is disabled),
    /// by [`TunnelHandle::delete`], or by [`L2tpHandle::delete_tunnel`].
    pub async fn create_unmanaged_tunnel(
        &self,
        config: TunnelConfig,
    ) -> crate::Result<TunnelHandle> {
        let message = netlink::encode_tunnel_create(&config, None)?;
        self.send_ack(message).await?;

        Ok(TunnelHandle {
            tunnel_id: config.tunnel_id,
            socket: None,
            auto_delete: true,
            handle: self.clone(),
        })
    }

    /// Creates a session in an existing tunnel.
    /// Cancellation during the follow-up information lookup schedules
    /// best-effort deletion of the acknowledged session.
    pub async fn create_session(
        &self,
        config: SessionConfig,
    ) -> crate::Result<SessionHandle> {
        let message = netlink::encode_session_create(&config)?;
        self.send_ack(message).await?;
        self.get_created_session(config).await
    }

    async fn get_created_session(
        &self,
        config: SessionConfig,
    ) -> crate::Result<SessionHandle> {
        // Own the acknowledged session before the next await, so cancellation
        // also triggers best-effort deletion.
        let mut session = SessionHandle {
            tunnel_id: config.tunnel_id,
            session_id: config.session_id,
            ifname: None,
            auto_delete: true,
            handle: self.clone(),
        };
        match self.get_session(config.tunnel_id, config.session_id).await {
            Ok(info) => {
                session.ifname = info.ifname;
                Ok(session)
            }
            Err(err) => {
                let _ = session.delete().await;
                Err(err)
            }
        }
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
        let replies = self
            .send_and_collect(
                netlink::encode_session_get(tunnel_id, session_id),
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

    /// Deletes a tunnel.
    pub async fn delete_tunnel(
        &self,
        tunnel_id: TunnelId,
    ) -> crate::Result<()> {
        self.send_ack(netlink::encode_tunnel_delete(tunnel_id))
            .await
    }

    /// Deletes a session from a tunnel.
    pub async fn delete_session(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
    ) -> crate::Result<()> {
        self.send_ack(netlink::encode_session_delete(tunnel_id, session_id))
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
        let replies = self
            .send_and_collect(
                netlink::encode_session_get(tunnel_id, session_id),
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
            tunnel_id, session_id, &params,
        ))
        .await
    }

    async fn resolve_family_id(&self) -> crate::Result<u16> {
        let id = self
            .inner
            .family_id
            .get_or_try_init(|| async {
                self.inner
                    .genl
                    .resolve_family::<L2tpMessage>()
                    .await
                    .map(|family| family.id)
                    .map_err(|e| crate::Error::FamilyResolution(e.to_string()))
            })
            .await?;
        Ok(*id)
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
        let family_id = self.resolve_family_id().await?;
        let mut genl = GenlMessage::from_payload(payload);
        genl.set_resolved_family_id(family_id);

        let mut request = NetlinkMessage::from(genl);
        request.header.flags = flags;
        request.finalize();

        let mut handle = self.inner.genl.clone();
        let mut stream = handle.send_request(request).map_err(to_io_error)?;

        collect_responses(&mut stream, flags).await
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
        let message = item.map_err(crate::Error::netlink)?;
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
            let handle = L2tpHandle {
                inner: Arc::new(L2tpInner {
                    genl,
                    family_id: tokio::sync::OnceCell::new_with(Some(1234)),
                }),
            };
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
            let handle = L2tpHandle {
                inner: Arc::new(L2tpInner {
                    genl,
                    family_id: tokio::sync::OnceCell::new_with(Some(1234)),
                }),
            };
            // This is the post-ACK phase; the idle connection leaves GET
            // pending.
            let mut lookup = Box::pin(handle.get_created_session(
                SessionConfig::eth(TunnelId(1), SessionId(2), SessionId(3)),
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
}

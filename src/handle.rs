use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use futures::StreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;
use netlink_packet_l2tp::{L2tpAttribute, L2tpMessage};

use crate::netlink;
use crate::{
    SessionConfig, SessionHandle, SessionId, SessionInfo, SessionModify, SessionStats,
    TunnelConfig, TunnelHandle, TunnelId, TunnelInfo, TunnelModify, TunnelSocket, TunnelStats,
};

#[derive(Clone)]
pub struct L2tpHandle {
    inner: Arc<L2tpInner>,
}

struct L2tpInner {
    genl: genetlink::GenetlinkHandle,
    family_id: tokio::sync::OnceCell<u16>,
}

impl L2tpHandle {
    /// Create a new L2TP Generic Netlink handle.
    ///
    /// This must be awaited while running inside a Tokio runtime because the
    /// internal Generic Netlink connection task is spawned onto the current
    /// Tokio executor.
    pub async fn new() -> crate::Result<Self> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("tokio runtime is required for L2tpHandle::new()"))?;
        let (connection, genl, _unsolicited) = genetlink::new_connection()?;
        runtime.spawn(connection);

        Ok(Self {
            inner: Arc::new(L2tpInner {
                genl,
                family_id: tokio::sync::OnceCell::new(),
            }),
        })
    }

    pub async fn create_tunnel(
        &self,
        config: TunnelConfig,
        socket: TunnelSocket,
    ) -> crate::Result<TunnelHandle> {
        let message = netlink::encode_tunnel_create(&config, Some(socket.as_raw_fd()));
        self.send_ack(message).await?;

        Ok(TunnelHandle {
            tunnel_id: config.tunnel_id,
            socket: Some(socket),
            auto_delete: true,
            handle: self.clone(),
        })
    }

    pub async fn create_unmanaged_tunnel(
        &self,
        config: TunnelConfig,
    ) -> crate::Result<TunnelHandle> {
        let message = netlink::encode_tunnel_create(&config, None);
        self.send_ack(message).await?;

        Ok(TunnelHandle {
            tunnel_id: config.tunnel_id,
            socket: None,
            auto_delete: true,
            handle: self.clone(),
        })
    }

    pub async fn create_session(&self, config: SessionConfig) -> crate::Result<SessionHandle> {
        let message = netlink::encode_session_create(&config);
        self.send_ack(message).await?;

        let info = self
            .get_session(config.tunnel_id, config.session_id)
            .await?;

        Ok(SessionHandle {
            tunnel_id: config.tunnel_id,
            session_id: config.session_id,
            ifname: info.ifname,
            auto_delete: true,
            handle: self.clone(),
        })
    }

    pub async fn get_tunnel(&self, tunnel_id: TunnelId) -> crate::Result<TunnelInfo> {
        let replies = self
            .send_and_collect(netlink::encode_tunnel_get(tunnel_id), NLM_F_REQUEST)
            .await?;
        let attrs = first_attributes(&replies, "tunnel not found")?;
        netlink::decode_tunnel_info(attrs)
    }

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
        let attrs = first_attributes(&replies, "session not found")?;
        netlink::decode_session_info(attrs)
    }

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

    pub async fn list_sessions(&self, tunnel_id: TunnelId) -> crate::Result<Vec<SessionInfo>> {
        let replies = self
            .send_and_collect(
                netlink::encode_session_get_dump(Some(tunnel_id)),
                NLM_F_REQUEST | NLM_F_DUMP,
            )
            .await?;
        let mut out = Vec::with_capacity(replies.len());
        for reply in replies {
            out.push(netlink::decode_session_info(&reply.payload.attributes)?);
        }
        Ok(out)
    }

    pub async fn list_all_sessions(&self) -> crate::Result<Vec<SessionInfo>> {
        let replies = self
            .send_and_collect(
                netlink::encode_session_get_dump(None),
                NLM_F_REQUEST | NLM_F_DUMP,
            )
            .await?;
        let mut out = Vec::with_capacity(replies.len());
        for reply in replies {
            out.push(netlink::decode_session_info(&reply.payload.attributes)?);
        }
        Ok(out)
    }

    pub async fn delete_tunnel(&self, tunnel_id: TunnelId) -> crate::Result<()> {
        self.send_ack(netlink::encode_tunnel_delete(tunnel_id))
            .await
    }

    pub async fn delete_session(
        &self,
        tunnel_id: TunnelId,
        session_id: SessionId,
    ) -> crate::Result<()> {
        self.send_ack(netlink::encode_session_delete(tunnel_id, session_id))
            .await
    }

    pub async fn tunnel_stats(&self, tunnel_id: TunnelId) -> crate::Result<TunnelStats> {
        let replies = self
            .send_and_collect(netlink::encode_tunnel_get(tunnel_id), NLM_F_REQUEST)
            .await?;
        let attrs = first_attributes(&replies, "tunnel not found")?;
        netlink::decode_tunnel_stats(attrs)
    }

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
        let attrs = first_attributes(&replies, "session not found")?;
        netlink::decode_session_stats(attrs)
    }

    pub async fn modify_tunnel(
        &self,
        tunnel_id: TunnelId,
        params: TunnelModify,
    ) -> crate::Result<()> {
        self.send_ack(netlink::encode_tunnel_modify(tunnel_id, &params))
            .await
    }

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
                    .resolve_family_id::<L2tpMessage>()
                    .await
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

        let mut responses = Vec::new();
        while let Some(item) = stream.next().await {
            let message = item?;
            match message.payload {
                NetlinkPayload::InnerMessage(inner) => responses.push(inner),
                NetlinkPayload::Error(err) => {
                    if let Some(code) = err.code {
                        return Err(crate::Error::KernelError {
                            code: normalize_errno(code.get()),
                            message: err.to_string(),
                        });
                    }
                }
                NetlinkPayload::Done(_) => break,
                NetlinkPayload::Noop | NetlinkPayload::Overrun(_) => {}
                _ => {}
            }
        }

        Ok(responses)
    }
}

fn first_attributes<'a>(
    replies: &'a [GenlMessage<L2tpMessage>],
    context: &str,
) -> crate::Result<&'a [L2tpAttribute]> {
    replies
        .first()
        .map(|msg| msg.payload.attributes.as_slice())
        .ok_or_else(|| crate::Error::KernelError {
            code: libc::ENOENT,
            message: context.to_string(),
        })
}

fn to_io_error(err: genetlink::GenetlinkError) -> crate::Error {
    io::Error::other(err.to_string()).into()
}

fn normalize_errno(code: i32) -> i32 {
    if code < 0 {
        -code
    } else {
        code
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_errno, L2tpHandle};

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

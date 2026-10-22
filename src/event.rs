// SPDX-License-Identifier: MIT

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Stream, channel::mpsc::UnboundedReceiver};
use genetlink::message::RawGenlMessage;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_l2tp::{L2tpCmd, L2tpMessage};
use netlink_proto::sys::SocketAddr;

use crate::{SessionInfo, TunnelInfo, netlink};

/// A change the kernel announced on the `l2tp` multicast group.
///
/// Deletion events carry the state the object had before it was removed.
/// The kernel sends tunnel modification events for `TUNNEL_MODIFY` requests
/// although it changes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub enum L2tpEvent {
    /// A tunnel was created.
    TunnelCreated(TunnelInfo),
    /// A tunnel modification was requested.
    TunnelModified(TunnelInfo),
    /// A tunnel was deleted.
    TunnelDeleted(TunnelInfo),
    /// A session was created.
    SessionCreated(SessionInfo),
    /// A session was modified.
    SessionModified(SessionInfo),
    /// A session was deleted.
    SessionDeleted(SessionInfo),
}

/// Stream of [`L2tpEvent`]s from the kernel, created by
/// [`L2tpHandle::events`](crate::L2tpHandle::events).
///
/// Dropping the stream leaves the multicast group. Messages that are not
/// L2TP notifications are skipped; a notification that fails to decode is
/// reported as an error and the stream continues.
#[derive(Debug)]
pub struct Events {
    receiver: UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
    connection: tokio::task::JoinHandle<()>,
}

impl Events {
    pub(crate) fn new(
        receiver: UnboundedReceiver<(
            NetlinkMessage<RawGenlMessage>,
            SocketAddr,
        )>,
        connection: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            receiver,
            connection,
        }
    }
}

impl Stream for Events {
    type Item = crate::Result<L2tpEvent>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            match Pin::new(&mut self.receiver).poll_next(cx) {
                Poll::Ready(Some((message, _))) => match decode(message) {
                    Ok(Some(event)) => return Poll::Ready(Some(Ok(event))),
                    Ok(None) => continue,
                    Err(err) => return Poll::Ready(Some(Err(err))),
                },
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for Events {
    fn drop(&mut self) {
        // The connection task is only woken by socket traffic, so stop it
        // explicitly rather than waiting for the next notification.
        self.connection.abort();
    }
}

pub(crate) fn decode(
    message: NetlinkMessage<RawGenlMessage>,
) -> crate::Result<Option<L2tpEvent>> {
    let NetlinkPayload::InnerMessage(raw) = message.payload else {
        return Ok(None);
    };
    let genl = raw.parse_into_genlmsg::<L2tpMessage>()?;
    let attrs = &genl.payload.attributes;
    let event = match genl.payload.cmd {
        L2tpCmd::TunnelCreate => {
            L2tpEvent::TunnelCreated(netlink::decode_tunnel_info(attrs)?)
        }
        L2tpCmd::TunnelModify => {
            L2tpEvent::TunnelModified(netlink::decode_tunnel_info(attrs)?)
        }
        L2tpCmd::TunnelDelete => {
            L2tpEvent::TunnelDeleted(netlink::decode_tunnel_info(attrs)?)
        }
        L2tpCmd::SessionCreate => {
            L2tpEvent::SessionCreated(netlink::decode_session_info(attrs)?)
        }
        L2tpCmd::SessionModify => {
            L2tpEvent::SessionModified(netlink::decode_session_info(attrs)?)
        }
        L2tpCmd::SessionDelete => {
            L2tpEvent::SessionDeleted(netlink::decode_session_info(attrs)?)
        }
        _ => return Ok(None),
    };
    Ok(Some(event))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use netlink_packet_core::{DoneMessage, NetlinkHeader};
    use netlink_packet_generic::GenlMessage;
    use netlink_packet_l2tp::{L2tpAttribute, L2tpEncapType, L2tpPwType};

    use super::*;
    use crate::{SessionId, TunnelId};

    fn notification(
        cmd: L2tpCmd,
        attributes: Vec<L2tpAttribute>,
    ) -> NetlinkMessage<RawGenlMessage> {
        let genl = GenlMessage::from_payload(L2tpMessage { cmd, attributes });
        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(RawGenlMessage::from_genlmsg(genl)),
        )
    }

    #[test]
    fn notifications_decode_into_events() {
        let tunnel = vec![
            L2tpAttribute::ConnId(1),
            L2tpAttribute::PeerConnId(2),
            L2tpAttribute::ProtoVersion(3),
            L2tpAttribute::EncapType(L2tpEncapType::Ip),
            L2tpAttribute::IpSaddr(Ipv4Addr::LOCALHOST),
            L2tpAttribute::IpDaddr(Ipv4Addr::LOCALHOST),
        ];
        let event = decode(notification(L2tpCmd::TunnelDelete, tunnel))
            .unwrap()
            .unwrap();
        let L2tpEvent::TunnelDeleted(info) = event else {
            panic!("expected a tunnel deletion");
        };
        assert_eq!(info.tunnel_id, TunnelId(1));

        let session = vec![
            L2tpAttribute::ConnId(1),
            L2tpAttribute::PeerConnId(2),
            L2tpAttribute::SessionId(3),
            L2tpAttribute::PeerSessionId(4),
            L2tpAttribute::PwType(L2tpPwType::Eth),
        ];
        let event = decode(notification(L2tpCmd::SessionCreate, session))
            .unwrap()
            .unwrap();
        let L2tpEvent::SessionCreated(info) = event else {
            panic!("expected a session creation");
        };
        assert_eq!(info.session_id, SessionId(3));

        // Other commands and non-notification payloads are skipped.
        assert_eq!(decode(notification(L2tpCmd::Noop, vec![])).unwrap(), None);
        let done = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Done(DoneMessage::default()),
        );
        assert_eq!(decode(done).unwrap(), None);

        // A malformed notification is an error, not a panic.
        let broken = notification(L2tpCmd::TunnelCreate, vec![]);
        assert!(matches!(
            decode(broken),
            Err(crate::Error::UnexpectedReply(_))
        ));
    }
}

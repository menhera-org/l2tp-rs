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
/// The originating network namespace is not encoded in these notifications.
/// On kernels that broadcast L2TP events across namespaces (including Linux
/// 6.8), an event can describe an object outside the receiving handle's
/// namespace. Use it as a hint to query current local state; matching IDs
/// alone do not establish that it describes a local object.
///
/// Deletion events carry the state the object had before it was removed.
/// The kernel sends tunnel modification events for `TUNNEL_MODIFY` requests
/// although it changes nothing. A session event names its interface by the
/// creation-time name only; the interface index is known to the process
/// that created the session
/// ([`SessionHandle::ifindex`](crate::SessionHandle::ifindex)), and an observer
/// can only look the name up while the interface still bears it.
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
/// Notifications are advisory and may describe another network namespace;
/// see [`L2tpEvent`]. Dropping the stream leaves the multicast group.
/// Messages that are not
/// L2TP notifications are skipped; a notification that fails to decode is
/// reported as an error and the stream continues.
/// If the receive buffer overruns, an [`Error::Io`](crate::Error::Io) with
/// OS error `ENOBUFS` reports that notifications were lost. Query current
/// tunnel and session state to resynchronize; the stream continues afterward.
#[derive(Debug)]
pub struct Events {
    receiver: UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
    connection: tokio::task::JoinHandle<()>,
    family_id: u16,
}

impl Events {
    pub(crate) fn new(
        receiver: UnboundedReceiver<(
            NetlinkMessage<RawGenlMessage>,
            SocketAddr,
        )>,
        connection: tokio::task::JoinHandle<()>,
        family_id: u16,
    ) -> Self {
        Self {
            receiver,
            connection,
            family_id,
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
                Poll::Ready(Some((message, _))) => {
                    match decode(message, self.family_id) {
                        Ok(Some(event)) => return Poll::Ready(Some(Ok(event))),
                        Ok(None) => continue,
                        Err(err) => return Poll::Ready(Some(Err(err))),
                    }
                }
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
    family_id: u16,
) -> crate::Result<Option<L2tpEvent>> {
    // netlink-proto translates receive-buffer ENOBUFS into this control
    // message, whose type is NLMSG_OVERRUN rather than the L2TP family ID.
    if matches!(message.payload, NetlinkPayload::Overrun(_)) {
        return Err(std::io::Error::from_raw_os_error(libc::ENOBUFS).into());
    }
    if message.header.message_type != family_id {
        return Ok(None);
    }
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

    use futures::StreamExt;
    use netlink_packet_core::{DoneMessage, NLMSG_OVERRUN, NetlinkHeader};
    use netlink_packet_generic::GenlMessage;
    use netlink_packet_l2tp::{L2tpAttribute, L2tpEncapType, L2tpPwType};

    use super::*;
    use crate::{SessionId, TunnelId};

    const FAMILY_ID: u16 = 42;

    fn notification(
        family_id: u16,
        cmd: L2tpCmd,
        attributes: Vec<L2tpAttribute>,
    ) -> NetlinkMessage<RawGenlMessage> {
        let genl = GenlMessage::from_payload(L2tpMessage { cmd, attributes });
        let mut header = NetlinkHeader::default();
        header.message_type = family_id;
        NetlinkMessage::new(
            header,
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
        let event = decode(
            notification(FAMILY_ID, L2tpCmd::TunnelDelete, tunnel),
            FAMILY_ID,
        )
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
        let event = decode(
            notification(FAMILY_ID, L2tpCmd::SessionCreate, session),
            FAMILY_ID,
        )
        .unwrap()
        .unwrap();
        let L2tpEvent::SessionCreated(info) = event else {
            panic!("expected a session creation");
        };
        assert_eq!(info.session_id, SessionId(3));

        // Other commands and non-notification payloads are skipped.
        assert_eq!(
            decode(notification(FAMILY_ID, L2tpCmd::Noop, vec![]), FAMILY_ID)
                .unwrap(),
            None
        );
        let done = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::Done(DoneMessage::default()),
        );
        assert_eq!(decode(done, FAMILY_ID).unwrap(), None);

        // A malformed notification is an error, not a panic.
        let broken = notification(FAMILY_ID, L2tpCmd::TunnelCreate, vec![]);
        assert!(matches!(
            decode(broken, FAMILY_ID),
            Err(crate::Error::UnexpectedReply(_))
        ));
    }

    #[test]
    fn notifications_from_other_families_are_skipped() {
        // The matching L2TP command would be malformed without attributes.
        let foreign =
            notification(FAMILY_ID + 1, L2tpCmd::TunnelCreate, vec![]);
        assert_eq!(decode(foreign, FAMILY_ID).unwrap(), None);
    }

    #[tokio::test]
    async fn stream_reports_overruns_and_continues_with_notifications() {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        let connection = tokio::spawn(std::future::pending());
        let mut events = Events::new(receiver, connection, FAMILY_ID);
        let mut header = NetlinkHeader::default();
        header.message_type = NLMSG_OVERRUN;
        sender
            .unbounded_send((
                NetlinkMessage::new(
                    header,
                    NetlinkPayload::Overrun(Vec::new()),
                ),
                SocketAddr::new(0, 0),
            ))
            .unwrap();
        sender
            .unbounded_send((
                notification(
                    FAMILY_ID,
                    L2tpCmd::TunnelCreate,
                    vec![
                        L2tpAttribute::ConnId(1),
                        L2tpAttribute::PeerConnId(2),
                        L2tpAttribute::ProtoVersion(3),
                        L2tpAttribute::EncapType(L2tpEncapType::Ip),
                        L2tpAttribute::IpSaddr(Ipv4Addr::LOCALHOST),
                        L2tpAttribute::IpDaddr(Ipv4Addr::LOCALHOST),
                    ],
                ),
                SocketAddr::new(0, 0),
            ))
            .unwrap();
        drop(sender);

        let error = events.next().await.unwrap().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOBUFS));
        assert!(matches!(
            events.next().await.unwrap().unwrap(),
            L2tpEvent::TunnelCreated(info) if info.tunnel_id == TunnelId(1)
        ));
        assert!(events.next().await.is_none());
    }
}

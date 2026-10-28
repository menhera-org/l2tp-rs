// SPDX-License-Identifier: MIT

use std::{
    collections::VecDeque,
    io,
    os::fd::{AsFd, BorrowedFd},
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Stream, channel::mpsc::UnboundedReceiver};
use genetlink::message::RawGenlMessage;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_l2tp::{L2tpCmd, L2tpMessage};
use netlink_sys::{Socket, SocketAddr};
use tokio::io::unix::AsyncFd;

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
/// Messages that are not L2TP notifications from the kernel are skipped; a
/// notification that fails to decode is reported as an error and the stream
/// continues.
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
                Poll::Ready(Some((message, source))) => {
                    // The header port can be forged; only recvmsg's sender
                    // address identifies a kernel notification.
                    if source.port_number() != 0 {
                        continue;
                    }
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

/// Stream of [`L2tpEvent`]s read straight from the kernel socket, created by
/// [`L2tpHandle::events_bounded`](crate::L2tpHandle::events_bounded).
///
/// Unlike [`Events`], no task drains the socket into a queue: notifications
/// wait in the socket's receive buffer until the stream is polled, so the
/// memory they take is bounded by that buffer. Size it with `SO_RCVBUF` or
/// `SO_RCVBUFFORCE` on [`as_fd`](AsFd::as_fd). Once it is full, the kernel
/// drops notifications, and the next item is an
/// [`Error::Io`](crate::Error::Io) with OS error `ENOBUFS`. The socket holds
/// that report ahead of the notifications it still queues, so it cannot be
/// lost behind them. Query current tunnel and session state to
/// resynchronize; the stream continues afterward and never ends.
///
/// Otherwise it behaves like [`Events`]: notifications are advisory and may
/// describe another network namespace, messages that are not L2TP
/// notifications from the kernel are skipped, and a notification that fails
/// to decode is reported as an error. Dropping the stream leaves the
/// multicast group.
#[derive(Debug)]
pub struct BoundedEvents {
    socket: AsyncFd<Socket>,
    pending: Pending,
}

impl BoundedEvents {
    pub(crate) fn new(socket: AsyncFd<Socket>, family_id: u16) -> Self {
        Self {
            socket,
            pending: Pending::new(family_id),
        }
    }
}

impl Stream for BoundedEvents {
    type Item = crate::Result<L2tpEvent>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(item) = this.pending.next() {
                return Poll::Ready(Some(item));
            }
            let mut guard = match this.socket.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Some(Err(err.into())));
                }
                Poll::Pending => return Poll::Pending,
            };
            if let Ok(received) =
                guard.try_io(|socket| socket.get_ref().recv_from_full())
            {
                this.pending.receive(received);
            }
        }
    }
}

impl AsFd for BoundedEvents {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.get_ref().as_fd()
    }
}

/// The items decoded from one received datagram, not yet returned.
#[derive(Debug)]
pub(crate) struct Pending {
    family_id: u16,
    items: VecDeque<crate::Result<L2tpEvent>>,
}

impl Pending {
    pub(crate) fn new(family_id: u16) -> Self {
        Self {
            family_id,
            items: VecDeque::new(),
        }
    }

    pub(crate) fn next(&mut self) -> Option<crate::Result<L2tpEvent>> {
        self.items.pop_front()
    }

    /// Queues what one receive returned: the socket's error, such as
    /// `ENOBUFS`, or the notifications a datagram holds.
    pub(crate) fn receive(
        &mut self,
        received: io::Result<(Vec<u8>, SocketAddr)>,
    ) {
        let (datagram, source) = match received {
            Ok(received) => received,
            Err(err) => return self.items.push_back(Err(err.into())),
        };
        // As in `Events`, only recvmsg's sender address identifies the
        // kernel.
        if source.port_number() != 0 {
            return;
        }
        let mut rest = datagram.as_slice();
        while !rest.is_empty() {
            let message = match NetlinkMessage::deserialize(rest) {
                Ok(message) => message,
                // The framing is lost; nothing after it can be found.
                Err(err) => return self.items.push_back(Err(err.into())),
            };
            // Messages are padded to four bytes.
            let len = (message.header.length as usize).next_multiple_of(4);
            match decode(message, self.family_id) {
                Ok(Some(event)) => self.items.push_back(Ok(event)),
                Ok(None) => {}
                Err(err) => self.items.push_back(Err(err)),
            }
            rest = rest.get(len..).unwrap_or_default();
        }
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
        let mut genl =
            GenlMessage::from_payload(L2tpMessage { cmd, attributes });
        genl.set_resolved_family_id(family_id);
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

    /// Serializes messages into one datagram, as the kernel may batch them.
    fn datagram(messages: Vec<NetlinkMessage<RawGenlMessage>>) -> Vec<u8> {
        let mut datagram = Vec::new();
        for mut message in messages {
            message.finalize();
            let start = datagram.len();
            datagram.resize(start + message.buffer_len(), 0);
            message.serialize(&mut datagram[start..]);
        }
        datagram
    }

    #[test]
    fn datagrams_are_decoded_from_the_kernel_only() {
        let created = || {
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
            )
        };
        let kernel = SocketAddr::new(0, 0);
        let mut pending = Pending::new(FAMILY_ID);
        // Every message of a datagram counts; other families are skipped.
        let foreign =
            notification(FAMILY_ID + 1, L2tpCmd::TunnelCreate, vec![]);
        pending.receive(Ok((
            datagram(vec![created(), foreign, created()]),
            kernel,
        )));
        for _ in 0..2 {
            assert!(matches!(
                pending.next(),
                Some(Ok(L2tpEvent::TunnelCreated(info))) if info.tunnel_id == TunnelId(1)
            ));
        }
        assert!(pending.next().is_none());
        // A forged header port of zero does not disguise a user-space sender.
        pending.receive(Ok((
            datagram(vec![created()]),
            SocketAddr::new(31337, 0),
        )));
        assert!(pending.next().is_none());
        // Broken framing and socket errors are reported.
        pending.receive(Ok((vec![0; 7], kernel)));
        assert!(matches!(
            pending.next(),
            Some(Err(crate::Error::Netlink(_)))
        ));
        pending.receive(Err(io::Error::from_raw_os_error(libc::ENOBUFS)));
        let error = pending.next().unwrap().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOBUFS));
        assert!(pending.next().is_none());
    }

    #[tokio::test]
    async fn stream_ignores_non_kernel_senders() {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        let connection = tokio::spawn(std::future::pending());
        let mut events = Events::new(receiver, connection, FAMILY_ID);
        // A forged header port of zero must not disguise a user-space
        // sender. This payload would otherwise fail L2TP decoding.
        sender
            .unbounded_send((
                notification(FAMILY_ID, L2tpCmd::TunnelCreate, vec![]),
                SocketAddr::new(31337, 0),
            ))
            .unwrap();
        drop(sender);
        assert!(events.next().await.is_none());
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

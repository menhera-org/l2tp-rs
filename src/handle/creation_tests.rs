// SPDX-License-Identifier: MIT

use std::{
    collections::VecDeque,
    future::Future,
    num::NonZeroI32,
    os::fd::RawFd,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};

use bytes::BufMut;
use netlink_packet_core::ErrorMessage;
use netlink_packet_l2tp::{L2tpCmd, L2tpPwType};
use netlink_sys::{AsyncSocket, Socket, SocketAddr};

use super::*;
use crate::{Encapsulation, UdpEndpoint};

type Message = NetlinkMessage<GenlMessage<L2tpMessage>>;
type Creation = Pin<Box<dyn Future<Output = crate::Result<()>> + Send>>;

// Exercise the real generic-netlink request queue and response decoder without
// requiring kernel L2TP support. Only the socket transport is replaced. Tests
// poll the connection explicitly, so transmission and ACK delivery are ordered
// independently of the caller and the creation task.
#[derive(Default)]
struct Wire {
    requests: VecDeque<Message>,
    replies: VecDeque<Vec<u8>>,
}

#[derive(Default)]
struct TestSocket(Arc<Mutex<Wire>>);

impl AsyncSocket for TestSocket {
    fn socket_ref(&self) -> &Socket {
        panic!("the mock transport has no kernel socket")
    }

    fn socket_mut(&mut self) -> &mut Socket {
        panic!("the mock transport has no kernel socket")
    }

    fn new(_protocol: isize) -> io::Result<Self> {
        Ok(Self::default())
    }

    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0
            .lock()
            .unwrap()
            .requests
            .push_back(Message::deserialize(buf).unwrap());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        _addr: &SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.poll_send(cx, buf)
    }

    fn poll_recv<B: BufMut>(
        &self,
        _cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<()>> {
        match self.0.lock().unwrap().replies.pop_front() {
            Some(reply) => {
                buf.put_slice(&reply);
                Poll::Ready(Ok(()))
            }
            None => Poll::Pending,
        }
    }

    fn poll_recv_from<B: BufMut>(
        &self,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<SocketAddr>> {
        self.poll_recv(cx, buf).map_ok(|()| SocketAddr::new(0, 0))
    }

    fn poll_recv_from_full(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(Vec<u8>, SocketAddr)>> {
        let mut buf = Vec::new();
        self.poll_recv_from(cx, &mut buf).map_ok(|addr| (buf, addr))
    }
}

struct Harness {
    handle: L2tpHandle,
    connection: Pin<Box<dyn Future<Output = ()>>>,
    wire: Arc<Mutex<Wire>>,
}

impl Harness {
    fn new() -> Self {
        let (mut connection, genl, _unsolicited) =
            genetlink::new_connection_with_socket::<TestSocket>().unwrap();
        connection.set_forward_ack(true);
        connection.set_forward_done(true);
        let wire = connection.socket_mut().0.clone();
        Self {
            handle: super::tests::test_handle(genl),
            connection: Box::pin(connection),
            wire,
        }
    }

    async fn step(&mut self) {
        assert!(futures::poll!(self.connection.as_mut()).is_pending());
        tokio::task::yield_now().await;
    }

    async fn next_request(&mut self, expected: L2tpCmd) -> Message {
        for _ in 0..16 {
            self.step().await;
            if let Some(message) =
                self.wire.lock().unwrap().requests.pop_front()
            {
                assert_eq!(payload(&message).cmd, expected);
                assert!(
                    payload(&message)
                        .attributes
                        .contains(&L2tpAttribute::ConnId(101))
                );
                return message;
            }
        }
        panic!("no {expected:?} request after driving all ready tasks");
    }

    fn reply(&mut self, request: &Message, mut reply: Message) {
        reply.header.sequence_number = request.header.sequence_number;
        reply.finalize();
        let mut bytes = vec![0; reply.buffer_len()];
        reply.serialize(&mut bytes);
        self.wire.lock().unwrap().replies.push_back(bytes);
    }

    fn ack(&mut self, request: &Message, code: i32) {
        let mut error = ErrorMessage::default();
        error.code = NonZeroI32::new(-code);
        self.reply(
            request,
            Message::new(Default::default(), NetlinkPayload::Error(error)),
        );
    }

    async fn session_lookup(&mut self, fail: bool) {
        let get = self.next_request(L2tpCmd::SessionGet).await;
        if fail {
            self.ack(&get, libc::EIO);
        } else {
            let mut message = L2tpMessage::new(L2tpCmd::SessionGet);
            message.attributes = vec![
                L2tpAttribute::ConnId(101),
                L2tpAttribute::PeerConnId(102),
                L2tpAttribute::SessionId(201),
                L2tpAttribute::PeerSessionId(202),
                L2tpAttribute::PwType(L2tpPwType::Eth),
            ];
            let mut genl = GenlMessage::from_payload(message);
            genl.set_resolved_family_id(1234);
            self.reply(&get, Message::from(genl));
        }
    }

    async fn finish_cleanup(&mut self, resource: Resource) {
        let delete = self.next_request(resource.delete_cmd()).await;
        if matches!(resource, Resource::Session) {
            assert!(
                payload(&delete)
                    .attributes
                    .contains(&L2tpAttribute::SessionId(201))
            );
        }
        self.ack(&delete, 0);
        if !matches!(resource, Resource::Session) {
            // Tunnel deletion then polls until the tunnel is gone.
            let get = self.next_request(L2tpCmd::TunnelGet).await;
            self.ack(&get, libc::ENODEV);
        }
        self.assert_idle().await;
    }

    async fn assert_idle(&mut self) {
        for _ in 0..16 {
            self.step().await;
        }
        assert!(self.wire.lock().unwrap().requests.is_empty());
        assert_eq!(Arc::strong_count(&self.handle.inner), 1);
    }

    fn create(&self, resource: Resource) -> (Creation, Option<SocketIdentity>) {
        let handle = self.handle.clone();
        let local = UdpEndpoint::V4("127.0.0.1:0".parse().unwrap());
        let remote = UdpEndpoint::V4("127.0.0.1:1701".parse().unwrap());
        let config = TunnelConfig::new(
            TunnelId(101),
            TunnelId(102),
            Encapsulation::Udp {
                local: local.clone(),
                remote: remote.clone(),
                udp_csum: true,
                udp_zero_csum6_tx: false,
                udp_zero_csum6_rx: false,
            },
        )
        .unwrap();
        match resource {
            Resource::Managed => {
                let socket = TunnelSocket::udp(&local, &remote, None).unwrap();
                let identity = SocketIdentity::new(socket.as_raw_fd());
                (
                    Box::pin(async move {
                        handle.create_tunnel(config, socket).await?;
                        Ok(())
                    }),
                    Some(identity),
                )
            }
            Resource::Unmanaged => (
                Box::pin(async move {
                    handle.create_unmanaged_tunnel(config).await?;
                    Ok(())
                }),
                None,
            ),
            Resource::Session => (
                Box::pin(async move {
                    handle
                        .create_session(SessionConfig::eth(
                            TunnelId(101),
                            SessionId(201),
                            SessionId(202),
                        ))
                        .await?;
                    Ok(())
                }),
                None,
            ),
        }
    }
}

fn payload(message: &Message) -> &L2tpMessage {
    let NetlinkPayload::InnerMessage(message) = &message.payload else {
        panic!("expected an L2TP request");
    };
    &message.payload
}

#[derive(Clone, Copy)]
enum Resource {
    Managed,
    Unmanaged,
    Session,
}

impl Resource {
    fn create_cmd(self) -> L2tpCmd {
        match self {
            Self::Managed | Self::Unmanaged => L2tpCmd::TunnelCreate,
            Self::Session => L2tpCmd::SessionCreate,
        }
    }

    fn delete_cmd(self) -> L2tpCmd {
        match self {
            Self::Managed | Self::Unmanaged => L2tpCmd::TunnelDelete,
            Self::Session => L2tpCmd::SessionDelete,
        }
    }
}

struct SocketIdentity {
    fd: RawFd,
    device: libc::dev_t,
    inode: libc::ino_t,
}

impl SocketIdentity {
    fn new(fd: RawFd) -> Self {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat initializes the provided stat buffer on success.
        assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
        // SAFETY: fstat succeeded above.
        let stat = unsafe { stat.assume_init() };
        Self {
            fd,
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }

    fn is_open(&self) -> bool {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat initializes the provided stat buffer on success.
        if unsafe { libc::fstat(self.fd, stat.as_mut_ptr()) } != 0 {
            return false;
        }
        // SAFETY: fstat succeeded above.
        let stat = unsafe { stat.assume_init() };
        // Comparing identity also catches another test reusing the closed FD.
        (stat.st_dev, stat.st_ino) == (self.device, self.inode)
    }
}

async fn cancelled_create(
    resource: Resource,
    cancel_before_send: bool,
    code: i32,
) {
    let mut harness = Harness::new();
    let (mut creation, socket) = harness.create(resource);
    assert!(futures::poll!(creation.as_mut()).is_pending());
    // The creation task can enqueue its request, but the connection has not
    // been polled and therefore cannot transmit it yet.
    tokio::task::yield_now().await;
    let request = if cancel_before_send {
        drop(creation);
        if let Some(socket) = &socket {
            assert!(socket.is_open(), "cancellation closed the queued FD");
        }
        harness.next_request(resource.create_cmd()).await
    } else {
        let request = harness.next_request(resource.create_cmd()).await;
        drop(creation);
        request
    };
    if let Some(socket) = &socket {
        assert!(socket.is_open(), "socket closed before CREATE ACK");
        assert!(
            payload(&request)
                .attributes
                .contains(&L2tpAttribute::Fd(socket.fd))
        );
    }
    harness.ack(&request, code);
    if code == 0 {
        if matches!(resource, Resource::Session) {
            harness.session_lookup(false).await;
        }
        harness.finish_cleanup(resource).await;
    } else {
        // EEXIST means this task never acquired ownership. No DELETE may be
        // sent, since it could remove an existing resource owned by a caller.
        harness.assert_idle().await;
    }
    if let Some(socket) = &socket {
        assert!(!socket.is_open(), "unclaimed socket was not released");
    }
}

#[tokio::test]
async fn cancelled_managed_create_keeps_the_queued_socket_until_ack() {
    for before_send in [true, false] {
        cancelled_create(Resource::Managed, before_send, 0).await;
    }
}

#[tokio::test]
async fn cancelled_unmanaged_create_deletes_after_ack() {
    for before_send in [true, false] {
        cancelled_create(Resource::Unmanaged, before_send, 0).await;
    }
}

#[tokio::test]
async fn cancelled_session_create_deletes_after_ack_and_lookup() {
    for before_send in [true, false] {
        cancelled_create(Resource::Session, before_send, 0).await;
    }
}

#[tokio::test]
async fn failed_cancelled_creates_do_not_delete_existing_resources() {
    for resource in [Resource::Managed, Resource::Unmanaged, Resource::Session]
    {
        for before_send in [true, false] {
            cancelled_create(resource, before_send, libc::EEXIST).await;
        }
    }
}

#[tokio::test]
async fn cancellation_during_session_lookup_still_deletes_the_session() {
    for lookup_fails in [false, true] {
        let mut harness = Harness::new();
        let (mut creation, _) = harness.create(Resource::Session);
        assert!(futures::poll!(creation.as_mut()).is_pending());
        let create = harness.next_request(L2tpCmd::SessionCreate).await;
        harness.ack(&create, 0);
        // Drive through the ACK while leaving GET and its reply pending.
        for _ in 0..4 {
            harness.step().await;
        }
        drop(creation);
        harness.session_lookup(lookup_fails).await;
        harness.finish_cleanup(Resource::Session).await;
    }
}

#[tokio::test]
async fn completed_but_unclaimed_creation_results_are_deleted() {
    for resource in [Resource::Managed, Resource::Unmanaged, Resource::Session]
    {
        let mut harness = Harness::new();
        let (mut creation, socket) = harness.create(resource);
        assert!(futures::poll!(creation.as_mut()).is_pending());
        let create = harness.next_request(resource.create_cmd()).await;
        harness.ack(&create, 0);
        if matches!(resource, Resource::Session) {
            harness.session_lookup(false).await;
        }
        for _ in 0..8 {
            harness.step().await;
        }
        // The task has finished, but its caller has not polled the JoinHandle
        // to claim the result. Cancelling must drop that completed result too.
        assert!(harness.wire.lock().unwrap().requests.is_empty());
        if let Some(socket) = &socket {
            assert!(socket.is_open());
        }
        // Drop on a thread with no Tokio context: cleanup must still use the
        // runtime that owns the creation task.
        std::thread::spawn(move || drop(creation)).join().unwrap();
        harness.finish_cleanup(resource).await;
        if let Some(socket) = &socket {
            assert!(!socket.is_open());
        }
    }
}

#[test]
fn deletion_wait_handles_present_tunnels_without_runtime_drivers() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        for code in [libc::ENODEV, libc::EIO] {
            let mut harness = Harness::new();
            let handle = harness.handle.clone();
            let mut wait = Box::pin(handle.wait_tunnel_removed(TunnelId(101)));
            assert!(futures::poll!(wait.as_mut()).is_pending());
            let get = harness.next_request(L2tpCmd::TunnelGet).await;
            let mut message = L2tpMessage::new(L2tpCmd::TunnelGet);
            message.attributes = vec![
                L2tpAttribute::ConnId(101),
                L2tpAttribute::PeerConnId(102),
                L2tpAttribute::ProtoVersion(3),
                L2tpAttribute::EncapType(
                    netlink_packet_l2tp::L2tpEncapType::Ip,
                ),
                L2tpAttribute::IpSaddr(std::net::Ipv4Addr::LOCALHOST),
                L2tpAttribute::IpDaddr(std::net::Ipv4Addr::LOCALHOST),
            ];
            let mut genl = GenlMessage::from_payload(message);
            genl.set_resolved_family_id(1234);
            harness.reply(&get, Message::from(genl));

            // The first lookup still finds the tunnel. Drive the transport
            // until the pacing thread wakes the wait for another lookup,
            // without enabling Tokio's timer or I/O drivers.
            let get = futures::future::poll_fn(|cx| {
                assert!(wait.as_mut().poll(cx).is_pending());
                assert!(harness.connection.as_mut().poll(cx).is_pending());
                match harness.wire.lock().unwrap().requests.pop_front() {
                    Some(request) => Poll::Ready(request),
                    None => Poll::Pending,
                }
            })
            .await;
            assert_eq!(payload(&get).cmd, L2tpCmd::TunnelGet);
            harness.ack(&get, code);
            let result = futures::future::poll_fn(|cx| {
                let result = wait.as_mut().poll(cx);
                assert!(harness.connection.as_mut().poll(cx).is_pending());
                result
            })
            .await;
            if code == libc::ENODEV {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().raw_os_error(), Some(code));
            }
            assert!(harness.wire.lock().unwrap().requests.is_empty());
        }
    });
}

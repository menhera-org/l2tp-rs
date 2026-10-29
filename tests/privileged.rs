// SPDX-License-Identifier: MIT

#![cfg(target_os = "linux")]

use std::{
    io::{BufRead, BufReader},
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    process::{Command, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::StreamExt;
use genetlink::message::RawGenlMessage;
use l2tp::{
    Cookie, Encapsulation, EventSocket, IpEndpoint, L2SpecType, L2tpEvent,
    L2tpHandle, L2tpIfName, L2tpIfNameExt, L2tpVersion, NetNs, PppSocket,
    PppUnit, PseudowireType, SessionConfig, SessionHandle, SessionId,
    SessionModify, TunnelConfig, TunnelHandle, TunnelId, TunnelSocket,
    UdpEndpoint, blocking,
};
use netlink_packet_core::{
    Emitable, NLM_F_ACK, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_generic::GenlHeader;
use netlink_packet_l2tp::{L2tpAttribute, L2tpMessage, L2tpPwType};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_GENERIC};

static ID_COUNTER: AtomicU32 = AtomicU32::new(0);

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("failed to build tokio runtime: {e}"))
}

fn next_id_base() -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let pid = std::process::id() as u64;
    let seq = ID_COUNTER.fetch_add(1, Ordering::Relaxed) as u64;
    let mixed = now ^ (pid << 16) ^ seq;
    1_000_000_000u32.wrapping_add((mixed as u32) % 500_000_000)
}

fn is_eexist(err: &l2tp::Error) -> bool {
    err.kind() == Some(std::io::ErrorKind::AlreadyExists)
}

fn udp_loopback(version: L2tpVersion) -> TunnelConfig {
    let base = next_id_base();
    let base = if version == L2tpVersion::V2 {
        // Keep both IDs nonzero and leave room for the peer's ID.
        base % (u32::from(u16::MAX) - 1) + 1
    } else {
        base
    };
    TunnelConfig::new(
        TunnelId(base),
        TunnelId(base.wrapping_add(1)),
        Encapsulation::Udp {
            local: UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            remote: UdpEndpoint::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                17012,
            )),
            udp_csum: false,
            udp_zero_csum6_tx: false,
            udp_zero_csum6_rx: false,
        },
    )
    .unwrap_or_else(|e| panic!("TunnelConfig::new failed: {e}"))
    .with_version(version)
}

fn ip_loopback() -> TunnelConfig {
    let base = next_id_base();
    TunnelConfig::new(
        TunnelId(base),
        TunnelId(base.wrapping_add(1)),
        Encapsulation::Ip {
            local: IpEndpoint::V4(Ipv4Addr::LOCALHOST),
            remote: IpEndpoint::V4(Ipv4Addr::LOCALHOST),
        },
    )
    .unwrap_or_else(|e| panic!("TunnelConfig::new failed: {e}"))
}

/// Creates an unmanaged tunnel, retrying the random identifiers on EEXIST.
async fn create_unmanaged(
    handle: &L2tpHandle,
    make: impl Fn() -> TunnelConfig,
) -> (TunnelConfig, l2tp::TunnelHandle) {
    for _ in 0..16 {
        let config = make();
        match handle.create_unmanaged_tunnel(config.clone()).await {
            Ok(tunnel) => return (config, tunnel),
            Err(e) if is_eexist(&e) => continue,
            Err(e) => panic!("create_unmanaged_tunnel failed: {e}"),
        }
    }
    panic!("could not allocate unique tunnel id after retries");
}

#[test]
#[ignore = "requires CAP_NET_RAW/root (SO_BINDTODEVICE)"]
fn privileged_bind_to_device_on_loopback() {
    let local = UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let remote = UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999));
    let device = L2tpIfName::new("lo").unwrap_or_else(|e| panic!("{e}"));

    let socket = TunnelSocket::udp(&local, &remote, None)
        .unwrap_or_else(|e| panic!("failed to create UDP tunnel socket: {e}"));
    socket
        .bind_to_device(&device)
        .unwrap_or_else(|e| panic!("SO_BINDTODEVICE failed: {e}"));
    // Disconnecting clears SO_BINDTODEVICE; binding again restores it.
    socket
        .disconnect()
        .unwrap_or_else(|e| panic!("disconnect failed: {e}"));
    assert!(socket.peer_addr_udp().is_err());
    let unbound = TunnelSocket::from_fd(
        socket
            .try_clone_fd()
            .unwrap_or_else(|e| panic!("dup failed: {e}")),
    )
    .unwrap_or_else(|e| panic!("from_fd failed: {e}"));
    assert!(
        unbound.local_addr_udp().is_ok(),
        "the local address survives the disconnect"
    );
    socket
        .bind_to_device(&device)
        .unwrap_or_else(|e| panic!("SO_BINDTODEVICE failed again: {e}"));
    socket
        .reconnect_udp(&remote)
        .unwrap_or_else(|e| panic!("reconnect failed: {e}"));
    // An adopted descriptor reads the bound device back.
    let adopted = TunnelSocket::from_fd(socket.into_fd())
        .unwrap_or_else(|e| panic!("from_fd failed: {e}"));
    drop(adopted);
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp generic-netlink support"]
fn privileged_unmanaged_tunnel_lifecycle_over_genl() {
    runtime().block_on(async {
        let handle = L2tpHandle::new(Default::default())
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        for version in [L2tpVersion::V3, L2tpVersion::V2] {
            let (config, tunnel) =
                create_unmanaged(&handle, || udp_loopback(version)).await;
            let info = tunnel
                .get()
                .await
                .unwrap_or_else(|e| panic!("tunnel get failed: {e}"));
            assert_eq!(info.tunnel_id, config.tunnel_id());
            assert_eq!(info.peer_tunnel_id, config.peer_tunnel_id());
            assert_eq!(info.version, version);

            // Opening an existing tunnel yields a non-owning handle.
            let opened = handle
                .open_tunnel(config.tunnel_id())
                .await
                .unwrap_or_else(|e| panic!("open_tunnel failed: {e}"));
            assert!(!opened.auto_delete());
            drop(opened);

            tunnel
                .delete()
                .await
                .unwrap_or_else(|e| panic!("delete failed: {e}"));
            assert!(handle.get_tunnel(config.tunnel_id()).await.is_err());
        }
    });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp_eth support"]
fn privileged_session_lifecycle_over_genl() {
    runtime().block_on(async {
        let handle = L2tpHandle::new(Default::default())
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let (config, mut tunnel) = create_unmanaged(&handle, ip_loopback).await;
        tunnel.set_auto_delete(false);
        let tunnel_id = config.tunnel_id();
        let session_id = SessionId(tunnel_id.0.wrapping_add(2));
        let peer_session_id = SessionId(tunnel_id.0.wrapping_add(3));

        let session_config = SessionConfig {
            tunnel_id,
            session_id,
            peer_session_id,
            pseudowire_type: PseudowireType::Eth,
            l2spec_type: L2SpecType::None,
            cookie: Cookie::from([1, 2, 3, 4]),
            peer_cookie: Cookie::none(),
            recv_seq: false,
            send_seq: false,
            lns_mode: false,
            recv_timeout_ms: Some(2000),
            ifname: None,
        };

        let mut session = handle
            .create_session(session_config)
            .await
            .unwrap_or_else(|e| panic!("create_session failed: {e}"));
        session.set_auto_delete(false);
        // The index was captured from the registration broadcast and agrees
        // with the name while the interface still bears it.
        let ifindex =
            session.ifindex().expect("ethernet sessions have an index");
        assert_eq!(
            session
                .ifname()
                .unwrap()
                .index()
                .unwrap_or_else(|e| panic!("{e}")),
            ifindex
        );

        let info = session
            .get()
            .await
            .unwrap_or_else(|e| panic!("session get failed: {e}"));
        assert_eq!(info.tunnel_id, tunnel_id);
        assert_eq!(info.peer_tunnel_id, config.peer_tunnel_id());
        assert_eq!(info.session_id, session_id);
        assert_eq!(info.peer_session_id, peer_session_id);
        assert_eq!(info.pseudowire_type, PseudowireType::Eth);
        assert_eq!(
            info.cookie,
            l2tp::KernelCookie::from(Cookie::from([1, 2, 3, 4]))
        );
        let ifname = info.ifname.expect("ethernet sessions have an interface");

        // The same session is reachable by its interface name.
        let by_name = handle
            .get_session_by_ifname(&ifname)
            .await
            .unwrap_or_else(|e| panic!("get_session_by_ifname failed: {e}"));
        assert_eq!(by_name.session_id, session_id);
        handle
            .modify_session_by_ifname(
                &ifname,
                SessionModify {
                    recv_seq: Some(true),
                    send_seq: Some(true),
                    lns_mode: Some(false),
                    recv_timeout_ms: Some(1500),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("session modify failed: {e}"));
        let opened = handle
            .open_session_by_ifname(&ifname)
            .await
            .unwrap_or_else(|e| panic!("open_session_by_ifname failed: {e}"));
        assert!(!opened.auto_delete());
        assert_eq!(opened.ifname(), Some(&ifname));
        assert_eq!(opened.ifindex(), Some(ifindex));
        drop(opened);

        handle
            .delete_session_by_ifname(&ifname)
            .await
            .unwrap_or_else(|e| panic!("delete_session failed: {e}"));
        handle
            .delete_tunnel(tunnel_id)
            .await
            .unwrap_or_else(|e| panic!("delete_tunnel failed: {e}"));
    });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp generic-netlink support"]
fn privileged_events_report_tunnel_lifecycle() {
    runtime().block_on(async {
        let handle = L2tpHandle::new(Default::default())
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let mut events = handle
            .events()
            .await
            .unwrap_or_else(|e| panic!("events failed: {e}"));
        let (config, tunnel) =
            create_unmanaged(&handle, || udp_loopback(L2tpVersion::V3)).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = events
                    .next()
                    .await
                    .expect("the stream is open")
                    .expect("the event decodes");
                if matches!(
                    event,
                    L2tpEvent::TunnelCreated(info) if info.tunnel_id == config.tunnel_id()
                ) {
                    break;
                }
            }
        })
        .await
        .expect("a creation event for this tunnel arrives");
        tunnel
            .delete()
            .await
            .unwrap_or_else(|e| panic!("delete failed: {e}"));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = events
                    .next()
                    .await
                    .expect("the stream is open")
                    .expect("the event decodes");
                if matches!(
                    event,
                    L2tpEvent::TunnelDeleted(info) if info.tunnel_id == config.tunnel_id()
                ) {
                    break;
                }
            }
        })
        .await
        .expect("a deletion event for this tunnel arrives");
    });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp generic-netlink support"]
fn privileged_bounded_events_report_overflow_and_continue() {
    runtime().block_on(async {
        let handle = L2tpHandle::new(Default::default())
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let mut events = handle
            .events_bounded()
            .await
            .unwrap_or_else(|e| panic!("events_bounded failed: {e}"));
        // The kernel raises this to its minimum receive buffer.
        let size: libc::c_int = 0;
        let rc = unsafe {
            libc::setsockopt(
                events.as_fd().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&size as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "SO_RCVBUF: {}", std::io::Error::last_os_error());
        // Notifications nobody reads overflow it.
        for _ in 0..32 {
            let (_, tunnel) =
                create_unmanaged(&handle, || udp_loopback(L2tpVersion::V3))
                    .await;
            tunnel
                .delete()
                .await
                .unwrap_or_else(|e| panic!("delete failed: {e}"));
        }
        let error = events
            .next()
            .await
            .expect("the stream does not end")
            .expect_err("the loss is reported first");
        assert_eq!(error.raw_os_error(), Some(libc::ENOBUFS), "{error}");
        // The kernel delivers again once the queued notifications are read.
        while let Ok(item) =
            tokio::time::timeout(Duration::from_millis(200), events.next())
                .await
        {
            item.expect("the stream does not end")
                .expect("the queued notifications decode");
        }
        let (config, _tunnel) =
            create_unmanaged(&handle, || udp_loopback(L2tpVersion::V3)).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = events
                    .next()
                    .await
                    .expect("the stream does not end")
                    .expect("the event decodes");
                if matches!(
                    event,
                    L2tpEvent::TunnelCreated(info) if info.tunnel_id == config.tunnel_id()
                ) {
                    break;
                }
            }
        })
        .await
        .expect("events arrive after the overflow");
    });
}

/// Resolves the `l2tp` family and its notification group without this crate,
/// as a caller with its own netlink code would.
async fn resolve_l2tp_family() -> (u16, u32) {
    let (connection, genl, _) = genetlink::new_connection()
        .unwrap_or_else(|e| panic!("genetlink connection failed: {e}"));
    tokio::spawn(connection);
    let family = genl
        .resolve_family::<L2tpMessage>()
        .await
        .unwrap_or_else(|e| panic!("resolve_family failed: {e}"));
    (family.id, family.multicast_groups["l2tp"])
}

/// Sends `SESSION_CREATE` with a cookie of any length, as another program
/// could. This crate refuses non-RFC lengths, `netlink-packet-l2tp` will not
/// emit them and iproute2 takes 8 or 16 hexadecimal digits only, so the
/// attribute is written by hand.
fn create_foreign_session(
    family_id: u16,
    attributes: &[L2tpAttribute],
    cookie: &[u8],
) {
    let mut payload = vec![0; attributes.buffer_len()];
    attributes.emit(&mut payload);
    // L2TP_ATTR_COOKIE: length, type, value, padding.
    payload.extend_from_slice(&((4 + cookie.len()) as u16).to_ne_bytes());
    payload.extend_from_slice(&15u16.to_ne_bytes());
    payload.extend_from_slice(cookie);
    payload.resize(payload.len().next_multiple_of(4), 0);

    // L2TP_CMD_SESSION_CREATE, version 1.
    let raw = RawGenlMessage::new(
        GenlHeader { cmd: 5, version: 1 },
        payload,
        family_id,
    );
    let mut request = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::InnerMessage(raw),
    );
    request.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    request.finalize();
    let mut buf = vec![0; request.buffer_len()];
    request.serialize(&mut buf);

    let socket = Socket::new(NETLINK_GENERIC)
        .unwrap_or_else(|e| panic!("netlink socket failed: {e}"));
    socket
        .send_to(&buf, &SocketAddr::new(0, 0), 0)
        .unwrap_or_else(|e| panic!("SESSION_CREATE send failed: {e}"));
    let (reply, _) = socket
        .recv_from_full()
        .unwrap_or_else(|e| panic!("SESSION_CREATE reply failed: {e}"));
    let reply = NetlinkMessage::<RawGenlMessage>::deserialize(&reply)
        .unwrap_or_else(|e| panic!("undecodable reply: {e}"));
    match reply.payload {
        NetlinkPayload::Error(err) => {
            assert!(err.code.is_none(), "SESSION_CREATE failed: {err}")
        }
        other => panic!("unexpected reply: {other:?}"),
    }
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp_eth support"]
fn privileged_foreign_odd_length_cookies_are_reported_never_sent() {
    runtime().block_on(async {
        let handle = L2tpHandle::new(Default::default())
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let (config, _tunnel) = create_unmanaged(&handle, ip_loopback).await;
        let tunnel_id = config.tunnel_id();
        let session_id = SessionId(tunnel_id.0.wrapping_add(2));
        let peer_session_id = SessionId(tunnel_id.0.wrapping_add(3));
        let (family_id, _) = resolve_l2tp_family().await;
        create_foreign_session(
            family_id,
            &[
                L2tpAttribute::ConnId(tunnel_id.0),
                L2tpAttribute::SessionId(session_id.0),
                L2tpAttribute::PeerSessionId(peer_session_id.0),
                L2tpAttribute::PwType(L2tpPwType::Eth),
            ],
            &[1, 2],
        );

        let info = handle
            .get_session(tunnel_id, session_id)
            .await
            .unwrap_or_else(|e| panic!("get_session failed: {e}"));
        assert_eq!(info.cookie.as_bytes(), &[1, 2]);
        assert!(!info.cookie.is_rfc3931());
        let listed = handle
            .list_sessions(tunnel_id)
            .await
            .unwrap_or_else(|e| panic!("list_sessions failed: {e}"));
        assert!(
            listed
                .iter()
                .any(|s| s.session_id == session_id && s.cookie == info.cookie)
        );
        handle
            .list_all_sessions()
            .await
            .unwrap_or_else(|e| panic!("list_all_sessions failed: {e}"));

        // Non-RFC reports cannot be converted into a creation cookie.
        assert!(matches!(
            Cookie::try_from(info.cookie),
            Err(l2tp::Error::InvalidCookieLength(2))
        ));
        handle
            .delete_session(tunnel_id, session_id)
            .await
            .unwrap_or_else(|e| panic!("delete_session failed: {e}"));
    });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp_eth support"]
fn privileged_event_socket_reads_without_a_runtime() {
    let rt = runtime();
    let (family_id, group_id) = rt.block_on(resolve_l2tp_family());
    let mut socket = EventSocket::new(family_id, group_id)
        .unwrap_or_else(|e| panic!("EventSocket::new failed: {e}"));
    // Nothing happened yet in this namespace.
    while let Some(item) = socket.try_next() {
        item.unwrap_or_else(|e| panic!("a queued notification failed: {e}"));
    }

    let session_id = rt.block_on(async {
        let handle = L2tpHandle::new(Default::default())
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let (config, _tunnel) = create_unmanaged(&handle, ip_loopback).await;
        let tunnel_id = config.tunnel_id();
        let session_id = SessionId(tunnel_id.0.wrapping_add(2));
        handle
            .create_session(SessionConfig::eth(
                tunnel_id,
                session_id,
                SessionId(tunnel_id.0.wrapping_add(3)),
            ))
            .await
            .unwrap_or_else(|e| panic!("create_session failed: {e}"))
            .delete()
            .await
            .unwrap_or_else(|e| panic!("delete failed: {e}"));
        session_id
    });

    // Read from this thread, outside the runtime, without blocking.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match socket.try_next() {
            Some(Ok(L2tpEvent::SessionDeleted(info)))
                if info.session_id == session_id =>
            {
                break;
            }
            Some(item) => {
                item.unwrap_or_else(|e| panic!("notification failed: {e}"));
            }
            None => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the deletion is announced"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// A PPP session on a fresh unmanaged tunnel, with the `PPPoL2TP` socket
/// attached to it. The session handle has auto-delete disabled, because the
/// kernel deletes the session together with the socket.
async fn attached_ppp_session(
    handle: &L2tpHandle,
) -> (
    TunnelConfig,
    TunnelHandle,
    SessionId,
    SessionHandle,
    PppSocket,
) {
    let (config, tunnel) =
        create_unmanaged(handle, || udp_loopback(L2tpVersion::V3)).await;
    let session_id = SessionId(config.tunnel_id().0.wrapping_add(2));
    let peer_session_id = SessionId(config.tunnel_id().0.wrapping_add(3));
    let mut session = handle
        .create_session(SessionConfig::ppp(
            config.tunnel_id(),
            session_id,
            peer_session_id,
        ))
        .await
        .unwrap_or_else(|e| panic!("create_session failed: {e}"));
    session.set_auto_delete(false);

    let socket = PppSocket::connect(
        L2tpVersion::V3,
        config.tunnel_id(),
        config.peer_tunnel_id(),
        session_id,
        peer_session_id,
    )
    .unwrap_or_else(|e| panic!("PppSocket::connect failed: {e}"));
    (config, tunnel, session_id, session, socket)
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and the kernel l2tp_ppp module"]
fn privileged_ppp_session_attaches_a_pppol2tp_socket() {
    runtime().block_on(async {
        let handle = L2tpHandle::new(Default::default())
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let (config, tunnel, session_id, session, socket) =
            attached_ppp_session(&handle).await;
        let channel = socket
            .channel_index()
            .unwrap_or_else(|e| panic!("channel_index failed: {e}"));
        assert!(channel >= 0);
        // A second socket cannot attach to the same session.
        let err = PppSocket::connect(
            L2tpVersion::V3,
            config.tunnel_id(),
            config.peer_tunnel_id(),
            session_id,
            SessionId(session_id.0.wrapping_add(1)),
        )
        .err()
        .map(|e| e.raw_os_error());
        assert_eq!(err, Some(Some(libc::EEXIST)));

        // Releasing the PPPoL2TP socket deletes the session in the kernel.
        drop(socket);
        let err = handle
            .get_session(config.tunnel_id(), session_id)
            .await
            .expect_err("the session is gone with its socket");
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV), "{err}");
        drop(session);
        tunnel.delete().await.unwrap_or_else(|e| panic!("{e}"));
    });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root, the kernel l2tp_ppp module and \
            /dev/ppp"]
fn privileged_ppp_unit_connects_and_disconnects_a_channel() {
    runtime().block_on(async {
        let handle = L2tpHandle::new(Default::default())
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let (_config, tunnel, _session_id, _session, socket) =
            attached_ppp_session(&handle).await;

        let unit = match PppUnit::new() {
            Ok(unit) => unit,
            // Without the device node (for example in a user namespace that
            // cannot create one) there is nothing to test.
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                eprintln!("skipping: /dev/ppp is absent: {e}");
                drop(socket);
                tunnel.delete().await.unwrap_or_else(|e| panic!("{e}"));
                return;
            }
            Err(e) => panic!("PppUnit::new failed: {e}"),
        };
        assert!(unit.ifname().as_bytes().starts_with(b"ppp"));
        let link = unit
            .connect_channel(&socket)
            .unwrap_or_else(|e| panic!("connect_channel failed: {e}"));
        // Dropping the channel disconnects it, so it can be connected again.
        drop(link);
        let link = unit
            .connect_channel(&socket)
            .unwrap_or_else(|e| panic!("second connect_channel failed: {e}"));
        drop(link);
        drop(unit);
        drop(socket);
        tunnel.delete().await.unwrap_or_else(|e| panic!("{e}"));
    });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp generic-netlink support"]
fn privileged_blocking_api_manages_a_tunnel() {
    let handle = blocking::L2tpHandle::new(Default::default())
        .unwrap_or_else(|e| panic!("blocking::L2tpHandle::new failed: {e}"));
    let mut events = handle
        .events_bounded()
        .unwrap_or_else(|e| panic!("events_bounded failed: {e}"));
    let mut created = None;
    for _ in 0..16 {
        let config = udp_loopback(L2tpVersion::V3);
        match handle.create_unmanaged_tunnel(config.clone()) {
            Ok(tunnel) => {
                created = Some((config, tunnel));
                break;
            }
            Err(e) if is_eexist(&e) => continue,
            Err(e) => panic!("create_unmanaged_tunnel failed: {e}"),
        }
    }
    let (config, tunnel) = created.expect("a unique tunnel id");
    // The notification was queued before the creation was acknowledged.
    assert!(events.any(|event| matches!(
        event,
        Ok(L2tpEvent::TunnelCreated(info)) if info.tunnel_id == config.tunnel_id()
    )));
    let info = tunnel.get().unwrap_or_else(|e| panic!("get failed: {e}"));
    assert_eq!(info.tunnel_id, config.tunnel_id());
    assert!(
        handle
            .list_tunnels()
            .unwrap_or_else(|e| panic!("{e}"))
            .iter()
            .any(|t| t.tunnel_id == config.tunnel_id())
    );
    tunnel
        .delete()
        .unwrap_or_else(|e| panic!("delete failed: {e}"));
    assert!(handle.get_tunnel(config.tunnel_id()).is_err());
}

#[test]
#[ignore = "requires kernel l2tp_ip and l2tp_ip6 support"]
fn privileged_managed_ip_sockets_report_their_peer() {
    for local in [
        IpEndpoint::V4(Ipv4Addr::LOCALHOST),
        IpEndpoint::v6(std::net::Ipv6Addr::LOCALHOST),
    ] {
        let id = next_id_base();
        let socket = TunnelSocket::ip(
            &local,
            &local,
            None,
            TunnelId(id),
            TunnelId(id.wrapping_add(1)),
        )
        .unwrap_or_else(|e| {
            panic!("create an L2TP/IP socket for {local}: {e}")
        });
        // IPv4 L2TP/IP sockets get no peer from the kernel; the socket
        // remembers it.
        assert_eq!(
            socket.peer_addr_ip().unwrap_or_else(|e| panic!("{e}")),
            local
        );
        let config = TunnelConfig::for_socket(
            TunnelId(id),
            TunnelId(id.wrapping_add(1)),
            &socket,
        )
        .unwrap_or_else(|e| panic!("describe the socket: {e}"));
        assert_eq!(
            *config.encapsulation(),
            Encapsulation::Ip {
                local: local.clone(),
                remote: local.clone()
            }
        );

        // After a disconnect the kernel still reports the old IPv6 peer;
        // the socket does not.
        socket
            .disconnect()
            .unwrap_or_else(|e| panic!("disconnect: {e}"));
        let err = socket.peer_addr_ip().expect_err("no peer after disconnect");
        assert_eq!(err.raw_os_error(), Some(libc::ENOTCONN), "{err}");
        let config = TunnelConfig::for_socket(
            TunnelId(id),
            TunnelId(id.wrapping_add(1)),
            &socket,
        )
        .unwrap_or_else(|e| panic!("describe the disconnected socket: {e}"));
        let Encapsulation::Ip { remote, .. } = config.encapsulation() else {
            panic!("expected IP encapsulation");
        };
        assert!(remote.ip().is_unspecified(), "{remote}");
        socket
            .reconnect_ip(&local)
            .unwrap_or_else(|e| panic!("reconnect: {e}"));
        assert_eq!(
            socket.peer_addr_ip().unwrap_or_else(|e| panic!("{e}")),
            local
        );
        drop(socket);
    }
}

/// Brings an interface up with `SIOCSIFFLAGS`.
fn set_up(ifindex: u32) {
    let name =
        L2tpIfName::from_index(ifindex).unwrap_or_else(|e| panic!("{e}"));
    // SAFETY: plain socket call; the descriptor is owned right below.
    let fd = unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
    };
    assert_ne!(fd, -1, "{}", std::io::Error::last_os_error());
    // SAFETY: `fd` is a new descriptor nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: an all-zero `ifreq` is a valid value.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in request.ifr_name.iter_mut().zip(name.as_array()) {
        *dst = *src as libc::c_char;
    }
    // The request type differs between C libraries.
    #[allow(clippy::unnecessary_cast)]
    let (get, set) = (
        libc::SIOCGIFFLAGS as libc::Ioctl,
        libc::SIOCSIFFLAGS as libc::Ioctl,
    );
    // SAFETY: `request` names the interface; the kernel writes its flags.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), get, &mut request) };
    assert_ne!(rc, -1, "{}", std::io::Error::last_os_error());
    // SAFETY: SIOCGIFFLAGS stored the flags in this union member.
    unsafe { request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short };
    // SAFETY: `request` names the interface and carries the new flags.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), set, &mut request) };
    assert_ne!(rc, -1, "{}", std::io::Error::last_os_error());
}

/// Sends one broadcast Ethernet frame out of the interface.
fn send_frame(ifindex: u32) {
    // IEEE local experimental EtherType.
    const ETHERTYPE: u16 = 0x88b5;
    // SAFETY: plain socket call; the descriptor is owned right below.
    let fd = unsafe {
        libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0)
    };
    assert_ne!(fd, -1, "{}", std::io::Error::last_os_error());
    // SAFETY: `fd` is a new descriptor nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: an all-zero `sockaddr_ll` is a valid value.
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as libc::c_ushort;
    addr.sll_protocol = ETHERTYPE.to_be();
    addr.sll_ifindex = ifindex as libc::c_int;
    let mut frame = [0u8; 60];
    frame[..6].fill(0xff);
    // A locally administered source address.
    frame[6] = 0x02;
    frame[12..14].copy_from_slice(&ETHERTYPE.to_be_bytes());
    // SAFETY: `frame` and `addr` are valid for the lengths passed.
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            frame.as_ptr().cast(),
            frame.len(),
            0,
            (&addr as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    assert_eq!(
        sent,
        frame.len() as isize,
        "{}",
        std::io::Error::last_os_error()
    );
}

/// Reads one counter of `/sys/class/net/<interface>/statistics`.
fn link_stat(ifindex: u32, stat: &str) -> u64 {
    let name =
        L2tpIfName::from_index(ifindex).unwrap_or_else(|e| panic!("{e}"));
    let path = std::path::Path::new("/sys/class/net")
        .join(name.as_os_str())
        .join("statistics")
        .join(stat);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Whether the counter exceeds `floor` within two seconds.
fn stat_rises(ifindex: u32, stat: &str, floor: u64) -> bool {
    (0..200).any(|_| {
        let risen = link_stat(ifindex, stat) > floor;
        if !risen {
            std::thread::sleep(Duration::from_millis(10));
        }
        risen
    })
}

#[test]
#[ignore = "requires CAP_NET_ADMIN and CAP_NET_RAW/root and kernel l2tp_ip and \
            l2tp_eth support"]
fn privileged_unconnected_ip_socket_drops_until_connected() {
    runtime().block_on(async {
        let handle = L2tpHandle::new(Default::default())
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let id = next_id_base();
        let (ours, theirs) = (TunnelId(id), TunnelId(id.wrapping_add(1)));
        let (our_session, their_session) =
            (SessionId(id.wrapping_add(2)), SessionId(id.wrapping_add(3)));
        let local = IpEndpoint::V4(Ipv4Addr::LOCALHOST);

        let socket = TunnelSocket::ip_unconnected(&local, None, ours, theirs)
            .unwrap_or_else(|e| panic!("create an unconnected socket: {e}"));
        let config = TunnelConfig::for_socket(ours, theirs, &socket)
            .unwrap_or_else(|e| panic!("describe the socket: {e}"));
        let tunnel = handle
            .create_tunnel(config, socket)
            .await
            .unwrap_or_else(|e| panic!("create_tunnel failed: {e}"));
        let session = handle
            .create_session(SessionConfig::eth(
                ours,
                our_session,
                their_session,
            ))
            .await
            .unwrap_or_else(|e| panic!("create_session failed: {e}"));

        // The peer is a kernel-socket tunnel on the same host with the
        // identifiers crossed.
        let peer_tunnel = handle
            .create_unmanaged_tunnel(
                TunnelConfig::new(
                    theirs,
                    ours,
                    Encapsulation::Ip {
                        local: local.clone(),
                        remote: local.clone(),
                    },
                )
                .unwrap_or_else(|e| panic!("TunnelConfig::new failed: {e}")),
            )
            .await
            .unwrap_or_else(|e| panic!("create the peer tunnel: {e}"));
        let peer_session = handle
            .create_session(SessionConfig::eth(
                theirs,
                their_session,
                our_session,
            ))
            .await
            .unwrap_or_else(|e| panic!("create the peer session: {e}"));

        let ifindex =
            session.ifindex().expect("ethernet sessions have an index");
        let peer_ifindex = peer_session
            .ifindex()
            .expect("ethernet sessions have an index");
        set_up(ifindex);
        set_up(peer_ifindex);

        let dropped = link_stat(ifindex, "tx_dropped");
        send_frame(ifindex);
        assert!(
            stat_rises(ifindex, "tx_dropped", dropped),
            "an unconnected tunnel drops what its session sends"
        );

        tunnel
            .socket()
            .expect("a managed tunnel keeps its socket")
            .reconnect_ip(&local)
            .unwrap_or_else(|e| panic!("reconnect: {e}"));
        let received = link_stat(peer_ifindex, "rx_packets");
        send_frame(ifindex);
        assert!(
            stat_rises(peer_ifindex, "rx_packets", received),
            "the frame reaches the peer after the connect"
        );

        peer_tunnel
            .delete()
            .await
            .unwrap_or_else(|e| panic!("delete the peer tunnel: {e}"));
        tunnel
            .delete()
            .await
            .unwrap_or_else(|e| panic!("delete the tunnel: {e}"));
    });
}

/// Set in the re-executed test binary that runs without procfs.
const NO_PROC_CHILD: &str = "L2TP_TEST_NO_PROC_CHILD";

#[test]
#[ignore = "requires CAP_SYS_ADMIN and CAP_NET_ADMIN/root, unshare(1) and \
            kernel l2tp_ip and l2tp_eth support"]
fn privileged_works_without_procfs() {
    if std::env::var_os(NO_PROC_CHILD).is_some() {
        return without_procfs();
    }
    // A private mount namespace with an empty tmpfs over /proc; the child
    // reports through its exit status.
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("{e}"));
    let status = Command::new("unshare")
        .args([
            "-m",
            "sh",
            "-c",
            "mount -t tmpfs none /proc && exec \"$0\" \"$@\"",
        ])
        .arg(exe)
        .args(["--exact", "privileged_works_without_procfs", "--ignored"])
        .env(NO_PROC_CHILD, "1")
        .status();
    match status {
        Ok(status) => assert!(status.success(), "the child failed: {status}"),
        Err(e) => eprintln!("skipped: cannot run unshare: {e}"),
    }
}

fn without_procfs() {
    assert!(
        !std::path::Path::new("/proc/thread-self").exists(),
        "procfs is still visible"
    );
    runtime().block_on(async {
        let handle = L2tpHandle::new(Default::default())
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        handle
            .list_tunnels()
            .await
            .unwrap_or_else(|e| panic!("list_tunnels failed: {e}"));
        let id = next_id_base();
        let local = IpEndpoint::V4(Ipv4Addr::LOCALHOST);
        let socket = TunnelSocket::ip(
            &local,
            &local,
            None,
            TunnelId(id),
            TunnelId(id.wrapping_add(1)),
        )
        .unwrap_or_else(|e| panic!("create an L2TP/IP socket: {e}"));
        let config = TunnelConfig::for_socket(
            TunnelId(id),
            TunnelId(id.wrapping_add(1)),
            &socket,
        )
        .unwrap_or_else(|e| panic!("describe the socket: {e}"));
        let tunnel = handle
            .create_tunnel(config, socket)
            .await
            .unwrap_or_else(|e| panic!("create_tunnel failed: {e}"));
        let session = handle
            .create_session(SessionConfig::eth(
                TunnelId(id),
                SessionId(id.wrapping_add(2)),
                SessionId(id.wrapping_add(3)),
            ))
            .await
            .unwrap_or_else(|e| panic!("create_session failed: {e}"));
        assert!(session.ifindex().is_some());
        let events = handle
            .events()
            .await
            .unwrap_or_else(|e| panic!("events failed: {e}"));
        drop(events);
        drop(session);
        drop(tunnel);
    });
}

#[test]
#[ignore = "requires CAP_SYS_ADMIN and CAP_NET_ADMIN/root, unshare(1) and \
            kernel l2tp generic-netlink support"]
fn privileged_new_in_controls_another_namespace() {
    let child = Command::new("unshare")
        .args(["-n", "sh", "-c", "echo ready && exec sleep 60"])
        .stdout(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(e) => return eprintln!("skipped: cannot run unshare: {e}"),
    };
    // The line comes after unshare(2), so the namespace is the new one.
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap_or_else(|e| panic!("{e}"));
    let result = std::panic::catch_unwind(|| {
        assert_eq!(line, "ready\n", "unshare -n failed");
        let netns = NetNs::open(format!("/proc/{}/ns/net", child.id()))
            .unwrap_or_else(|e| panic!("open the namespace: {e}"));
        runtime().block_on(async {
            let outer = L2tpHandle::new(Default::default())
                .await
                .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
            let inner = L2tpHandle::new_in(&netns, Default::default())
                .await
                .unwrap_or_else(|e| panic!("L2tpHandle::new_in failed: {e}"));
            // Opened from this thread, in another namespace: setns.
            let events = inner
                .events()
                .await
                .unwrap_or_else(|e| panic!("events failed: {e}"));
            let (config, tunnel) =
                create_unmanaged(&outer, || udp_loopback(L2tpVersion::V3))
                    .await;
            let listed = inner
                .list_tunnels()
                .await
                .unwrap_or_else(|e| panic!("list_tunnels failed: {e}"));
            tunnel.delete().await.unwrap_or_else(|e| panic!("{e}"));
            assert!(
                listed.iter().all(|t| t.tunnel_id != config.tunnel_id()),
                "the other namespace sees this tunnel"
            );
            drop(events);
        });
    });
    let _ = child.kill();
    let _ = child.wait();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[cfg(feature = "cli")]
#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp generic-netlink support"]
fn privileged_cli_tunnel_survives_process_exit() {
    let id = next_id_base();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_l2tp"))
        .args([
            "tunnel",
            "create",
            "--tunnel-id",
            &id.to_string(),
            "--peer-tunnel-id",
            &(id + 1).to_string(),
            "--local",
            "127.0.0.1:0",
            "--remote",
            "127.0.0.1:17012",
        ])
        .output()
        .expect("run l2tp tunnel create");
    // A failed create (including EEXIST) gives us no ownership of this ID.
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    runtime().block_on(async {
        let handle = L2tpHandle::new(Default::default()).await.unwrap();
        let info = handle.get_tunnel(TunnelId(id)).await;
        // Clean up our tunnel before asserting that the lookup succeeded.
        let cleanup = handle.delete_tunnel(TunnelId(id)).await;
        assert_eq!(
            info.expect("tunnel must survive CLI exit").tunnel_id,
            TunnelId(id)
        );
        cleanup.expect("delete CLI-created tunnel");
    });
}

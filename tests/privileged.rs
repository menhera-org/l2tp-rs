// SPDX-License-Identifier: MIT

#![cfg(target_os = "linux")]

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::StreamExt;
use l2tp::{
    Cookie, Encapsulation, IpEndpoint, L2SpecType, L2tpEvent, L2tpHandle,
    L2tpIfName, L2tpVersion, PppSocket, PppUnit, PseudowireType, SessionConfig,
    SessionId, SessionModify, TunnelConfig, TunnelId, TunnelSocket,
    UdpEndpoint, blocking,
};

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
        let handle = L2tpHandle::new()
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
        let handle = L2tpHandle::new()
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let (config, mut tunnel) = create_unmanaged(&handle, || {
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
        })
        .await;
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

        let info = session
            .get()
            .await
            .unwrap_or_else(|e| panic!("session get failed: {e}"));
        assert_eq!(info.tunnel_id, tunnel_id);
        assert_eq!(info.peer_tunnel_id, config.peer_tunnel_id());
        assert_eq!(info.session_id, session_id);
        assert_eq!(info.peer_session_id, peer_session_id);
        assert_eq!(info.pseudowire_type, PseudowireType::Eth);
        assert_eq!(info.cookie, Cookie::from([1, 2, 3, 4]));
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
        let handle = L2tpHandle::new()
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let mut events = handle
            .events()
            .await
            .unwrap_or_else(|e| panic!("events failed: {e}"));
        let (config, tunnel) =
            create_unmanaged(&handle, || udp_loopback(L2tpVersion::V3)).await;
        let created = tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("a creation event arrives")
            .expect("the stream is open")
            .expect("the event decodes");
        assert!(matches!(
            created,
            L2tpEvent::TunnelCreated(info) if info.tunnel_id == config.tunnel_id()
        ));
        tunnel
            .delete()
            .await
            .unwrap_or_else(|e| panic!("delete failed: {e}"));
        let deleted = tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("a deletion event arrives")
            .expect("the stream is open")
            .expect("the event decodes");
        assert!(matches!(
            deleted,
            L2tpEvent::TunnelDeleted(info) if info.tunnel_id == config.tunnel_id()
        ));
    });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp_ppp and ppp_generic \
            support"]
fn privileged_ppp_session_attaches_a_pppol2tp_socket() {
    runtime().block_on(async {
        let handle = L2tpHandle::new()
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let (config, tunnel) =
            create_unmanaged(&handle, || udp_loopback(L2tpVersion::V3)).await;
        let session_id = SessionId(config.tunnel_id().0.wrapping_add(2));
        let peer_session_id = SessionId(config.tunnel_id().0.wrapping_add(3));
        let session = handle
            .create_session(SessionConfig::ppp(
                config.tunnel_id(),
                session_id,
                peer_session_id,
            ))
            .await
            .unwrap_or_else(|e| panic!("create_session failed: {e}"));

        let socket = PppSocket::connect(
            L2tpVersion::V3,
            config.tunnel_id(),
            config.peer_tunnel_id(),
            session_id,
            peer_session_id,
        )
        .unwrap_or_else(|e| panic!("PppSocket::connect failed: {e}"));
        let channel = socket
            .channel_index()
            .unwrap_or_else(|e| panic!("channel_index failed: {e}"));
        assert!(channel >= 0);

        let unit = PppUnit::new().unwrap_or_else(|e| panic!("PppUnit: {e}"));
        assert!(unit.ifname().as_bytes().starts_with(b"ppp"));
        let link = unit
            .connect_channel(&socket)
            .unwrap_or_else(|e| panic!("connect_channel failed: {e}"));
        drop(link);
        drop(unit);
        drop(socket);

        session.delete().await.unwrap_or_else(|e| panic!("{e}"));
        tunnel.delete().await.unwrap_or_else(|e| panic!("{e}"));
    });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp generic-netlink support"]
fn privileged_blocking_api_manages_a_tunnel() {
    let handle = blocking::L2tpHandle::new()
        .unwrap_or_else(|e| panic!("blocking::L2tpHandle::new failed: {e}"));
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
#[ignore = "requires kernel l2tp_ip support"]
fn privileged_managed_ipv4_ip_socket_uses_inet_family() {
    let id = next_id_base();
    let socket = TunnelSocket::ip(
        &IpEndpoint::V4(Ipv4Addr::LOCALHOST),
        &IpEndpoint::V4(Ipv4Addr::LOCALHOST),
        None,
        TunnelId(id),
        TunnelId(id.wrapping_add(1)),
    )
    .expect("create an IPv4 L2TP/IP socket");
    let config = TunnelConfig::for_socket(
        TunnelId(id),
        TunnelId(id.wrapping_add(1)),
        &socket,
    )
    .expect("describe the socket");
    assert!(matches!(config.encapsulation(), Encapsulation::Ip { .. }));
    drop(socket);
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
    runtime().block_on(async {
        let handle = L2tpHandle::new().await.unwrap();
        let info = handle.get_tunnel(TunnelId(id)).await;
        // Clean up before asserting, including when creation returned an error.
        let cleanup = handle.delete_tunnel(TunnelId(id)).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            info.expect("tunnel must survive CLI exit").tunnel_id,
            TunnelId(id)
        );
        cleanup.expect("delete CLI-created tunnel");
    });
}

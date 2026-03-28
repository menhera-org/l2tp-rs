use l2tp::{
    Cookie, Encapsulation, IfName, IpEndpoint, L2SpecType, L2tpHandle, PseudowireType,
    SessionConfig, SessionId, SessionModify, TunnelConfig, TunnelId, TunnelModify, TunnelSocket,
    UdpEndpoint,
};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
    match err {
        l2tp::Error::KernelError { code, .. } => *code == libc::EEXIST,
        _ => false,
    }
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root (SO_BINDTODEVICE)"]
fn privileged_bind_to_device_on_loopback() {
    let local = UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let remote = UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999));
    let device = IfName::new("lo").unwrap_or_else(|e| panic!("invalid ifname: {e}"));

    let socket = TunnelSocket::udp(&local, &remote, None)
        .unwrap_or_else(|e| panic!("failed to create UDP tunnel socket: {e}"));
    socket
        .bind_to_device(&device)
        .unwrap_or_else(|e| panic!("SO_BINDTODEVICE failed: {e}"));
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp generic-netlink support"]
fn privileged_unmanaged_tunnel_lifecycle_over_genl() {
    runtime().block_on(async {
        let handle = L2tpHandle::new()
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let mut selected_ids = None;
        let mut tunnel_opt = None;
        for _ in 0..16 {
            let base = next_id_base();
            let tunnel_id = TunnelId(base);
            let peer_tunnel_id = TunnelId(base.wrapping_add(1));

            let config = TunnelConfig::new(
                tunnel_id,
                peer_tunnel_id,
                Encapsulation::Udp {
                    local: UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 17011)),
                    remote: UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 17012)),
                    udp_csum: false,
                    udp_zero_csum6_tx: false,
                    udp_zero_csum6_rx: false,
                },
            )
            .unwrap_or_else(|e| panic!("TunnelConfig::new failed: {e}"));

            match handle.create_unmanaged_tunnel(config).await {
                Ok(mut tunnel) => {
                    tunnel.set_auto_delete(false);
                    selected_ids = Some((tunnel_id, peer_tunnel_id));
                    tunnel_opt = Some(tunnel);
                    break;
                }
                Err(e) if is_eexist(&e) => continue,
                Err(e) => panic!("create_unmanaged_tunnel failed: {e}"),
            }
        }

        let (tunnel_id, peer_tunnel_id) = selected_ids
            .unwrap_or_else(|| panic!("could not allocate unique tunnel id after retries"));
        let mut tunnel = tunnel_opt.unwrap_or_else(|| panic!("missing tunnel after creation"));
        tunnel.set_auto_delete(false);

        let info = tunnel
            .get()
            .await
            .unwrap_or_else(|e| panic!("tunnel get failed: {e}"));
        assert_eq!(info.tunnel_id, tunnel_id);
        assert_eq!(info.peer_tunnel_id, peer_tunnel_id);
        assert_eq!(info.proto_version, 3);

        tunnel
            .modify(TunnelModify {
                udp_csum: Some(true),
            })
            .await
            .unwrap_or_else(|e| panic!("tunnel modify failed: {e}"));

        handle
            .delete_tunnel(tunnel_id)
            .await
            .unwrap_or_else(|e| panic!("delete_tunnel failed: {e}"));
    });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN/root and kernel l2tp_eth support"]
fn privileged_session_lifecycle_over_genl() {
    runtime().block_on(async {
        let handle = L2tpHandle::new()
            .await
            .unwrap_or_else(|e| panic!("L2tpHandle::new failed: {e}"));
        let mut selected_ids = None;
        let mut tunnel_opt = None;
        for _ in 0..16 {
            let base = next_id_base();
            let tunnel_id = TunnelId(base);
            let peer_tunnel_id = TunnelId(base.wrapping_add(1));
            let session_id = SessionId(base.wrapping_add(2));
            let peer_session_id = SessionId(base.wrapping_add(3));

            let tunnel_config = TunnelConfig::new(
                tunnel_id,
                peer_tunnel_id,
                Encapsulation::Ip {
                    local: IpEndpoint::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    remote: IpEndpoint::V4(Ipv4Addr::new(127, 0, 0, 1)),
                },
            )
            .unwrap_or_else(|e| panic!("TunnelConfig::new failed: {e}"));

            match handle.create_unmanaged_tunnel(tunnel_config).await {
                Ok(mut tunnel) => {
                    tunnel.set_auto_delete(false);
                    selected_ids = Some((tunnel_id, peer_tunnel_id, session_id, peer_session_id));
                    tunnel_opt = Some(tunnel);
                    break;
                }
                Err(e) if is_eexist(&e) => continue,
                Err(e) => panic!("create_unmanaged_tunnel failed: {e}"),
            }
        }

        let (tunnel_id, _peer_tunnel_id, session_id, peer_session_id) = selected_ids
            .unwrap_or_else(|| {
                panic!("could not allocate unique tunnel/session ids after retries")
            });
        let mut tunnel = tunnel_opt.unwrap_or_else(|| panic!("missing tunnel after creation"));
        tunnel.set_auto_delete(false);

        let session_config = SessionConfig {
            tunnel_id,
            session_id,
            peer_session_id,
            pseudowire_type: PseudowireType::Eth,
            l2spec_type: L2SpecType::None,
            cookie: Cookie::none(),
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
        assert_eq!(info.session_id, session_id);
        assert_eq!(info.peer_session_id, peer_session_id);
        assert_eq!(info.pseudowire_type, PseudowireType::Eth);

        session
            .modify(SessionModify {
                recv_seq: Some(true),
                send_seq: Some(true),
                lns_mode: Some(false),
                recv_timeout_ms: Some(1500),
            })
            .await
            .unwrap_or_else(|e| panic!("session modify failed: {e}"));

        handle
            .delete_session(tunnel_id, session_id)
            .await
            .unwrap_or_else(|e| panic!("delete_session failed: {e}"));

        handle
            .delete_tunnel(tunnel_id)
            .await
            .unwrap_or_else(|e| panic!("delete_tunnel failed: {e}"));
    });
}

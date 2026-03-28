use std::os::fd::RawFd;

use netlink_packet_l2tp::{
    L2tpAttribute, L2tpEncapType, L2tpL2SpecType, L2tpMessage, L2tpPwType, L2tpStatsAttr,
};

use crate::{
    Encapsulation, IfName, IpEndpoint, L2SpecType, PseudowireType, SessionConfig, SessionId,
    SessionInfo, SessionModify, SessionStats, TunnelConfig, TunnelId, TunnelInfo, TunnelModify,
    TunnelStats, UdpEndpoint,
};

pub(crate) fn encode_tunnel_create(config: &TunnelConfig, fd: Option<RawFd>) -> L2tpMessage {
    let mut attrs = vec![
        L2tpAttribute::ConnId(config.tunnel_id.0),
        L2tpAttribute::PeerConnId(config.peer_tunnel_id.0),
        L2tpAttribute::ProtoVersion(3),
    ];

    match &config.encapsulation {
        Encapsulation::Udp {
            local,
            remote,
            udp_csum,
            udp_zero_csum6_tx,
            udp_zero_csum6_rx,
        } => {
            attrs.push(L2tpAttribute::EncapType(L2tpEncapType::Udp));
            match (local, remote) {
                (UdpEndpoint::V4(local), UdpEndpoint::V4(remote)) => {
                    attrs.push(L2tpAttribute::IpSaddr(*local.ip()));
                    attrs.push(L2tpAttribute::IpDaddr(*remote.ip()));
                    attrs.push(L2tpAttribute::UdpSport(local.port()));
                    attrs.push(L2tpAttribute::UdpDport(remote.port()));
                }
                (UdpEndpoint::V6(local), UdpEndpoint::V6(remote)) => {
                    attrs.push(L2tpAttribute::Ip6Saddr(*local.ip()));
                    attrs.push(L2tpAttribute::Ip6Daddr(*remote.ip()));
                    attrs.push(L2tpAttribute::UdpSport(local.port()));
                    attrs.push(L2tpAttribute::UdpDport(remote.port()));
                }
                _ => {}
            }
            attrs.push(L2tpAttribute::UdpCsum(*udp_csum));
            if *udp_zero_csum6_tx {
                attrs.push(L2tpAttribute::UdpZeroCsum6Tx);
            }
            if *udp_zero_csum6_rx {
                attrs.push(L2tpAttribute::UdpZeroCsum6Rx);
            }
        }
        Encapsulation::Ip { local, remote } => {
            attrs.push(L2tpAttribute::EncapType(L2tpEncapType::Ip));
            match (local, remote) {
                (IpEndpoint::V4(local), IpEndpoint::V4(remote)) => {
                    attrs.push(L2tpAttribute::IpSaddr(*local));
                    attrs.push(L2tpAttribute::IpDaddr(*remote));
                }
                (IpEndpoint::V6(local), IpEndpoint::V6(remote)) => {
                    attrs.push(L2tpAttribute::Ip6Saddr(*local));
                    attrs.push(L2tpAttribute::Ip6Daddr(*remote));
                }
                _ => {}
            }
        }
    }

    if let Some(fd) = fd {
        attrs.push(L2tpAttribute::Fd(fd));
    }
    if let Some(ifname) = &config.ifname {
        attrs.push(L2tpAttribute::IfName(ifname.as_str().to_string()));
    }

    L2tpMessage::tunnel_create(attrs)
}

pub(crate) fn encode_tunnel_delete(id: TunnelId) -> L2tpMessage {
    L2tpMessage::tunnel_delete(vec![L2tpAttribute::ConnId(id.0)])
}

pub(crate) fn encode_tunnel_modify(id: TunnelId, params: &TunnelModify) -> L2tpMessage {
    let mut attrs = vec![L2tpAttribute::ConnId(id.0)];

    if let Some(v) = params.udp_csum {
        attrs.push(L2tpAttribute::UdpCsum(v));
    }

    L2tpMessage::tunnel_modify(attrs)
}

pub(crate) fn encode_tunnel_get(id: TunnelId) -> L2tpMessage {
    L2tpMessage::tunnel_get(vec![L2tpAttribute::ConnId(id.0)])
}

pub(crate) fn encode_tunnel_get_dump() -> L2tpMessage {
    L2tpMessage::tunnel_get(Vec::new())
}

pub(crate) fn encode_session_create(config: &SessionConfig) -> L2tpMessage {
    let mut attrs = vec![
        L2tpAttribute::ConnId(config.tunnel_id.0),
        L2tpAttribute::SessionId(config.session_id.0),
        L2tpAttribute::PeerSessionId(config.peer_session_id.0),
        L2tpAttribute::PwType(to_l2tp_pw(config.pseudowire_type)),
        L2tpAttribute::L2SpecType(to_l2tp_l2spec(config.l2spec_type)),
        L2tpAttribute::Cookie(config.cookie.as_bytes().to_vec()),
        L2tpAttribute::PeerCookie(config.peer_cookie.as_bytes().to_vec()),
    ];

    if config.recv_seq {
        attrs.push(L2tpAttribute::RecvSeq(true));
    }
    if config.send_seq {
        attrs.push(L2tpAttribute::SendSeq(true));
    }
    if config.lns_mode {
        attrs.push(L2tpAttribute::LnsMode(true));
    }
    if let Some(timeout) = config.recv_timeout_ms {
        attrs.push(L2tpAttribute::RecvTimeout(timeout));
    }
    if let Some(ifname) = &config.ifname {
        attrs.push(L2tpAttribute::IfName(ifname.as_str().to_string()));
    }

    L2tpMessage::session_create(attrs)
}

pub(crate) fn encode_session_delete(tunnel_id: TunnelId, session_id: SessionId) -> L2tpMessage {
    L2tpMessage::session_delete(vec![
        L2tpAttribute::ConnId(tunnel_id.0),
        L2tpAttribute::SessionId(session_id.0),
    ])
}

pub(crate) fn encode_session_modify(
    tunnel_id: TunnelId,
    session_id: SessionId,
    params: &SessionModify,
) -> L2tpMessage {
    let mut attrs = vec![
        L2tpAttribute::ConnId(tunnel_id.0),
        L2tpAttribute::SessionId(session_id.0),
    ];

    if let Some(v) = params.recv_seq {
        attrs.push(L2tpAttribute::RecvSeq(v));
    }
    if let Some(v) = params.send_seq {
        attrs.push(L2tpAttribute::SendSeq(v));
    }
    if let Some(v) = params.lns_mode {
        attrs.push(L2tpAttribute::LnsMode(v));
    }
    if let Some(v) = params.recv_timeout_ms {
        attrs.push(L2tpAttribute::RecvTimeout(v));
    }

    L2tpMessage::session_modify(attrs)
}

pub(crate) fn encode_session_get(tunnel_id: TunnelId, session_id: SessionId) -> L2tpMessage {
    L2tpMessage::session_get(vec![
        L2tpAttribute::ConnId(tunnel_id.0),
        L2tpAttribute::SessionId(session_id.0),
    ])
}

pub(crate) fn encode_session_get_dump(tunnel_id: Option<TunnelId>) -> L2tpMessage {
    let mut attrs = Vec::new();
    if let Some(tunnel_id) = tunnel_id {
        attrs.push(L2tpAttribute::ConnId(tunnel_id.0));
    }
    L2tpMessage::session_get(attrs)
}

pub(crate) fn decode_tunnel_info(attrs: &[L2tpAttribute]) -> crate::Result<TunnelInfo> {
    let mut tunnel_id = None;
    let mut peer_tunnel_id = None;
    let mut proto_version = None;
    let mut encap_type = None;
    let mut ifname: Option<IfName> = None;
    let mut using_ipsec = false;

    let mut ip_saddr_v4 = None;
    let mut ip_daddr_v4 = None;
    let mut ip_saddr_v6 = None;
    let mut ip_daddr_v6 = None;
    let mut udp_sport = None;
    let mut udp_dport = None;
    let mut udp_csum = false;
    let mut udp_zero_csum6_tx = false;
    let mut udp_zero_csum6_rx = false;

    for attr in attrs {
        match attr {
            L2tpAttribute::ConnId(v) => tunnel_id = Some(TunnelId(*v)),
            L2tpAttribute::PeerConnId(v) => peer_tunnel_id = Some(TunnelId(*v)),
            L2tpAttribute::ProtoVersion(v) => proto_version = Some(*v),
            L2tpAttribute::EncapType(v) => encap_type = Some(*v),
            L2tpAttribute::IfName(v) => ifname = Some(IfName::new(v.clone())?),
            L2tpAttribute::UsingIpsec(v) => using_ipsec = *v,
            L2tpAttribute::IpSaddr(v) => ip_saddr_v4 = Some(*v),
            L2tpAttribute::IpDaddr(v) => ip_daddr_v4 = Some(*v),
            L2tpAttribute::Ip6Saddr(v) => ip_saddr_v6 = Some(*v),
            L2tpAttribute::Ip6Daddr(v) => ip_daddr_v6 = Some(*v),
            L2tpAttribute::UdpSport(v) => udp_sport = Some(*v),
            L2tpAttribute::UdpDport(v) => udp_dport = Some(*v),
            L2tpAttribute::UdpCsum(v) => udp_csum = *v,
            L2tpAttribute::UdpZeroCsum6Tx => udp_zero_csum6_tx = true,
            L2tpAttribute::UdpZeroCsum6Rx => udp_zero_csum6_rx = true,
            _ => {}
        }
    }

    let tunnel_id = required(tunnel_id, "L2TP_ATTR_CONN_ID")?;
    let peer_tunnel_id = required(peer_tunnel_id, "L2TP_ATTR_PEER_CONN_ID")?;
    let proto_version = required(proto_version, "L2TP_ATTR_PROTO_VERSION")?;
    let encap_type = required(encap_type, "L2TP_ATTR_ENCAP_TYPE")?;

    let encapsulation = match encap_type {
        L2tpEncapType::Udp => {
            if let (Some(local), Some(remote), Some(sport), Some(dport)) =
                (ip_saddr_v4, ip_daddr_v4, udp_sport, udp_dport)
            {
                Encapsulation::Udp {
                    local: UdpEndpoint::V4(std::net::SocketAddrV4::new(local, sport)),
                    remote: UdpEndpoint::V4(std::net::SocketAddrV4::new(remote, dport)),
                    udp_csum,
                    udp_zero_csum6_tx,
                    udp_zero_csum6_rx,
                }
            } else if let (Some(local), Some(remote), Some(sport), Some(dport)) =
                (ip_saddr_v6, ip_daddr_v6, udp_sport, udp_dport)
            {
                Encapsulation::Udp {
                    local: UdpEndpoint::V6(std::net::SocketAddrV6::new(local, sport, 0, 0)),
                    remote: UdpEndpoint::V6(std::net::SocketAddrV6::new(remote, dport, 0, 0)),
                    udp_csum,
                    udp_zero_csum6_tx,
                    udp_zero_csum6_rx,
                }
            } else {
                return Err(missing_attr_error(
                    "missing or mixed-family UDP address/port attributes for tunnel",
                ));
            }
        }
        L2tpEncapType::Ip => {
            if let (Some(local), Some(remote)) = (ip_saddr_v4, ip_daddr_v4) {
                Encapsulation::Ip {
                    local: IpEndpoint::V4(local),
                    remote: IpEndpoint::V4(remote),
                }
            } else if let (Some(local), Some(remote)) = (ip_saddr_v6, ip_daddr_v6) {
                Encapsulation::Ip {
                    local: IpEndpoint::V6(local),
                    remote: IpEndpoint::V6(remote),
                }
            } else {
                return Err(missing_attr_error(
                    "missing IP address attributes for IP-encapsulated tunnel",
                ));
            }
        }
        L2tpEncapType::Other(v) => {
            return Err(crate::Error::KernelError {
                code: libc::EINVAL,
                message: format!("unsupported encapsulation type {v}"),
            })
        }
        _ => {
            return Err(crate::Error::KernelError {
                code: libc::EINVAL,
                message: "unsupported encapsulation type".to_string(),
            })
        }
    };

    Ok(TunnelInfo {
        tunnel_id,
        peer_tunnel_id,
        proto_version,
        encapsulation,
        ifname,
        using_ipsec,
    })
}

pub(crate) fn decode_session_info(attrs: &[L2tpAttribute]) -> crate::Result<SessionInfo> {
    let mut tunnel_id = None;
    let mut session_id = None;
    let mut peer_session_id = None;
    let mut pseudowire_type = None;
    let mut l2spec_type = None;
    let mut recv_seq = false;
    let mut send_seq = false;
    let mut lns_mode = false;
    let mut recv_timeout_ms = None;
    let mut ifname = None;
    let mut using_ipsec = false;

    for attr in attrs {
        match attr {
            L2tpAttribute::ConnId(v) => tunnel_id = Some(TunnelId(*v)),
            L2tpAttribute::SessionId(v) => session_id = Some(SessionId(*v)),
            L2tpAttribute::PeerSessionId(v) => peer_session_id = Some(SessionId(*v)),
            L2tpAttribute::PwType(v) => pseudowire_type = Some(from_l2tp_pw(*v)?),
            L2tpAttribute::L2SpecType(v) => l2spec_type = Some(from_l2tp_l2spec(*v)?),
            L2tpAttribute::RecvSeq(v) => recv_seq = *v,
            L2tpAttribute::SendSeq(v) => send_seq = *v,
            L2tpAttribute::LnsMode(v) => lns_mode = *v,
            L2tpAttribute::RecvTimeout(v) => recv_timeout_ms = Some(*v),
            L2tpAttribute::IfName(v) => ifname = Some(IfName::new(v.clone())?),
            L2tpAttribute::UsingIpsec(v) => using_ipsec = *v,
            _ => {}
        }
    }

    Ok(SessionInfo {
        tunnel_id: required(tunnel_id, "L2TP_ATTR_CONN_ID")?,
        session_id: required(session_id, "L2TP_ATTR_SESSION_ID")?,
        peer_session_id: required(peer_session_id, "L2TP_ATTR_PEER_SESSION_ID")?,
        pseudowire_type: required(pseudowire_type, "L2TP_ATTR_PW_TYPE")?,
        l2spec_type: l2spec_type.unwrap_or_default(),
        recv_seq,
        send_seq,
        lns_mode,
        recv_timeout_ms,
        ifname,
        using_ipsec,
    })
}

pub(crate) fn decode_tunnel_stats(attrs: &[L2tpAttribute]) -> crate::Result<TunnelStats> {
    let nested = attrs
        .iter()
        .find_map(|attr| match attr {
            L2tpAttribute::Stats(v) => Some(v.as_slice()),
            _ => None,
        })
        .ok_or_else(|| missing_attr_error("missing L2TP_ATTR_STATS"))?;

    let mut stats = TunnelStats::default();
    for attr in nested {
        match attr {
            L2tpStatsAttr::TxPackets(v) => stats.tx_packets = *v,
            L2tpStatsAttr::TxBytes(v) => stats.tx_bytes = *v,
            L2tpStatsAttr::TxErrors(v) => stats.tx_errors = *v,
            L2tpStatsAttr::RxPackets(v) => stats.rx_packets = *v,
            L2tpStatsAttr::RxBytes(v) => stats.rx_bytes = *v,
            L2tpStatsAttr::RxErrors(v) => stats.rx_errors = *v,
            _ => {}
        }
    }
    Ok(stats)
}

pub(crate) fn decode_session_stats(attrs: &[L2tpAttribute]) -> crate::Result<SessionStats> {
    let nested = attrs
        .iter()
        .find_map(|attr| match attr {
            L2tpAttribute::Stats(v) => Some(v.as_slice()),
            _ => None,
        })
        .ok_or_else(|| missing_attr_error("missing L2TP_ATTR_STATS"))?;

    let mut stats = SessionStats::default();
    for attr in nested {
        match attr {
            L2tpStatsAttr::TxPackets(v) => stats.tx_packets = *v,
            L2tpStatsAttr::TxBytes(v) => stats.tx_bytes = *v,
            L2tpStatsAttr::TxErrors(v) => stats.tx_errors = *v,
            L2tpStatsAttr::RxPackets(v) => stats.rx_packets = *v,
            L2tpStatsAttr::RxBytes(v) => stats.rx_bytes = *v,
            L2tpStatsAttr::RxErrors(v) => stats.rx_errors = *v,
            L2tpStatsAttr::RxSeqDiscards(v) => stats.rx_seq_discards = *v,
            L2tpStatsAttr::RxOosPackets(v) => stats.rx_oos_packets = *v,
            L2tpStatsAttr::RxCookieDiscards(v) => stats.rx_cookie_discards = *v,
            L2tpStatsAttr::RxInvalid(v) => stats.rx_invalid = *v,
            _ => {}
        }
    }
    Ok(stats)
}

fn required<T>(value: Option<T>, name: &str) -> crate::Result<T> {
    value.ok_or_else(|| missing_attr_error(&format!("missing mandatory attribute {name}")))
}

fn missing_attr_error(message: &str) -> crate::Error {
    crate::Error::KernelError {
        code: libc::EINVAL,
        message: message.to_string(),
    }
}

fn to_l2tp_pw(value: PseudowireType) -> L2tpPwType {
    match value {
        PseudowireType::Eth => L2tpPwType::Eth,
        PseudowireType::EthVlan => L2tpPwType::EthVlan,
        PseudowireType::Ppp => L2tpPwType::Ppp,
        PseudowireType::PppAc => L2tpPwType::PppAc,
        PseudowireType::Ip => L2tpPwType::Ip,
        PseudowireType::None => L2tpPwType::None,
    }
}

fn from_l2tp_pw(value: L2tpPwType) -> crate::Result<PseudowireType> {
    match value {
        L2tpPwType::Eth => Ok(PseudowireType::Eth),
        L2tpPwType::EthVlan => Ok(PseudowireType::EthVlan),
        L2tpPwType::Ppp => Ok(PseudowireType::Ppp),
        L2tpPwType::PppAc => Ok(PseudowireType::PppAc),
        L2tpPwType::Ip => Ok(PseudowireType::Ip),
        L2tpPwType::None => Ok(PseudowireType::None),
        L2tpPwType::Other(v) => Err(crate::Error::KernelError {
            code: libc::EINVAL,
            message: format!("unsupported pseudowire type {v}"),
        }),
        _ => Err(crate::Error::KernelError {
            code: libc::EINVAL,
            message: "unsupported pseudowire type".to_string(),
        }),
    }
}

fn to_l2tp_l2spec(value: L2SpecType) -> L2tpL2SpecType {
    match value {
        L2SpecType::None => L2tpL2SpecType::None,
        L2SpecType::Default => L2tpL2SpecType::Default,
    }
}

fn from_l2tp_l2spec(value: L2tpL2SpecType) -> crate::Result<L2SpecType> {
    match value {
        L2tpL2SpecType::None => Ok(L2SpecType::None),
        L2tpL2SpecType::Default => Ok(L2SpecType::Default),
        L2tpL2SpecType::Other(v) => Err(crate::Error::KernelError {
            code: libc::EINVAL,
            message: format!("unsupported l2spec type {v}"),
        }),
        _ => Err(crate::Error::KernelError {
            code: libc::EINVAL,
            message: "unsupported l2spec type".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn has_attr(attrs: &[L2tpAttribute], f: impl Fn(&L2tpAttribute) -> bool) -> bool {
        attrs.iter().any(f)
    }

    #[test]
    fn encode_tunnel_create_udp_v4_includes_required_attributes() {
        let cfg = TunnelConfig::new(
            TunnelId(10),
            TunnelId(20),
            Encapsulation::Udp {
                local: UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1111)),
                remote: UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2222)),
                udp_csum: true,
                udp_zero_csum6_tx: true,
                udp_zero_csum6_rx: true,
            },
            Some(IfName::new("l2tp0").unwrap()),
        )
        .unwrap();

        let msg = encode_tunnel_create(&cfg, Some(7));
        assert!(matches!(
            msg.cmd,
            netlink_packet_l2tp::L2tpCmd::TunnelCreate
        ));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::ConnId(10)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::PeerConnId(20)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::ProtoVersion(3)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::EncapType(L2tpEncapType::Udp)
        )));
        assert!(has_attr(
            &msg.attributes,
            |a| matches!(a, L2tpAttribute::IpSaddr(ip) if *ip == Ipv4Addr::new(10, 0, 0, 1))
        ));
        assert!(has_attr(
            &msg.attributes,
            |a| matches!(a, L2tpAttribute::IpDaddr(ip) if *ip == Ipv4Addr::new(10, 0, 0, 2))
        ));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::UdpSport(1111)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::UdpDport(2222)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::UdpCsum(true)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::UdpZeroCsum6Tx
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::UdpZeroCsum6Rx
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::Fd(7)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::IfName(name) if name == "l2tp0"
        )));
    }

    #[test]
    fn encode_tunnel_create_ip_v6_includes_ip_fields() {
        let cfg = TunnelConfig::new(
            TunnelId(30),
            TunnelId(40),
            Encapsulation::Ip {
                local: IpEndpoint::V6(Ipv6Addr::LOCALHOST),
                remote: IpEndpoint::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)),
            },
            None,
        )
        .unwrap();

        let msg = encode_tunnel_create(&cfg, None);
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::EncapType(L2tpEncapType::Ip)
        )));
        assert!(has_attr(
            &msg.attributes,
            |a| matches!(a, L2tpAttribute::Ip6Saddr(ip) if *ip == Ipv6Addr::LOCALHOST)
        ));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::Ip6Daddr(_)
        )));
        assert!(!has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::Fd(_)
        )));
    }

    #[test]
    fn encode_tunnel_modify_only_emits_optional_fields() {
        let msg = encode_tunnel_modify(
            TunnelId(42),
            &TunnelModify {
                udp_csum: Some(false),
            },
        );
        assert_eq!(msg.attributes.len(), 2);
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::ConnId(42)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::UdpCsum(false)
        )));
    }

    #[test]
    fn encode_session_create_includes_cookies_and_flags() {
        let cfg = SessionConfig {
            tunnel_id: TunnelId(1),
            session_id: SessionId(2),
            peer_session_id: SessionId(3),
            pseudowire_type: PseudowireType::Eth,
            l2spec_type: L2SpecType::Default,
            cookie: crate::Cookie::try_from_bytes(vec![1, 2, 3, 4]).unwrap(),
            peer_cookie: crate::Cookie::none(),
            recv_seq: true,
            send_seq: true,
            lns_mode: true,
            recv_timeout_ms: Some(999),
            ifname: Some(IfName::new("l2tpeth0").unwrap()),
        };

        let msg = encode_session_create(&cfg);
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::ConnId(1)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::SessionId(2)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::PeerSessionId(3)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::PwType(L2tpPwType::Eth)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::L2SpecType(L2tpL2SpecType::Default)
        )));
        assert!(has_attr(
            &msg.attributes,
            |a| matches!(a, L2tpAttribute::Cookie(v) if v.as_slice() == [1, 2, 3, 4])
        ));
        assert!(has_attr(
            &msg.attributes,
            |a| matches!(a, L2tpAttribute::PeerCookie(v) if v.is_empty())
        ));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::RecvSeq(true)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::SendSeq(true)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::LnsMode(true)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::RecvTimeout(999)
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::IfName(name) if name == "l2tpeth0"
        )));
    }

    #[test]
    fn encode_session_get_dump_handles_optional_tunnel_id() {
        let with = encode_session_get_dump(Some(TunnelId(77)));
        assert_eq!(with.attributes.len(), 1);
        assert!(matches!(with.attributes[0], L2tpAttribute::ConnId(77)));

        let without = encode_session_get_dump(None);
        assert!(without.attributes.is_empty());
    }

    #[test]
    fn decode_tunnel_info_udp_v6_round_trip() {
        let attrs = vec![
            L2tpAttribute::ConnId(100),
            L2tpAttribute::PeerConnId(200),
            L2tpAttribute::ProtoVersion(3),
            L2tpAttribute::EncapType(L2tpEncapType::Udp),
            L2tpAttribute::Ip6Saddr(Ipv6Addr::LOCALHOST),
            L2tpAttribute::Ip6Daddr(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            L2tpAttribute::UdpSport(5555),
            L2tpAttribute::UdpDport(6666),
            L2tpAttribute::UdpCsum(true),
            L2tpAttribute::UdpZeroCsum6Tx,
            L2tpAttribute::UsingIpsec(true),
            L2tpAttribute::IfName("l2tpv6".into()),
        ];

        let info = decode_tunnel_info(&attrs).unwrap();
        assert_eq!(info.tunnel_id, TunnelId(100));
        assert_eq!(info.peer_tunnel_id, TunnelId(200));
        assert_eq!(info.proto_version, 3);
        assert!(info.using_ipsec);
        assert_eq!(info.ifname.unwrap().as_str(), "l2tpv6");

        match info.encapsulation {
            Encapsulation::Udp {
                local,
                remote,
                udp_csum,
                udp_zero_csum6_tx,
                udp_zero_csum6_rx,
            } => {
                assert!(udp_csum);
                assert!(udp_zero_csum6_tx);
                assert!(!udp_zero_csum6_rx);
                assert!(matches!(local, UdpEndpoint::V6(SocketAddrV6 { .. })));
                assert!(matches!(remote, UdpEndpoint::V6(SocketAddrV6 { .. })));
            }
            _ => panic!("unexpected encapsulation"),
        }
    }

    #[test]
    fn decode_tunnel_info_missing_mandatory_attribute_fails() {
        let attrs = vec![
            L2tpAttribute::PeerConnId(2),
            L2tpAttribute::ProtoVersion(3),
            L2tpAttribute::EncapType(L2tpEncapType::Ip),
            L2tpAttribute::IpSaddr(Ipv4Addr::LOCALHOST),
            L2tpAttribute::IpDaddr(Ipv4Addr::LOCALHOST),
        ];
        let err = decode_tunnel_info(&attrs).unwrap_err();
        assert!(matches!(err, crate::Error::KernelError { .. }));
    }

    #[test]
    fn decode_session_info_round_trip() {
        let attrs = vec![
            L2tpAttribute::ConnId(7),
            L2tpAttribute::SessionId(8),
            L2tpAttribute::PeerSessionId(9),
            L2tpAttribute::PwType(L2tpPwType::Ppp),
            L2tpAttribute::L2SpecType(L2tpL2SpecType::None),
            L2tpAttribute::RecvSeq(true),
            L2tpAttribute::SendSeq(false),
            L2tpAttribute::LnsMode(true),
            L2tpAttribute::RecvTimeout(3000),
            L2tpAttribute::IfName("sess0".into()),
            L2tpAttribute::UsingIpsec(true),
        ];

        let info = decode_session_info(&attrs).unwrap();
        assert_eq!(info.tunnel_id, TunnelId(7));
        assert_eq!(info.session_id, SessionId(8));
        assert_eq!(info.peer_session_id, SessionId(9));
        assert_eq!(info.pseudowire_type, PseudowireType::Ppp);
        assert_eq!(info.l2spec_type, L2SpecType::None);
        assert!(info.recv_seq);
        assert!(!info.send_seq);
        assert!(info.lns_mode);
        assert_eq!(info.recv_timeout_ms, Some(3000));
        assert_eq!(info.ifname.unwrap().as_str(), "sess0");
        assert!(info.using_ipsec);
    }

    #[test]
    fn decode_session_info_missing_l2spec_defaults_to_none() {
        let attrs = vec![
            L2tpAttribute::ConnId(7),
            L2tpAttribute::SessionId(8),
            L2tpAttribute::PeerSessionId(9),
            L2tpAttribute::PwType(L2tpPwType::Eth),
        ];

        let info = decode_session_info(&attrs).unwrap();
        assert_eq!(info.tunnel_id, TunnelId(7));
        assert_eq!(info.session_id, SessionId(8));
        assert_eq!(info.peer_session_id, SessionId(9));
        assert_eq!(info.pseudowire_type, PseudowireType::Eth);
        assert_eq!(info.l2spec_type, L2SpecType::None);
    }

    #[test]
    fn decode_session_info_rejects_unknown_pw_or_l2spec() {
        let attrs_unknown_pw = vec![
            L2tpAttribute::ConnId(1),
            L2tpAttribute::SessionId(2),
            L2tpAttribute::PeerSessionId(3),
            L2tpAttribute::PwType(L2tpPwType::Other(777)),
            L2tpAttribute::L2SpecType(L2tpL2SpecType::None),
        ];
        let err = decode_session_info(&attrs_unknown_pw).unwrap_err();
        assert!(matches!(err, crate::Error::KernelError { .. }));

        let attrs_unknown_l2spec = vec![
            L2tpAttribute::ConnId(1),
            L2tpAttribute::SessionId(2),
            L2tpAttribute::PeerSessionId(3),
            L2tpAttribute::PwType(L2tpPwType::Eth),
            L2tpAttribute::L2SpecType(L2tpL2SpecType::Other(9)),
        ];
        let err = decode_session_info(&attrs_unknown_l2spec).unwrap_err();
        assert!(matches!(err, crate::Error::KernelError { .. }));
    }

    #[test]
    fn decode_tunnel_stats_extracts_fields() {
        let attrs = vec![L2tpAttribute::Stats(vec![
            L2tpStatsAttr::TxPackets(11),
            L2tpStatsAttr::TxBytes(12),
            L2tpStatsAttr::TxErrors(13),
            L2tpStatsAttr::RxPackets(21),
            L2tpStatsAttr::RxBytes(22),
            L2tpStatsAttr::RxErrors(23),
        ])];

        let stats = decode_tunnel_stats(&attrs).unwrap();
        assert_eq!(stats.tx_packets, 11);
        assert_eq!(stats.tx_bytes, 12);
        assert_eq!(stats.tx_errors, 13);
        assert_eq!(stats.rx_packets, 21);
        assert_eq!(stats.rx_bytes, 22);
        assert_eq!(stats.rx_errors, 23);
    }

    #[test]
    fn decode_session_stats_extracts_fields() {
        let attrs = vec![L2tpAttribute::Stats(vec![
            L2tpStatsAttr::TxPackets(1),
            L2tpStatsAttr::TxBytes(2),
            L2tpStatsAttr::TxErrors(3),
            L2tpStatsAttr::RxPackets(4),
            L2tpStatsAttr::RxBytes(5),
            L2tpStatsAttr::RxErrors(6),
            L2tpStatsAttr::RxSeqDiscards(7),
            L2tpStatsAttr::RxOosPackets(8),
            L2tpStatsAttr::RxCookieDiscards(9),
            L2tpStatsAttr::RxInvalid(10),
        ])];

        let stats = decode_session_stats(&attrs).unwrap();
        assert_eq!(stats.tx_packets, 1);
        assert_eq!(stats.tx_bytes, 2);
        assert_eq!(stats.tx_errors, 3);
        assert_eq!(stats.rx_packets, 4);
        assert_eq!(stats.rx_bytes, 5);
        assert_eq!(stats.rx_errors, 6);
        assert_eq!(stats.rx_seq_discards, 7);
        assert_eq!(stats.rx_oos_packets, 8);
        assert_eq!(stats.rx_cookie_discards, 9);
        assert_eq!(stats.rx_invalid, 10);
    }
}

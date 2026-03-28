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
        l2spec_type: required(l2spec_type, "L2TP_ATTR_L2SPEC_TYPE")?,
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

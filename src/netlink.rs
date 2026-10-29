// SPDX-License-Identifier: MIT

use std::os::fd::RawFd;

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, NLA_TYPE_MASK, NlasIterator,
    Parseable, ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_l2tp::{
    L2tpAttribute, L2tpCmd, L2tpEncapType, L2tpMessage, L2tpPwType,
    L2tpStatsAttribute,
};

use crate::{
    Encapsulation, IpEndpoint, KernelCookie, L2SpecType, L2tpIfName,
    L2tpVersion, PseudowireType, SessionConfig, SessionId, SessionInfo,
    SessionModify, SessionStats, TunnelConfig, TunnelId, TunnelInfo,
    TunnelStats, UdpEndpoint,
};

/// How a session is addressed in `SESSION_GET`, `SESSION_DELETE` and
/// `SESSION_MODIFY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionRef {
    /// By tunnel and session identifier.
    Ids(TunnelId, SessionId),
    /// By the interface name of an Ethernet pseudowire.
    IfName(L2tpIfName),
}

impl SessionRef {
    fn attributes(self) -> Vec<L2tpAttribute> {
        match self {
            Self::Ids(tunnel_id, session_id) => vec![
                L2tpAttribute::ConnId(tunnel_id.0),
                L2tpAttribute::SessionId(session_id.0),
            ],
            Self::IfName(name) => vec![L2tpAttribute::IfName(name)],
        }
    }
}

// Only fixed-size attributes or checked variable-length attributes are passed
// here.
fn message(cmd: L2tpCmd, attributes: Vec<L2tpAttribute>) -> L2tpMessage {
    L2tpMessage { cmd, attributes }
}

const L2TP_ATTR_COOKIE: u16 = 15;
const L2TP_ATTR_PEER_COOKIE: u16 = 16;

/// An L2TP generic-netlink message decoded with the kernel's cookie limits.
///
/// Use with [`netlink_packet_generic::GenlMessage`] when receiving replies or
/// notifications on your own socket, without a handle or runtime. Both cookie
/// attributes accept any length from 0 through 8; other attributes retain
/// the validation of [`L2tpMessage`]. Convert reported bytes to
/// [`KernelCookie`].
///
/// Emission delegates to `netlink-packet-l2tp` unchanged. Its emitter
/// **panics** for non-RFC cookie lengths; decoding a message does not make it
/// suitable for emission. Use [`Cookie`](crate::Cookie) to validate cookies for
/// creation.
#[derive(Debug, Clone)]
pub struct KernelMessage(
    /// The decoded message, including the original cookie bytes.
    pub L2tpMessage,
);

impl GenlFamily for KernelMessage {
    fn family_name() -> &'static str {
        L2tpMessage::family_name()
    }

    fn version(&self) -> u8 {
        self.0.version()
    }

    fn command(&self) -> u8 {
        self.0.command()
    }
}

impl Emitable for KernelMessage {
    fn buffer_len(&self) -> usize {
        self.0.buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.0.emit(buffer)
    }
}

impl ParseableParametrized<[u8], GenlHeader> for KernelMessage {
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        let mut attributes = Vec::new();
        for nla in NlasIterator::new(buf) {
            let nla = nla.context("failed to parse l2tp netlink attributes")?;
            let value = nla.value();
            let attribute = match nla.kind() & NLA_TYPE_MASK {
                L2TP_ATTR_COOKIE if value.len() <= 8 => {
                    L2tpAttribute::Cookie(value.to_vec())
                }
                L2TP_ATTR_PEER_COOKIE if value.len() <= 8 => {
                    L2tpAttribute::PeerCookie(value.to_vec())
                }
                _ => L2tpAttribute::parse(&nla)?,
            };
            attributes.push(attribute);
        }
        Ok(Self(message(header.cmd.into(), attributes)))
    }
}

pub(crate) fn encode_tunnel_create(
    config: &TunnelConfig,
    fd: Option<RawFd>,
) -> crate::Result<L2tpMessage> {
    if config.version == L2tpVersion::V2 {
        // The kernel accepts V2/IP tunnels, but IP receive only looks up V3
        // sessions, so such a tunnel cannot receive session data.
        if matches!(&config.encapsulation, Encapsulation::Ip { .. }) {
            return Err(crate::Error::V2IpEncapsulation);
        }
        // L2TPv2 identifiers are 16-bit on the wire.
        for id in [config.tunnel_id, config.peer_tunnel_id] {
            if u16::try_from(id.0).is_err() {
                return Err(crate::Error::V2IdTooLarge(id.0));
            }
        }
    }
    let mut attrs = vec![
        L2tpAttribute::ConnId(config.tunnel_id.0),
        L2tpAttribute::PeerConnId(config.peer_tunnel_id.0),
        L2tpAttribute::ProtoVersion(config.version.number()),
    ];

    // Kernel-created sockets get no interface scope, so they can neither bind
    // nor connect a link-local address.
    let link_local = match &config.encapsulation {
        Encapsulation::Udp { local, remote, .. } => {
            local.is_link_local() || remote.is_link_local()
        }
        Encapsulation::Ip { local, remote } => {
            local.is_link_local() || remote.is_link_local()
        }
    };
    if fd.is_none() && link_local {
        return Err(crate::Error::UnmanagedLinkLocal);
    }

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
                    // udp_sock_create6 only applies the IPv6 checksum
                    // options. Mapped peers use the IPv4 transmit path, whose
                    // SO_NO_CHECK setting requires a userspace-owned socket.
                    if fd.is_none()
                        && !udp_csum
                        && remote.ip().to_ipv4_mapped().is_some()
                    {
                        return Err(crate::Error::UnmanagedUdpChecksum);
                    }
                    attrs.push(L2tpAttribute::Ip6Saddr(*local.ip()));
                    attrs.push(L2tpAttribute::Ip6Daddr(*remote.ip()));
                    attrs.push(L2tpAttribute::UdpSport(local.port()));
                    attrs.push(L2tpAttribute::UdpDport(remote.port()));
                }
                _ => return Err(crate::Error::AddressFamilyMismatch),
            }
            // On creation the kernel checks presence, even when the byte is
            // zero.
            if *udp_csum {
                attrs.push(L2tpAttribute::UdpCsum(1));
            }
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
                (
                    IpEndpoint::V6 { addr: local, .. },
                    IpEndpoint::V6 { addr: remote, .. },
                ) => {
                    attrs.push(L2tpAttribute::Ip6Saddr(*local));
                    attrs.push(L2tpAttribute::Ip6Daddr(*remote));
                }
                _ => return Err(crate::Error::AddressFamilyMismatch),
            }
        }
    }

    if let Some(fd) = fd {
        attrs.push(L2tpAttribute::Fd(fd));
    }
    Ok(message(L2tpCmd::TunnelCreate, attrs))
}

pub(crate) fn encode_tunnel_delete(id: TunnelId) -> L2tpMessage {
    message(L2tpCmd::TunnelDelete, vec![L2tpAttribute::ConnId(id.0)])
}

pub(crate) fn encode_tunnel_get(id: TunnelId) -> L2tpMessage {
    message(L2tpCmd::TunnelGet, vec![L2tpAttribute::ConnId(id.0)])
}

pub(crate) fn encode_tunnel_get_dump() -> L2tpMessage {
    message(L2tpCmd::TunnelGet, Vec::new())
}

pub(crate) fn encode_session_create(
    config: &SessionConfig,
) -> crate::Result<L2tpMessage> {
    let mut attrs = vec![
        L2tpAttribute::ConnId(config.tunnel_id.0),
        L2tpAttribute::SessionId(config.session_id.0),
        L2tpAttribute::PeerSessionId(config.peer_session_id.0),
        L2tpAttribute::PwType(to_l2tp_pw(config.pseudowire_type)),
        L2tpAttribute::L2SpecType(to_l2tp_l2spec(config.l2spec_type)),
        L2tpAttribute::cookie(config.cookie.as_bytes().to_vec())?,
        L2tpAttribute::peer_cookie(config.peer_cookie.as_bytes().to_vec())?,
    ];

    if config.recv_seq {
        attrs.push(L2tpAttribute::RecvSeq(1));
    }
    if config.send_seq {
        attrs.push(L2tpAttribute::SendSeq(1));
    }
    if config.lns_mode {
        attrs.push(L2tpAttribute::LnsMode(1));
    }
    if let Some(timeout) = config.recv_timeout_ms {
        attrs.push(L2tpAttribute::RecvTimeout(timeout));
    }
    if let Some(ifname) = config.ifname {
        attrs.push(L2tpAttribute::IfName(ifname));
    }

    Ok(message(L2tpCmd::SessionCreate, attrs))
}

pub(crate) fn encode_session_delete(session: SessionRef) -> L2tpMessage {
    message(L2tpCmd::SessionDelete, session.attributes())
}

pub(crate) fn encode_session_modify(
    session: SessionRef,
    params: &SessionModify,
) -> L2tpMessage {
    let mut attrs = session.attributes();

    if let Some(v) = params.recv_seq {
        attrs.push(L2tpAttribute::RecvSeq(u8::from(v)));
    }
    if let Some(v) = params.send_seq {
        attrs.push(L2tpAttribute::SendSeq(u8::from(v)));
    }
    if let Some(v) = params.lns_mode {
        attrs.push(L2tpAttribute::LnsMode(u8::from(v)));
    }
    if let Some(v) = params.recv_timeout_ms {
        attrs.push(L2tpAttribute::RecvTimeout(v));
    }

    message(L2tpCmd::SessionModify, attrs)
}

pub(crate) fn encode_session_get(session: SessionRef) -> L2tpMessage {
    message(L2tpCmd::SessionGet, session.attributes())
}

pub(crate) fn encode_session_get_dump() -> L2tpMessage {
    message(L2tpCmd::SessionGet, Vec::new())
}

pub(crate) fn decode_tunnel_info(
    attrs: &[L2tpAttribute],
) -> crate::Result<TunnelInfo> {
    let mut tunnel_id = None;
    let mut peer_tunnel_id = None;
    let mut proto_version = None;
    let mut encap_type = None;
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
            L2tpAttribute::UsingIpsec(v) => using_ipsec = *v != 0,
            L2tpAttribute::IpSaddr(v) => ip_saddr_v4 = Some(*v),
            L2tpAttribute::IpDaddr(v) => ip_daddr_v4 = Some(*v),
            L2tpAttribute::Ip6Saddr(v) => ip_saddr_v6 = Some(*v),
            L2tpAttribute::Ip6Daddr(v) => ip_daddr_v6 = Some(*v),
            L2tpAttribute::UdpSport(v) => udp_sport = Some(*v),
            L2tpAttribute::UdpDport(v) => udp_dport = Some(*v),
            L2tpAttribute::UdpCsum(v) => udp_csum = *v != 0,
            L2tpAttribute::UdpZeroCsum6Tx => udp_zero_csum6_tx = true,
            L2tpAttribute::UdpZeroCsum6Rx => udp_zero_csum6_rx = true,
            _ => {}
        }
    }

    let tunnel_id = required(tunnel_id, "L2TP_ATTR_CONN_ID")?;
    let peer_tunnel_id = required(peer_tunnel_id, "L2TP_ATTR_PEER_CONN_ID")?;
    let proto_version = required(proto_version, "L2TP_ATTR_PROTO_VERSION")?;
    let version = L2tpVersion::try_from(proto_version).map_err(|_| {
        crate::Error::UnexpectedReply(format!(
            "unsupported protocol version {proto_version}"
        ))
    })?;
    let encap_type = required(encap_type, "L2TP_ATTR_ENCAP_TYPE")?;

    let encapsulation = match encap_type {
        L2tpEncapType::Udp => {
            if let (Some(local), Some(remote), Some(sport), Some(dport)) =
                (ip_saddr_v4, ip_daddr_v4, udp_sport, udp_dport)
            {
                Encapsulation::Udp {
                    local: UdpEndpoint::V4(std::net::SocketAddrV4::new(
                        local, sport,
                    )),
                    remote: UdpEndpoint::V4(std::net::SocketAddrV4::new(
                        remote, dport,
                    )),
                    udp_csum,
                    udp_zero_csum6_tx,
                    udp_zero_csum6_rx,
                }
            } else if let (
                Some(local),
                Some(remote),
                Some(sport),
                Some(dport),
            ) = (ip_saddr_v6, ip_daddr_v6, udp_sport, udp_dport)
            {
                Encapsulation::Udp {
                    local: UdpEndpoint::V6(std::net::SocketAddrV6::new(
                        local, sport, 0, 0,
                    )),
                    remote: UdpEndpoint::V6(std::net::SocketAddrV6::new(
                        remote, dport, 0, 0,
                    )),
                    udp_csum,
                    udp_zero_csum6_tx,
                    udp_zero_csum6_rx,
                }
            } else {
                return Err(missing_attr_error(
                    "missing or mixed-family UDP address/port attributes for \
                     tunnel",
                ));
            }
        }
        L2tpEncapType::Ip => {
            if let (Some(local), Some(remote)) = (ip_saddr_v4, ip_daddr_v4) {
                Encapsulation::Ip {
                    local: IpEndpoint::V4(local),
                    remote: IpEndpoint::V4(remote),
                }
            } else if let (Some(local), Some(remote)) =
                (ip_saddr_v6, ip_daddr_v6)
            {
                // The kernel does not report interface scopes.
                Encapsulation::Ip {
                    local: IpEndpoint::v6(local),
                    remote: IpEndpoint::v6(remote),
                }
            } else {
                return Err(missing_attr_error(
                    "missing IP address attributes for IP-encapsulated tunnel",
                ));
            }
        }
        other => {
            return Err(crate::Error::UnexpectedReply(format!(
                "unsupported encapsulation type {other:?}"
            )));
        }
    };

    Ok(TunnelInfo {
        tunnel_id,
        peer_tunnel_id,
        version,
        encapsulation,
        using_ipsec,
    })
}

pub(crate) fn decode_session_info(
    attrs: &[L2tpAttribute],
) -> crate::Result<SessionInfo> {
    let mut tunnel_id = None;
    let mut peer_tunnel_id = None;
    let mut session_id = None;
    let mut peer_session_id = None;
    let mut pseudowire_type = None;
    let mut l2spec_type = None;
    let mut cookie = KernelCookie::none();
    let mut peer_cookie = KernelCookie::none();
    let mut recv_seq = false;
    let mut send_seq = false;
    let mut lns_mode = false;
    let mut recv_timeout_ms = None;
    let mut ifname = None;
    let mut using_ipsec = false;

    for attr in attrs {
        match attr {
            L2tpAttribute::ConnId(v) => tunnel_id = Some(TunnelId(*v)),
            L2tpAttribute::PeerConnId(v) => peer_tunnel_id = Some(TunnelId(*v)),
            L2tpAttribute::SessionId(v) => session_id = Some(SessionId(*v)),
            L2tpAttribute::PeerSessionId(v) => {
                peer_session_id = Some(SessionId(*v))
            }
            L2tpAttribute::PwType(v) => {
                pseudowire_type = Some(from_l2tp_pw(*v))
            }
            L2tpAttribute::L2SpecType(v) => {
                l2spec_type = Some(from_l2tp_l2spec(*v))
            }
            // A session created elsewhere may carry any length up to 8.
            L2tpAttribute::Cookie(v) => {
                cookie = KernelCookie::try_from(v.as_slice())?
            }
            L2tpAttribute::PeerCookie(v) => {
                peer_cookie = KernelCookie::try_from(v.as_slice())?
            }
            L2tpAttribute::RecvSeq(v) => recv_seq = *v != 0,
            L2tpAttribute::SendSeq(v) => send_seq = *v != 0,
            L2tpAttribute::LnsMode(v) => lns_mode = *v != 0,
            L2tpAttribute::RecvTimeout(v) => recv_timeout_ms = Some(*v),
            L2tpAttribute::IfName(v) => ifname = Some(*v),
            L2tpAttribute::UsingIpsec(v) => using_ipsec = *v != 0,
            _ => {}
        }
    }

    Ok(SessionInfo {
        tunnel_id: required(tunnel_id, "L2TP_ATTR_CONN_ID")?,
        peer_tunnel_id: required(peer_tunnel_id, "L2TP_ATTR_PEER_CONN_ID")?,
        session_id: required(session_id, "L2TP_ATTR_SESSION_ID")?,
        peer_session_id: required(
            peer_session_id,
            "L2TP_ATTR_PEER_SESSION_ID",
        )?,
        pseudowire_type: required(pseudowire_type, "L2TP_ATTR_PW_TYPE")?,
        l2spec_type,
        cookie,
        peer_cookie,
        recv_seq,
        send_seq,
        lns_mode,
        recv_timeout_ms,
        ifname,
        using_ipsec,
    })
}

pub(crate) fn decode_tunnel_stats(
    attrs: &[L2tpAttribute],
) -> crate::Result<TunnelStats> {
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
            L2tpStatsAttribute::TxPackets(v) => stats.tx_packets = *v,
            L2tpStatsAttribute::TxBytes(v) => stats.tx_bytes = *v,
            L2tpStatsAttribute::TxErrors(v) => stats.tx_errors = *v,
            L2tpStatsAttribute::RxPackets(v) => stats.rx_packets = *v,
            L2tpStatsAttribute::RxBytes(v) => stats.rx_bytes = *v,
            L2tpStatsAttribute::RxErrors(v) => stats.rx_errors = *v,
            _ => {}
        }
    }
    Ok(stats)
}

pub(crate) fn decode_session_stats(
    attrs: &[L2tpAttribute],
) -> crate::Result<SessionStats> {
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
            L2tpStatsAttribute::TxPackets(v) => stats.tx_packets = *v,
            L2tpStatsAttribute::TxBytes(v) => stats.tx_bytes = *v,
            L2tpStatsAttribute::TxErrors(v) => stats.tx_errors = *v,
            L2tpStatsAttribute::RxPackets(v) => stats.rx_packets = *v,
            L2tpStatsAttribute::RxBytes(v) => stats.rx_bytes = *v,
            L2tpStatsAttribute::RxErrors(v) => stats.rx_errors = *v,
            L2tpStatsAttribute::RxSeqDiscards(v) => stats.rx_seq_discards = *v,
            L2tpStatsAttribute::RxOosPackets(v) => stats.rx_oos_packets = *v,
            L2tpStatsAttribute::RxCookieDiscards(v) => {
                stats.rx_cookie_discards = *v
            }
            L2tpStatsAttribute::RxInvalid(v) => stats.rx_invalid = *v,
            _ => {}
        }
    }
    Ok(stats)
}

fn required<T>(value: Option<T>, name: &str) -> crate::Result<T> {
    value.ok_or_else(|| {
        missing_attr_error(&format!("missing mandatory attribute {name}"))
    })
}

fn missing_attr_error(message: &str) -> crate::Error {
    crate::Error::UnexpectedReply(message.to_string())
}

fn to_l2tp_pw(value: PseudowireType) -> L2tpPwType {
    match value {
        PseudowireType::Eth => L2tpPwType::Eth,
        PseudowireType::EthVlan => L2tpPwType::EthVlan,
        PseudowireType::Ppp => L2tpPwType::Ppp,
        PseudowireType::PppAc => L2tpPwType::PppAc,
        PseudowireType::Ip => L2tpPwType::Ip,
        PseudowireType::None => L2tpPwType::None,
        PseudowireType::Other(v) => L2tpPwType::from(v),
    }
}

fn from_l2tp_pw(value: L2tpPwType) -> PseudowireType {
    match value {
        L2tpPwType::Eth => PseudowireType::Eth,
        L2tpPwType::EthVlan => PseudowireType::EthVlan,
        L2tpPwType::Ppp => PseudowireType::Ppp,
        L2tpPwType::PppAc => PseudowireType::PppAc,
        L2tpPwType::Ip => PseudowireType::Ip,
        L2tpPwType::None => PseudowireType::None,
        other => PseudowireType::Other(u16::from(other)),
    }
}

fn to_l2tp_l2spec(value: L2SpecType) -> u8 {
    match value {
        L2SpecType::None => 0,
        L2SpecType::Default => 1,
        L2SpecType::Other(v) => v,
    }
}

fn from_l2tp_l2spec(value: u8) -> L2SpecType {
    match value {
        0 => L2SpecType::None,
        1 => L2SpecType::Default,
        v => L2SpecType::Other(v),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use super::*;
    use crate::Cookie;

    fn has_attr(
        attrs: &[L2tpAttribute],
        f: impl Fn(&L2tpAttribute) -> bool,
    ) -> bool {
        attrs.iter().any(f)
    }

    fn assert_wire_round_trip(message: L2tpMessage) {
        use netlink_packet_core::{Emitable, ParseableParametrized};
        use netlink_packet_generic::GenlHeader;

        let mut bytes = vec![0; message.buffer_len()];
        message.emit(&mut bytes);
        let parsed = L2tpMessage::parse_with_param(
            &bytes,
            GenlHeader {
                cmd: message.cmd.into(),
                version: 1,
            },
        )
        .unwrap();
        assert_eq!(parsed, message);
    }

    fn udp_v4_config(udp_csum: bool) -> TunnelConfig {
        TunnelConfig::new(
            TunnelId(1),
            TunnelId(2),
            Encapsulation::Udp {
                local: UdpEndpoint::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    1000,
                )),
                remote: UdpEndpoint::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    1001,
                )),
                udp_csum,
                udp_zero_csum6_tx: false,
                udp_zero_csum6_rx: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn session_create_checked_attributes_serialize_at_valid_boundaries() {
        for len in [0, 4, 8] {
            for l2spec_type in [L2SpecType::None, L2SpecType::Default] {
                let mut cfg =
                    SessionConfig::eth(TunnelId(1), SessionId(2), SessionId(3));
                cfg.cookie = Cookie::try_from(vec![0xff; len]).unwrap();
                cfg.peer_cookie = cfg.cookie;
                // The limit is bytes, including for UTF-8 names.
                cfg.ifname = Some(L2tpIfName::new("éééééééa").unwrap());
                cfg.l2spec_type = l2spec_type;
                cfg.recv_seq = true;
                cfg.send_seq = true;
                cfg.lns_mode = true;
                cfg.recv_timeout_ms = Some(u64::MAX);
                assert_wire_round_trip(encode_session_create(&cfg).unwrap());
            }
        }
    }

    #[test]
    fn non_utf8_ifnames_round_trip_through_the_attribute_layer() {
        let mut cfg =
            SessionConfig::eth(TunnelId(1), SessionId(2), SessionId(3));
        let raw = L2tpIfName::new(b"eth\xff0").unwrap();
        cfg.ifname = Some(raw);
        let message = encode_session_create(&cfg).unwrap();
        assert!(has_attr(&message.attributes, |a| matches!(
            a,
            L2tpAttribute::IfName(name) if *name == raw
        )));
        assert_wire_round_trip(message);
        let info = decode_session_info(&[
            L2tpAttribute::ConnId(1),
            L2tpAttribute::PeerConnId(2),
            L2tpAttribute::SessionId(3),
            L2tpAttribute::PeerSessionId(4),
            L2tpAttribute::PwType(L2tpPwType::Eth),
            L2tpAttribute::IfName(raw),
        ])
        .unwrap();
        assert_eq!(info.ifname, Some(raw));
    }

    #[test]
    fn request_commands_and_optional_updates_serialize() {
        let ids = SessionRef::Ids(TunnelId(1), SessionId(2));
        let name = SessionRef::IfName(L2tpIfName::new("l2tpeth0").unwrap());
        for message in [
            encode_tunnel_delete(TunnelId(1)),
            encode_tunnel_get(TunnelId(1)),
            encode_tunnel_get_dump(),
            encode_session_delete(ids),
            encode_session_delete(name),
            encode_session_get(ids),
            encode_session_get(name),
            encode_session_get_dump(),
            encode_session_modify(
                ids,
                &SessionModify {
                    recv_seq: Some(false),
                    send_seq: Some(true),
                    lns_mode: Some(false),
                    recv_timeout_ms: Some(1234),
                },
            ),
            encode_session_modify(
                name,
                &SessionModify {
                    lns_mode: Some(true),
                    ..Default::default()
                },
            ),
        ] {
            assert_wire_round_trip(message);
        }
        let by_name = encode_session_get(name);
        assert!(has_attr(&by_name.attributes, |a| matches!(
            a,
            L2tpAttribute::IfName(n) if n.as_bytes() == b"l2tpeth0"
        )));
        assert!(!has_attr(&by_name.attributes, |a| matches!(
            a,
            L2tpAttribute::ConnId(_)
        )));
    }

    #[test]
    fn tunnel_create_carries_the_protocol_version() {
        for version in [L2tpVersion::V2, L2tpVersion::V3] {
            let cfg = udp_v4_config(true).with_version(version);
            for fd in [None, Some(7)] {
                let message = encode_tunnel_create(&cfg, fd).unwrap();
                assert!(
                    message.attributes.contains(&L2tpAttribute::ProtoVersion(
                        version.number()
                    ))
                );
                assert_wire_round_trip(message);
            }
        }
    }

    #[test]
    fn ip_tunnel_create_requires_v3() {
        for endpoint in [
            IpEndpoint::V4(Ipv4Addr::LOCALHOST),
            IpEndpoint::v6(Ipv6Addr::LOCALHOST),
        ] {
            let cfg = TunnelConfig::new(
                TunnelId(1),
                TunnelId(2),
                Encapsulation::Ip {
                    local: endpoint.clone(),
                    remote: endpoint,
                },
            )
            .unwrap();
            let v2 = cfg.clone().with_version(L2tpVersion::V2);
            for fd in [None, Some(7)] {
                assert!(matches!(
                    encode_tunnel_create(&v2, fd),
                    Err(crate::Error::V2IpEncapsulation)
                ));
                let message = encode_tunnel_create(&cfg, fd).unwrap();
                assert!(
                    message
                        .attributes
                        .contains(&L2tpAttribute::EncapType(L2tpEncapType::Ip))
                );
                assert_wire_round_trip(message);
            }
        }
    }

    #[test]
    fn v2_tunnel_create_rejects_oversized_local_and_peer_ids() {
        for (tunnel_id, peer_tunnel_id) in [(0x1_0000, 2), (1, 0x1_0000)] {
            let mut cfg = udp_v4_config(true).with_version(L2tpVersion::V2);
            cfg.tunnel_id = TunnelId(tunnel_id);
            cfg.peer_tunnel_id = TunnelId(peer_tunnel_id);
            for fd in [None, Some(7)] {
                assert!(matches!(
                    encode_tunnel_create(&cfg, fd),
                    Err(crate::Error::V2IdTooLarge(0x1_0000))
                ));
            }
        }
    }

    #[test]
    fn tunnel_create_preserves_maximum_ids_for_each_version() {
        for (version, id) in [
            (L2tpVersion::V2, u32::from(u16::MAX)),
            (L2tpVersion::V3, u32::MAX),
        ] {
            let mut cfg = udp_v4_config(true).with_version(version);
            cfg.tunnel_id = TunnelId(id);
            cfg.peer_tunnel_id = TunnelId(id);
            for fd in [None, Some(7)] {
                let message = encode_tunnel_create(&cfg, fd).unwrap();
                assert!(
                    message.attributes.contains(&L2tpAttribute::ConnId(id))
                );
                assert!(
                    message.attributes.contains(&L2tpAttribute::PeerConnId(id))
                );
                assert_wire_round_trip(message);
            }
        }
    }

    #[test]
    fn tunnel_create_omits_disabled_udp_checksum_attribute() {
        let message =
            encode_tunnel_create(&udp_v4_config(false), None).unwrap();
        assert!(!has_attr(&message.attributes, |a| matches!(
            a,
            L2tpAttribute::UdpCsum(_)
        )));
        assert_wire_round_trip(message);
    }

    #[test]
    fn mapped_udp_checksum_requires_managed_socket_when_disabled() {
        let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        for local in [Ipv6Addr::UNSPECIFIED, mapped] {
            for (remote, udp_csum, fd, rejected) in [
                (mapped, false, None, true),
                (mapped, true, None, false),
                (mapped, false, Some(7), false),
                (mapped, true, Some(7), false),
                (Ipv6Addr::LOCALHOST, false, None, false),
            ] {
                // IPv6 checksum flags must not bypass the IPv4 check.
                for udp_zero_csum6_tx in [false, true] {
                    let cfg = TunnelConfig::new(
                        TunnelId(1),
                        TunnelId(2),
                        Encapsulation::Udp {
                            local: UdpEndpoint::V6(SocketAddrV6::new(
                                local, 1000, 0, 0,
                            )),
                            remote: UdpEndpoint::V6(SocketAddrV6::new(
                                remote, 1001, 0, 0,
                            )),
                            udp_csum,
                            udp_zero_csum6_tx,
                            udp_zero_csum6_rx: false,
                        },
                    )
                    .unwrap();
                    let result = encode_tunnel_create(&cfg, fd);
                    if rejected {
                        assert!(matches!(
                            result,
                            Err(crate::Error::UnmanagedUdpChecksum)
                        ));
                    } else {
                        assert_wire_round_trip(result.unwrap());
                    }
                }
            }
        }
    }

    #[test]
    fn unmanaged_tunnels_reject_link_local_endpoints() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let eth0 = L2tpIfName::new("eth0").unwrap();
        let configs = [
            Encapsulation::Ip {
                local: IpEndpoint::v6_scoped(link_local, eth0),
                remote: IpEndpoint::v6(Ipv6Addr::LOCALHOST),
            },
            Encapsulation::Ip {
                local: IpEndpoint::v6(Ipv6Addr::UNSPECIFIED),
                remote: IpEndpoint::v6_scoped(link_local, eth0),
            },
            Encapsulation::Udp {
                local: UdpEndpoint::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    1701,
                    0,
                    0,
                )),
                remote: UdpEndpoint::V6(SocketAddrV6::new(
                    link_local, 1701, 0, 2,
                )),
                udp_csum: true,
                udp_zero_csum6_tx: false,
                udp_zero_csum6_rx: false,
            },
        ];
        for encapsulation in configs {
            let cfg =
                TunnelConfig::new(TunnelId(1), TunnelId(2), encapsulation)
                    .unwrap();
            assert!(matches!(
                encode_tunnel_create(&cfg, None),
                Err(crate::Error::UnmanagedLinkLocal)
            ));
            // A managed socket carries its own scope.
            let message = encode_tunnel_create(&cfg, Some(7)).unwrap();
            assert!(has_attr(&message.attributes, |a| matches!(
                a,
                L2tpAttribute::Fd(7)
            )));
            assert_wire_round_trip(message);
        }
    }

    #[test]
    fn session_info_treats_nonzero_flag_bytes_as_true() {
        let info = decode_session_info(&[
            L2tpAttribute::ConnId(1),
            L2tpAttribute::PeerConnId(2),
            L2tpAttribute::SessionId(2),
            L2tpAttribute::PeerSessionId(3),
            L2tpAttribute::PwType(L2tpPwType::Eth),
            L2tpAttribute::RecvSeq(2),
            L2tpAttribute::SendSeq(255),
            L2tpAttribute::LnsMode(128),
            L2tpAttribute::UsingIpsec(42),
        ])
        .unwrap();
        assert!(
            info.recv_seq && info.send_seq && info.lns_mode && info.using_ipsec
        );
    }

    #[test]
    fn encode_tunnel_create_udp_v4_includes_required_attributes() {
        let cfg = TunnelConfig::new(
            TunnelId(10),
            TunnelId(20),
            Encapsulation::Udp {
                local: UdpEndpoint::V4(SocketAddrV4::new(
                    Ipv4Addr::new(10, 0, 0, 1),
                    1111,
                )),
                remote: UdpEndpoint::V4(SocketAddrV4::new(
                    Ipv4Addr::new(10, 0, 0, 2),
                    2222,
                )),
                udp_csum: true,
                udp_zero_csum6_tx: true,
                udp_zero_csum6_rx: true,
            },
        )
        .unwrap();

        let msg = encode_tunnel_create(&cfg, Some(7)).unwrap();
        assert_wire_round_trip(msg.clone());
        assert!(matches!(msg.cmd, L2tpCmd::TunnelCreate));
        for expected in [
            L2tpAttribute::ConnId(10),
            L2tpAttribute::PeerConnId(20),
            L2tpAttribute::ProtoVersion(3),
            L2tpAttribute::EncapType(L2tpEncapType::Udp),
            L2tpAttribute::IpSaddr(Ipv4Addr::new(10, 0, 0, 1)),
            L2tpAttribute::IpDaddr(Ipv4Addr::new(10, 0, 0, 2)),
            L2tpAttribute::UdpSport(1111),
            L2tpAttribute::UdpDport(2222),
            L2tpAttribute::UdpCsum(1),
            L2tpAttribute::UdpZeroCsum6Tx,
            L2tpAttribute::UdpZeroCsum6Rx,
            L2tpAttribute::Fd(7),
        ] {
            assert!(msg.attributes.contains(&expected), "{expected:?}");
        }
        assert!(!has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::IfName(_)
        )));
    }

    #[test]
    fn encode_tunnel_create_ip_v6_includes_ip_fields() {
        let cfg = TunnelConfig::new(
            TunnelId(30),
            TunnelId(40),
            Encapsulation::Ip {
                local: IpEndpoint::v6(Ipv6Addr::LOCALHOST),
                remote: IpEndpoint::v6(Ipv6Addr::new(
                    0x2001, 0xdb8, 1, 2, 3, 4, 5, 6,
                )),
            },
        )
        .unwrap();

        let msg = encode_tunnel_create(&cfg, None).unwrap();
        assert_wire_round_trip(msg.clone());
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
    fn encode_tunnel_create_rejects_family_mismatches() {
        let udp = TunnelConfig {
            tunnel_id: TunnelId(1),
            peer_tunnel_id: TunnelId(2),
            encapsulation: Encapsulation::Udp {
                local: UdpEndpoint::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    1000,
                )),
                remote: UdpEndpoint::V6(SocketAddrV6::new(
                    Ipv6Addr::LOCALHOST,
                    1001,
                    0,
                    0,
                )),
                udp_csum: false,
                udp_zero_csum6_tx: false,
                udp_zero_csum6_rx: false,
            },
            version: L2tpVersion::V3,
        };
        assert!(matches!(
            encode_tunnel_create(&udp, None),
            Err(crate::Error::AddressFamilyMismatch)
        ));

        let ip = TunnelConfig {
            tunnel_id: TunnelId(11),
            peer_tunnel_id: TunnelId(12),
            encapsulation: Encapsulation::Ip {
                local: IpEndpoint::V4(Ipv4Addr::LOCALHOST),
                remote: IpEndpoint::v6(Ipv6Addr::LOCALHOST),
            },
            version: L2tpVersion::V3,
        };
        assert!(matches!(
            encode_tunnel_create(&ip, None),
            Err(crate::Error::AddressFamilyMismatch)
        ));
    }

    #[test]
    fn encode_session_create_includes_cookies_and_flags() {
        let cfg = SessionConfig {
            tunnel_id: TunnelId(1),
            session_id: SessionId(2),
            peer_session_id: SessionId(3),
            pseudowire_type: PseudowireType::Eth,
            l2spec_type: L2SpecType::Default,
            cookie: Cookie::from([1, 2, 3, 4]),
            peer_cookie: Cookie::none(),
            recv_seq: true,
            send_seq: true,
            lns_mode: true,
            recv_timeout_ms: Some(999),
            ifname: Some(L2tpIfName::new("l2tpeth0").unwrap()),
        };

        let msg = encode_session_create(&cfg).unwrap();
        for expected in [
            L2tpAttribute::ConnId(1),
            L2tpAttribute::SessionId(2),
            L2tpAttribute::PeerSessionId(3),
            L2tpAttribute::PwType(L2tpPwType::Eth),
            L2tpAttribute::L2SpecType(1),
            L2tpAttribute::Cookie(vec![1, 2, 3, 4]),
            L2tpAttribute::PeerCookie(vec![]),
            L2tpAttribute::RecvSeq(1),
            L2tpAttribute::SendSeq(1),
            L2tpAttribute::LnsMode(1),
            L2tpAttribute::RecvTimeout(999),
            L2tpAttribute::IfName(L2tpIfName::new("l2tpeth0").unwrap()),
        ] {
            assert!(msg.attributes.contains(&expected), "{expected:?}");
        }
    }

    #[test]
    fn encode_session_get_dump_has_no_filter() {
        assert!(encode_session_get_dump().attributes.is_empty());
    }

    #[test]
    fn decode_tunnel_info_udp_v6_round_trip() {
        let attrs = vec![
            L2tpAttribute::ConnId(100),
            L2tpAttribute::PeerConnId(200),
            L2tpAttribute::ProtoVersion(3),
            L2tpAttribute::EncapType(L2tpEncapType::Udp),
            L2tpAttribute::Ip6Saddr(Ipv6Addr::LOCALHOST),
            L2tpAttribute::Ip6Daddr(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
            )),
            L2tpAttribute::UdpSport(5555),
            L2tpAttribute::UdpDport(6666),
            L2tpAttribute::UdpCsum(1),
            L2tpAttribute::UdpZeroCsum6Tx,
            L2tpAttribute::UsingIpsec(1),
            L2tpAttribute::IfName(L2tpIfName::new("ignored").unwrap()),
        ];

        let info = decode_tunnel_info(&attrs).unwrap();
        assert_eq!(info.tunnel_id, TunnelId(100));
        assert_eq!(info.peer_tunnel_id, TunnelId(200));
        assert_eq!(info.version, L2tpVersion::V3);
        assert!(info.using_ipsec);

        let ip_attrs = vec![
            L2tpAttribute::ConnId(1),
            L2tpAttribute::PeerConnId(2),
            L2tpAttribute::ProtoVersion(2),
            L2tpAttribute::EncapType(L2tpEncapType::Ip),
            L2tpAttribute::Ip6Saddr(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            L2tpAttribute::Ip6Daddr(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)),
        ];
        let ip_info = decode_tunnel_info(&ip_attrs).unwrap();
        assert_eq!(ip_info.version, L2tpVersion::V2);
        let Encapsulation::Ip { local, remote } = ip_info.encapsulation else {
            panic!("expected IP encapsulation");
        };
        // Scopes are not reported by the kernel.
        assert!(local.is_link_local() && local.scope().is_none());
        assert!(remote.is_link_local() && remote.scope().is_none());

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
    fn decode_tunnel_info_rejects_missing_or_unknown_values() {
        let attrs = vec![
            L2tpAttribute::PeerConnId(2),
            L2tpAttribute::ProtoVersion(3),
            L2tpAttribute::EncapType(L2tpEncapType::Ip),
            L2tpAttribute::IpSaddr(Ipv4Addr::LOCALHOST),
            L2tpAttribute::IpDaddr(Ipv4Addr::LOCALHOST),
        ];
        let err = decode_tunnel_info(&attrs).unwrap_err();
        assert!(matches!(err, crate::Error::UnexpectedReply(_)));

        let attrs = vec![
            L2tpAttribute::ConnId(1),
            L2tpAttribute::PeerConnId(2),
            L2tpAttribute::ProtoVersion(9),
            L2tpAttribute::EncapType(L2tpEncapType::Ip),
            L2tpAttribute::IpSaddr(Ipv4Addr::LOCALHOST),
            L2tpAttribute::IpDaddr(Ipv4Addr::LOCALHOST),
        ];
        let err = decode_tunnel_info(&attrs).unwrap_err();
        assert!(matches!(err, crate::Error::UnexpectedReply(_)));
    }

    #[test]
    fn decode_session_info_round_trip() {
        let attrs = vec![
            L2tpAttribute::ConnId(7),
            L2tpAttribute::PeerConnId(70),
            L2tpAttribute::SessionId(8),
            L2tpAttribute::PeerSessionId(9),
            L2tpAttribute::PwType(L2tpPwType::Ppp),
            L2tpAttribute::L2SpecType(0),
            L2tpAttribute::Cookie(vec![1, 2, 3, 4]),
            L2tpAttribute::PeerCookie(vec![5, 6, 7, 8, 9, 10, 11, 12]),
            L2tpAttribute::RecvSeq(1),
            L2tpAttribute::SendSeq(0),
            L2tpAttribute::LnsMode(1),
            L2tpAttribute::RecvTimeout(3000),
            L2tpAttribute::IfName(L2tpIfName::new("sess0").unwrap()),
            L2tpAttribute::UsingIpsec(1),
        ];

        let info = decode_session_info(&attrs).unwrap();
        assert_eq!(info.tunnel_id, TunnelId(7));
        assert_eq!(info.peer_tunnel_id, TunnelId(70));
        assert_eq!(info.session_id, SessionId(8));
        assert_eq!(info.peer_session_id, SessionId(9));
        assert_eq!(info.pseudowire_type, PseudowireType::Ppp);
        assert_eq!(info.l2spec_type, Some(L2SpecType::None));
        assert_eq!(info.cookie, KernelCookie::from([1, 2, 3, 4]));
        assert_eq!(
            info.peer_cookie,
            KernelCookie::from([5, 6, 7, 8, 9, 10, 11, 12])
        );
        assert!(info.recv_seq);
        assert!(!info.send_seq);
        assert!(info.lns_mode);
        assert_eq!(info.recv_timeout_ms, Some(3000));
        assert_eq!(info.ifname.unwrap().to_str().unwrap(), "sess0");
        assert!(info.using_ipsec);
    }

    #[test]
    fn decode_session_info_accepts_any_cookie_length_the_kernel_holds() {
        for len in [1, 2, 7] {
            let bytes: Vec<u8> = (1..=len).collect();
            let attrs = vec![
                L2tpAttribute::ConnId(7),
                L2tpAttribute::PeerConnId(70),
                L2tpAttribute::SessionId(8),
                L2tpAttribute::PeerSessionId(9),
                L2tpAttribute::PwType(L2tpPwType::Eth),
                L2tpAttribute::Cookie(bytes.clone()),
                L2tpAttribute::PeerCookie(bytes.clone()),
            ];
            let info = decode_session_info(&attrs).unwrap();
            assert_eq!(info.cookie.as_bytes(), bytes.as_slice());
            assert_eq!(info.peer_cookie.as_bytes(), bytes.as_slice());
            assert!(!info.cookie.is_rfc3931());

            // Reported cookies must be validated before session creation.
            for cookie in [info.cookie, info.peer_cookie] {
                assert!(matches!(
                    Cookie::try_from(cookie),
                    Err(crate::Error::InvalidCookieLength(n)) if n == bytes.len()
                ));
            }
        }
    }

    #[test]
    fn kernel_replies_keep_cookies_upstream_parsing_refuses() {
        use netlink_packet_core::{NLA_HEADER_SIZE, emit_u16};

        // Emitting checks cookie lengths, so these are written by hand.
        fn nla(kind: u16, value: &[u8]) -> Vec<u8> {
            let mut raw = vec![0; NLA_HEADER_SIZE];
            emit_u16(&mut raw[..2], (NLA_HEADER_SIZE + value.len()) as u16)
                .unwrap();
            emit_u16(&mut raw[2..], kind).unwrap();
            raw.extend_from_slice(value);
            raw.resize(raw.len().next_multiple_of(4), 0);
            raw
        }
        let session_id = [L2tpAttribute::SessionId(8)];
        let mut session_id_nla = vec![0; session_id.as_slice().buffer_len()];
        session_id.as_slice().emit(&mut session_id_nla);
        let header = GenlHeader { cmd: 8, version: 1 };

        for len in [1, 2, 7] {
            let cookie: Vec<u8> = (1..=len).collect();
            let buf = [
                nla(L2TP_ATTR_COOKIE, &cookie),
                session_id_nla.clone(),
                nla(L2TP_ATTR_PEER_COOKIE, &cookie),
            ]
            .concat();
            assert!(L2tpMessage::parse_with_param(&buf, header).is_err());
            let parsed = KernelMessage::parse_with_param(&buf, header).unwrap();
            assert_eq!(parsed.0.cmd, L2tpCmd::SessionGet);
            assert_eq!(
                parsed.0.attributes,
                [
                    L2tpAttribute::Cookie(cookie.clone()),
                    L2tpAttribute::SessionId(8),
                    L2tpAttribute::PeerCookie(cookie.clone()),
                ]
            );
        }
        // Beyond the kernel's own limit the upstream error stands.
        let buf = nla(L2TP_ATTR_COOKIE, &[0; 9]);
        assert!(KernelMessage::parse_with_param(&buf, header).is_err());
    }

    #[test]
    fn decode_session_info_defaults_optional_attributes() {
        let attrs = vec![
            L2tpAttribute::ConnId(7),
            L2tpAttribute::PeerConnId(70),
            L2tpAttribute::SessionId(8),
            L2tpAttribute::PeerSessionId(9),
            L2tpAttribute::PwType(L2tpPwType::Eth),
        ];

        let info = decode_session_info(&attrs).unwrap();
        // The kernel never reports the sublayer type; it stays unknown.
        assert_eq!(info.l2spec_type, None);
        assert!(info.cookie.is_empty());
        assert!(info.peer_cookie.is_empty());
        assert_eq!(info.ifname, None);

        // The peer tunnel identifier is always reported by the kernel.
        let err = decode_session_info(&attrs[1..]).unwrap_err();
        assert!(matches!(err, crate::Error::UnexpectedReply(_)));
    }

    #[test]
    fn decode_session_info_keeps_unknown_pw_and_l2spec() {
        let attrs = vec![
            L2tpAttribute::ConnId(1),
            L2tpAttribute::PeerConnId(2),
            L2tpAttribute::SessionId(2),
            L2tpAttribute::PeerSessionId(3),
            L2tpAttribute::PwType(L2tpPwType::Other(777)),
            L2tpAttribute::L2SpecType(9),
        ];
        let info = decode_session_info(&attrs).unwrap();
        assert_eq!(info.pseudowire_type, PseudowireType::Other(777));
        assert_eq!(info.l2spec_type, Some(L2SpecType::Other(9)));
    }

    #[test]
    fn unknown_pw_and_l2spec_round_trip_to_raw_values() {
        let mut cfg =
            SessionConfig::eth(TunnelId(1), SessionId(2), SessionId(3));
        cfg.pseudowire_type = PseudowireType::Other(777);
        cfg.l2spec_type = L2SpecType::Other(9);
        let msg = encode_session_create(&cfg).unwrap();
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::PwType(L2tpPwType::Other(777))
        )));
        assert!(has_attr(&msg.attributes, |a| matches!(
            a,
            L2tpAttribute::L2SpecType(9)
        )));
    }

    #[test]
    fn decode_tunnel_stats_extracts_fields() {
        let attrs = vec![L2tpAttribute::Stats(vec![
            L2tpStatsAttribute::TxPackets(11),
            L2tpStatsAttribute::TxBytes(12),
            L2tpStatsAttribute::TxErrors(13),
            L2tpStatsAttribute::RxPackets(21),
            L2tpStatsAttribute::RxBytes(22),
            L2tpStatsAttribute::RxErrors(23),
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
            L2tpStatsAttribute::TxPackets(1),
            L2tpStatsAttribute::TxBytes(2),
            L2tpStatsAttribute::TxErrors(3),
            L2tpStatsAttribute::RxPackets(4),
            L2tpStatsAttribute::RxBytes(5),
            L2tpStatsAttribute::RxErrors(6),
            L2tpStatsAttribute::RxSeqDiscards(7),
            L2tpStatsAttribute::RxOosPackets(8),
            L2tpStatsAttribute::RxCookieDiscards(9),
            L2tpStatsAttribute::RxInvalid(10),
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

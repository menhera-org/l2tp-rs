use std::fmt;

/// Kernel tunnel identifier (`L2TP_ATTR_CONN_ID`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelId(
    /// Raw numeric tunnel identifier.
    pub u32,
);

/// Kernel session identifier (`L2TP_ATTR_SESSION_ID`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(
    /// Raw numeric session identifier.
    pub u32,
);

/// Session cookie bytes.
///
/// Valid lengths are `0`, `4`, or `8`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie(Vec<u8>);

impl Cookie {
    /// Returns an empty cookie.
    pub fn none() -> Self {
        Self(Vec::new())
    }

    /// Creates a cookie from bytes after validating its length.
    pub fn try_from_bytes(b: Vec<u8>) -> crate::Result<Self> {
        match b.len() {
            0 | 4 | 8 => Ok(Self(b)),
            n => Err(crate::Error::InvalidCookieLength(n)),
        }
    }

    /// Returns the raw cookie bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Linux interface name (`IFNAMSIZ - 1` max bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfName(String);

impl IfName {
    /// Validates and constructs an interface name.
    ///
    /// The name must be non-empty, must not contain NUL or `/`, and must be
    /// at most `IFNAMSIZ - 1` bytes.
    pub fn new(s: impl Into<String>) -> crate::Result<Self> {
        let s = s.into();
        let b = s.as_bytes();

        if b.is_empty() {
            return Err(crate::Error::InvalidIfName(s));
        }
        if b.len() > (libc::IFNAMSIZ - 1) {
            return Err(crate::Error::InvalidIfName(s));
        }
        if b.contains(&0) {
            return Err(crate::Error::InvalidIfName(s));
        }
        if b.contains(&b'/') {
            return Err(crate::Error::InvalidIfName(s));
        }

        Ok(Self(s))
    }

    /// Returns the interface name as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// UDP socket endpoint used for UDP encapsulated tunnels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpEndpoint {
    /// IPv4 endpoint.
    V4(std::net::SocketAddrV4),
    /// IPv6 endpoint.
    V6(std::net::SocketAddrV6),
}

impl UdpEndpoint {
    /// Returns `4` for IPv4 endpoints and `6` for IPv6 endpoints.
    pub fn ip_version(&self) -> u8 {
        match self {
            Self::V4(_) => 4,
            Self::V6(_) => 6,
        }
    }
}

/// IP endpoint used for IP encapsulated (`L2TPIP`) tunnels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpEndpoint {
    /// IPv4 endpoint.
    V4(std::net::Ipv4Addr),
    /// IPv6 endpoint.
    V6(std::net::Ipv6Addr),
}

impl IpEndpoint {
    /// Returns `4` for IPv4 endpoints and `6` for IPv6 endpoints.
    pub fn ip_version(&self) -> u8 {
        match self {
            Self::V4(_) => 4,
            Self::V6(_) => 6,
        }
    }
}

/// Tunnel encapsulation parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encapsulation {
    /// UDP-encapsulated L2TPv3 tunnel.
    Udp {
        /// Local UDP address.
        local: UdpEndpoint,
        /// Remote UDP address.
        remote: UdpEndpoint,
        /// Whether UDP checksum is enabled.
        udp_csum: bool,
        /// Whether zero-checksum transmit is enabled for IPv6.
        udp_zero_csum6_tx: bool,
        /// Whether zero-checksum receive is enabled for IPv6.
        udp_zero_csum6_rx: bool,
    },
    /// IP-encapsulated L2TPv3 tunnel.
    Ip {
        /// Local IP address.
        local: IpEndpoint,
        /// Remote IP address.
        remote: IpEndpoint,
    },
}

/// Session pseudowire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudowireType {
    /// Ethernet pseudowire.
    Eth,
    /// Ethernet VLAN pseudowire.
    EthVlan,
    /// PPP pseudowire.
    Ppp,
    /// PPP Access Concentrator pseudowire.
    PppAc,
    /// IP pseudowire.
    Ip,
    /// No pseudowire payload type.
    None,
}

/// L2-specific sublayer header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum L2SpecType {
    /// No L2-specific sublayer header.
    #[default]
    None,
    /// Kernel default L2-specific sublayer header.
    Default,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn cookie_accepts_valid_lengths() {
        let c0 = Cookie::try_from_bytes(vec![]).unwrap();
        let c4 = Cookie::try_from_bytes(vec![1, 2, 3, 4]).unwrap();
        let c8 = Cookie::try_from_bytes(vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(c0.as_bytes(), &[]);
        assert_eq!(c4.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(c8.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn cookie_rejects_invalid_length() {
        let err = Cookie::try_from_bytes(vec![1, 2, 3]).unwrap_err();
        match err {
            crate::Error::InvalidCookieLength(3) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ifname_validates_constraints() {
        let ok = IfName::new("l2tp0").unwrap();
        assert_eq!(ok.as_str(), "l2tp0");
        assert_eq!(ok.to_string(), "l2tp0");

        assert!(matches!(
            IfName::new(""),
            Err(crate::Error::InvalidIfName(_))
        ));
        assert!(matches!(
            IfName::new("abc/def"),
            Err(crate::Error::InvalidIfName(_))
        ));
        assert!(matches!(
            IfName::new("ab\0cd"),
            Err(crate::Error::InvalidIfName(_))
        ));
        assert!(matches!(
            IfName::new("0123456789abcdef"),
            Err(crate::Error::InvalidIfName(_))
        ));
    }

    #[test]
    fn endpoint_ip_versions_are_reported() {
        let udp4 = UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1701));
        let udp6 = UdpEndpoint::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1701, 0, 0));
        let ip4 = IpEndpoint::V4(Ipv4Addr::LOCALHOST);
        let ip6 = IpEndpoint::V6(Ipv6Addr::LOCALHOST);

        assert_eq!(udp4.ip_version(), 4);
        assert_eq!(udp6.ip_version(), 6);
        assert_eq!(ip4.ip_version(), 4);
        assert_eq!(ip6.ip_version(), 6);
    }

    #[test]
    fn l2spec_default_is_none() {
        assert_eq!(L2SpecType::default(), L2SpecType::None);
    }
}

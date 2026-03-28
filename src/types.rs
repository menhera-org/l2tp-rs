use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie(Vec<u8>);

impl Cookie {
    pub fn none() -> Self {
        Self(Vec::new())
    }

    pub fn try_from_bytes(b: Vec<u8>) -> crate::Result<Self> {
        match b.len() {
            0 | 4 | 8 => Ok(Self(b)),
            n => Err(crate::Error::InvalidCookieLength(n)),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfName(String);

impl IfName {
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

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpEndpoint {
    V4(std::net::SocketAddrV4),
    V6(std::net::SocketAddrV6),
}

impl UdpEndpoint {
    pub fn ip_version(&self) -> u8 {
        match self {
            Self::V4(_) => 4,
            Self::V6(_) => 6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpEndpoint {
    V4(std::net::Ipv4Addr),
    V6(std::net::Ipv6Addr),
}

impl IpEndpoint {
    pub fn ip_version(&self) -> u8 {
        match self {
            Self::V4(_) => 4,
            Self::V6(_) => 6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encapsulation {
    Udp {
        local: UdpEndpoint,
        remote: UdpEndpoint,
        udp_csum: bool,
        udp_zero_csum6_tx: bool,
        udp_zero_csum6_rx: bool,
    },
    Ip {
        local: IpEndpoint,
        remote: IpEndpoint,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudowireType {
    Eth,
    EthVlan,
    Ppp,
    PppAc,
    Ip,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum L2SpecType {
    #[default]
    None,
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

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

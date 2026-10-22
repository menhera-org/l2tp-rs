// SPDX-License-Identifier: MIT

use std::{
    ffi::{CStr, CString},
    fmt,
};

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
///
/// Validation follows the kernel's `dev_valid_name()`, so names accepted here
/// are not rejected later by the kernel for their spelling. The kernel allows
/// any bytes except NUL, `/`, `:` and whitespace, but this crate requires
/// UTF-8, because `netlink-packet-l2tp` carries interface names as `String`.
/// A session whose interface has a non-UTF-8 name cannot be created through
/// this crate, and a session listing that contains one fails to decode.
///
/// Construct a name with [`IfName::new`], [`str::parse`] or `TryFrom`, and
/// read it back with [`as_str`](Self::as_str), [`as_bytes`](Self::as_bytes),
/// `AsRef<str>`, `Display` or `From<IfName> for String`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IfName(String);

impl IfName {
    /// Validates and constructs an interface name.
    ///
    /// The name must be non-empty, at most `IFNAMSIZ - 1` bytes, not `.` or
    /// `..`, and must not contain NUL, `/`, `:`, or ASCII whitespace.
    pub fn new(s: impl Into<String>) -> crate::Result<Self> {
        let s = s.into();
        let b = s.as_bytes();

        if b.is_empty() {
            return Err(crate::Error::InvalidIfName(s));
        }
        if b.len() > (libc::IFNAMSIZ - 1) {
            return Err(crate::Error::InvalidIfName(s));
        }
        if s == "." || s == ".." {
            return Err(crate::Error::InvalidIfName(s));
        }
        // The kernel uses `isspace()`, which also matches vertical tab.
        if b.iter().any(|&c| {
            matches!(c, 0 | b'/' | b':' | 0x0b) || c.is_ascii_whitespace()
        }) {
            return Err(crate::Error::InvalidIfName(s));
        }

        Ok(Self(s))
    }

    /// Returns the interface name as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the interface name as bytes, without a NUL terminator.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Resolves the name to the interface's current index with
    /// `if_nametoindex(3)`.
    ///
    /// Interface indexes change when an interface is re-created, so resolve
    /// the name right before it is used. For example, build the scope ID of a
    /// link-local [`SocketAddrV6`](std::net::SocketAddrV6) just before
    /// creating or reconnecting a UDP tunnel socket. The error carries
    /// `ENODEV` when no interface has this name.
    pub fn index(&self) -> crate::Result<u32> {
        // The name never contains NUL, which `new` rejects.
        let name = CString::new(self.0.as_str())
            .map_err(|_| crate::Error::InvalidIfName(self.0.clone()))?;
        // SAFETY: `name` is a valid NUL-terminated string that outlives the
        // call.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(index)
    }

    /// Looks up the name of the interface with `index` using
    /// `if_indextoname(3)`.
    ///
    /// The error carries `ENXIO` when no interface has this index.
    pub fn from_index(index: u32) -> crate::Result<Self> {
        let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
        // SAFETY: `buf` provides the `IFNAMSIZ` bytes the function requires.
        let ptr = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
        if ptr.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: on success the buffer holds a NUL-terminated name.
        let name = unsafe { CStr::from_ptr(buf.as_ptr()) };
        let name = name.to_str().map_err(|_| {
            crate::Error::InvalidIfName(name.to_string_lossy().into_owned())
        })?;
        Self::new(name)
    }
}

impl fmt::Display for IfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for IfName {
    type Err = crate::Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        Self::new(s)
    }
}

impl TryFrom<&str> for IfName {
    type Error = crate::Error;

    fn try_from(s: &str) -> crate::Result<Self> {
        Self::new(s)
    }
}

impl TryFrom<String> for IfName {
    type Error = crate::Error;

    fn try_from(s: String) -> crate::Result<Self> {
        Self::new(s)
    }
}

impl TryFrom<&[u8]> for IfName {
    type Error = crate::Error;

    /// Validates raw name bytes, which must be UTF-8.
    fn try_from(bytes: &[u8]) -> crate::Result<Self> {
        let s = std::str::from_utf8(bytes).map_err(|_| {
            crate::Error::InvalidIfName(
                String::from_utf8_lossy(bytes).into_owned(),
            )
        })?;
        Self::new(s)
    }
}

impl AsRef<str> for IfName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<IfName> for String {
    fn from(name: IfName) -> Self {
        name.0
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

    /// Returns whether this is a link-local IPv6 address.
    ///
    /// Managed sockets scope such an address with the
    /// [`SocketAddrV6`](std::net::SocketAddrV6) scope ID; resolve it with
    /// [`IfName::index`] right before creating or reconnecting the socket.
    /// Unmanaged tunnels cannot use link-local addresses.
    pub fn is_link_local(&self) -> bool {
        match self {
            Self::V4(_) => false,
            Self::V6(addr) => addr.ip().is_unicast_link_local(),
        }
    }
}

/// IP endpoint used for IP encapsulated (`L2TPIP`) tunnels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpEndpoint {
    /// IPv4 endpoint.
    V4(std::net::Ipv4Addr),
    /// IPv6 endpoint.
    V6 {
        /// IPv6 address.
        addr: std::net::Ipv6Addr,
        /// Interface that scopes a link-local `addr`.
        ///
        /// The kernel refuses to bind or connect a link-local address
        /// without an interface. The name is resolved to the interface index
        /// each time a [`TunnelSocket`](crate::TunnelSocket) binds, connects
        /// or reconnects, so it stays valid after the interface has been
        /// re-created with a new index. The kernel ignores the scope of other
        /// addresses; use the `device` argument of
        /// [`TunnelSocket::ip`](crate::TunnelSocket::ip) to pin a socket to an
        /// interface. [`TunnelInfo`](crate::TunnelInfo) never carries a
        /// scope, because the kernel does not report it.
        scope: Option<IfName>,
    },
}

impl IpEndpoint {
    /// Creates an IPv6 endpoint without an interface scope.
    pub fn v6(addr: std::net::Ipv6Addr) -> Self {
        Self::V6 { addr, scope: None }
    }

    /// Creates an IPv6 endpoint scoped to an interface, as link-local
    /// addresses require.
    pub fn v6_scoped(addr: std::net::Ipv6Addr, scope: IfName) -> Self {
        Self::V6 {
            addr,
            scope: Some(scope),
        }
    }

    /// Returns `4` for IPv4 endpoints and `6` for IPv6 endpoints.
    pub fn ip_version(&self) -> u8 {
        match self {
            Self::V4(_) => 4,
            Self::V6 { .. } => 6,
        }
    }

    /// Returns the interface scope of an IPv6 endpoint.
    pub fn scope(&self) -> Option<&IfName> {
        match self {
            Self::V4(_) => None,
            Self::V6 { scope, .. } => scope.as_ref(),
        }
    }

    /// Returns whether this is a link-local IPv6 address, which needs an
    /// interface scope.
    pub fn is_link_local(&self) -> bool {
        match self {
            Self::V4(_) => false,
            Self::V6 { addr, .. } => addr.is_unicast_link_local(),
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
        /// Whether UDP checksums are sent for IPv4 traffic.
        ///
        /// For managed sockets this also covers IPv4 peers reached through
        /// IPv4-mapped addresses on an IPv6 socket. Unmanaged tunnels with
        /// an IPv4-mapped peer reject `false` with
        /// [`Error::UnmanagedUdpChecksum`](crate::Error::UnmanagedUdpChecksum);
        /// use IPv4 endpoints or a managed socket to disable those checksums.
        /// IPv6 UDP always carries checksums unless `udp_zero_csum6_tx` is
        /// set.
        ///
        /// The kernel reports this setting only for IPv4 sockets, so
        /// [`TunnelInfo`](crate::TunnelInfo) shows `false` for every IPv6
        /// tunnel, even one whose IPv4-mapped peer receives checksums.
        udp_csum: bool,
        /// Whether IPv6 packets are sent with a zero UDP checksum.
        udp_zero_csum6_tx: bool,
        /// Whether IPv6 packets with a zero UDP checksum are accepted.
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
#[non_exhaustive]
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
    /// Raw `L2TP_PWTYPE_*` value not covered by the other variants.
    Other(u16),
}

/// L2-specific sublayer header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum L2SpecType {
    /// No L2-specific sublayer header.
    #[default]
    None,
    /// Kernel default L2-specific sublayer header.
    Default,
    /// Raw `L2TP_L2SPECTYPE_*` value not covered by the other variants.
    Other(u8),
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use super::*;

    #[test]
    fn cookie_accepts_valid_lengths() {
        let c0 = Cookie::try_from_bytes(vec![]).unwrap();
        let c4 = Cookie::try_from_bytes(vec![1, 2, 3, 4]).unwrap();
        let c8 = Cookie::try_from_bytes(vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert!(c0.as_bytes().is_empty());
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
        for bad in [".", "..", "eth:0", "a b", "a\tb", "a\x0bb"] {
            assert!(
                matches!(IfName::new(bad), Err(crate::Error::InvalidIfName(_))),
                "{bad:?} should be rejected"
            );
        }
        assert!(IfName::new("a.b").is_ok());
    }

    #[test]
    fn ifname_conversions_validate() {
        let name: IfName = "eth0".parse().unwrap();
        assert_eq!(IfName::try_from("eth0").unwrap(), name);
        assert_eq!(IfName::try_from(String::from("eth0")).unwrap(), name);
        assert_eq!(IfName::try_from(&b"eth0"[..]).unwrap(), name);
        assert_eq!(name.as_ref(), "eth0");
        assert_eq!(name.as_bytes(), b"eth0");
        assert_eq!(String::from(name.clone()), "eth0");

        assert!(matches!(
            "eth:0".parse::<IfName>(),
            Err(crate::Error::InvalidIfName(_))
        ));
        assert!(matches!(
            IfName::try_from(String::from("")),
            Err(crate::Error::InvalidIfName(_))
        ));
        // Non-UTF-8 names are unsupported by the netlink attribute layer.
        assert!(matches!(
            IfName::try_from(&b"eth\xff0"[..]),
            Err(crate::Error::InvalidIfName(_))
        ));

        let mut names = [name.clone(), IfName::new("br0").unwrap()];
        names.sort();
        assert_eq!(names[0].as_str(), "br0");
        let set: std::collections::HashSet<IfName> = names.into();
        assert!(set.contains(&name));
    }

    #[test]
    fn endpoint_ip_versions_are_reported() {
        let udp4 =
            UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1701));
        let udp6 =
            UdpEndpoint::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1701, 0, 0));
        let ip4 = IpEndpoint::V4(Ipv4Addr::LOCALHOST);
        let ip6 = IpEndpoint::v6(Ipv6Addr::LOCALHOST);

        assert_eq!(udp4.ip_version(), 4);
        assert_eq!(udp6.ip_version(), 6);
        assert_eq!(ip4.ip_version(), 4);
        assert_eq!(ip6.ip_version(), 6);
    }

    #[test]
    fn link_local_endpoints_are_detected_and_scoped() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let eth0 = IfName::new("eth0").unwrap();

        let unscoped = IpEndpoint::v6(link_local);
        assert!(unscoped.is_link_local());
        assert_eq!(unscoped.scope(), None);

        let scoped = IpEndpoint::v6_scoped(link_local, eth0.clone());
        assert!(scoped.is_link_local());
        assert_eq!(scoped.scope(), Some(&eth0));
        assert_eq!(scoped.ip_version(), 6);

        assert!(!IpEndpoint::v6(Ipv6Addr::LOCALHOST).is_link_local());
        assert!(!IpEndpoint::V4(Ipv4Addr::new(169, 254, 1, 1)).is_link_local());
        assert_eq!(IpEndpoint::V4(Ipv4Addr::LOCALHOST).scope(), None);

        assert!(
            UdpEndpoint::V6(SocketAddrV6::new(link_local, 1701, 0, 0))
                .is_link_local()
        );
        assert!(
            !UdpEndpoint::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                1701,
                0,
                0
            ))
            .is_link_local()
        );
        assert!(
            !UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1701))
                .is_link_local()
        );
    }

    #[test]
    fn ifname_index_round_trips_through_the_kernel() {
        // Loopback always exists on Linux.
        let lo = IfName::new("lo").unwrap();
        let index = lo.index().unwrap();
        assert_ne!(index, 0);
        assert_eq!(IfName::from_index(index).unwrap(), lo);

        let missing = IfName::new("l2tp-no-such0").unwrap();
        let err = missing.index().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV));

        let err = IfName::from_index(u32::MAX).unwrap_err();
        assert!(matches!(err, crate::Error::Io(_)));
    }

    #[test]
    fn l2spec_default_is_none() {
        assert_eq!(L2SpecType::default(), L2SpecType::None);
    }
}

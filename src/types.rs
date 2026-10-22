// SPDX-License-Identifier: MIT

use std::{
    borrow::Cow,
    ffi::{CStr, OsStr, OsString},
    fmt,
    os::unix::ffi::{OsStrExt, OsStringExt},
};

/// Size of the kernel's interface name buffer (`IFNAMSIZ`), including the NUL
/// terminator.
pub const IFNAMSIZ: usize = libc::IFNAMSIZ;

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

/// Why bytes are not a valid Linux interface name.
///
/// Carried by [`Error::InvalidIfName`](crate::Error::InvalidIfName).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IfNameError {
    /// The name is empty.
    #[error("name is empty")]
    Empty,
    /// The name is longer than `IFNAMSIZ - 1` bytes.
    #[error("name is longer than {} bytes", IfName::MAX_LEN)]
    TooLong,
    /// The name is `.` or `..`.
    #[error("`.` and `..` are reserved")]
    Reserved,
    /// The name contains NUL, `/`, `:` or whitespace.
    #[error("name contains {:?}", char::from(*.0))]
    InvalidByte(u8),
}

/// Linux interface name: 1 to [`IfName::MAX_LEN`] bytes, stored NUL-padded
/// like the kernel's `char ifname[IFNAMSIZ]`.
///
/// Validation follows the kernel's `dev_valid_name()`, so names accepted here
/// are not rejected later by the kernel for their spelling. Names are byte
/// strings: the kernel allows any bytes except NUL, `/`, `:` and whitespace,
/// so a name is not necessarily UTF-8.
///
/// Construct a name with [`IfName::new`], [`str::parse`] or the `TryFrom`
/// conversions from `&str`, `String`, `&[u8]`, `Vec<u8>`, `&OsStr`, `&CStr`
/// and the kernel's `[u8; IFNAMSIZ]` buffer. Read it back with
/// [`as_bytes`](Self::as_bytes), [`as_array`](Self::as_array),
/// [`to_str`](Self::to_str), [`to_string_lossy`](Self::to_string_lossy),
/// [`as_os_str`](Self::as_os_str), [`as_c_str`](Self::as_c_str), `Display`
/// (lossy) or the `From<IfName>` conversions into `[u8; IFNAMSIZ]`,
/// `Vec<u8>` and `OsString`. A rejected name yields
/// [`Error::InvalidIfName`](crate::Error::InvalidIfName) with an
/// [`IfNameError`] that names the violated rule.
///
/// `netlink-packet-l2tp` 0.3 carries `L2TP_ATTR_IFNAME` as a `String`. Until
/// a release that carries the raw bytes is adopted, a session with a
/// non-UTF-8 interface name cannot be created
/// ([`Error::Netlink`](crate::Error::Netlink)) and a session listing that
/// contains one fails to decode.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IfName([u8; IFNAMSIZ]);

impl IfName {
    /// Maximum length of a name in bytes, `IFNAMSIZ - 1`.
    pub const MAX_LEN: usize = IFNAMSIZ - 1;

    /// Validates and constructs an interface name from bytes, `&str` or
    /// `String`.
    ///
    /// The name must be non-empty, at most [`MAX_LEN`](Self::MAX_LEN) bytes,
    /// not `.` or `..`, and must not contain NUL, `/`, `:`, or ASCII
    /// whitespace.
    pub fn new(name: impl AsRef<[u8]>) -> crate::Result<Self> {
        let b = name.as_ref();

        if b.is_empty() {
            return Err(IfNameError::Empty.into());
        }
        if b.len() > Self::MAX_LEN {
            return Err(IfNameError::TooLong.into());
        }
        if b == b"." || b == b".." {
            return Err(IfNameError::Reserved.into());
        }
        // The kernel uses `isspace()`, which also matches vertical tab.
        if let Some(&c) = b.iter().find(|&&c| {
            matches!(c, 0 | b'/' | b':' | 0x0b) || c.is_ascii_whitespace()
        }) {
            return Err(IfNameError::InvalidByte(c).into());
        }

        let mut array = [0; IFNAMSIZ];
        array[..b.len()].copy_from_slice(b);
        Ok(Self(array))
    }

    fn len(&self) -> usize {
        // `new` leaves at least one NUL of padding.
        self.0.iter().position(|&c| c == 0).unwrap_or(IFNAMSIZ)
    }

    /// Returns the name bytes, without padding or a NUL terminator.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..self.len()]
    }

    /// Returns the name as the kernel's NUL-padded `char ifname[IFNAMSIZ]`.
    pub fn as_array(&self) -> &[u8; IFNAMSIZ] {
        &self.0
    }

    /// Returns the name as `&str`, or `None` when it is not UTF-8.
    pub fn to_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()).ok()
    }

    /// Returns the name as a string, replacing non-UTF-8 bytes with U+FFFD.
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.as_bytes())
    }

    /// Returns the name as an `OsStr`.
    pub fn as_os_str(&self) -> &OsStr {
        OsStr::from_bytes(self.as_bytes())
    }

    /// Returns the name as a NUL-terminated C string, for C interfaces.
    pub fn as_c_str(&self) -> &CStr {
        // `new` rejects interior NUL and leaves at least one NUL of padding.
        CStr::from_bytes_until_nul(&self.0)
            .expect("interface names are NUL-terminated by construction")
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
        // SAFETY: `as_c_str` is NUL-terminated and outlives the call.
        let index = unsafe { libc::if_nametoindex(self.as_c_str().as_ptr()) };
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
        let mut buf = [0 as libc::c_char; IFNAMSIZ];
        // SAFETY: `buf` provides the `IFNAMSIZ` bytes the function requires.
        let ptr = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
        if ptr.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        // On success the buffer holds a NUL-terminated name.
        Self::try_from(buf.map(|c| c as u8))
    }
}

impl fmt::Debug for IfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `OsStr` escapes bytes that are not UTF-8.
        write!(f, "IfName({:?})", self.as_os_str())
    }
}

impl fmt::Display for IfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.to_string_lossy(), f)
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

    fn try_from(bytes: &[u8]) -> crate::Result<Self> {
        Self::new(bytes)
    }
}

impl TryFrom<Vec<u8>> for IfName {
    type Error = crate::Error;

    fn try_from(bytes: Vec<u8>) -> crate::Result<Self> {
        Self::new(bytes)
    }
}

impl TryFrom<&OsStr> for IfName {
    type Error = crate::Error;

    fn try_from(s: &OsStr) -> crate::Result<Self> {
        Self::new(s.as_bytes())
    }
}

impl TryFrom<&CStr> for IfName {
    type Error = crate::Error;

    fn try_from(s: &CStr) -> crate::Result<Self> {
        Self::new(s.to_bytes())
    }
}

impl TryFrom<[u8; IFNAMSIZ]> for IfName {
    type Error = crate::Error;

    /// Validates a NUL-padded kernel buffer such as `ifreq::ifr_name`.
    fn try_from(array: [u8; IFNAMSIZ]) -> crate::Result<Self> {
        let len = array
            .iter()
            .position(|&c| c == 0)
            .ok_or(IfNameError::TooLong)?;
        Self::new(&array[..len])
    }
}

impl AsRef<[u8]> for IfName {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<OsStr> for IfName {
    fn as_ref(&self) -> &OsStr {
        self.as_os_str()
    }
}

impl AsRef<CStr> for IfName {
    fn as_ref(&self) -> &CStr {
        self.as_c_str()
    }
}

impl From<IfName> for [u8; IFNAMSIZ] {
    fn from(name: IfName) -> Self {
        name.0
    }
}

impl From<IfName> for Vec<u8> {
    fn from(name: IfName) -> Self {
        name.as_bytes().to_vec()
    }
}

impl From<IfName> for OsString {
    fn from(name: IfName) -> Self {
        OsString::from_vec(name.as_bytes().to_vec())
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
        assert_eq!(ok.to_str(), Some("l2tp0"));
        assert_eq!(ok.to_string(), "l2tp0");
        assert_eq!(ok.as_bytes(), b"l2tp0");
        assert_eq!(ok.as_array(), b"l2tp0\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(format!("{ok:?}"), "IfName(\"l2tp0\")");

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
        assert!(IfName::new("0123456789abcde").is_ok());
    }

    #[test]
    fn ifname_errors_name_the_violated_rule() {
        use crate::Error::InvalidIfName;

        assert!(matches!(
            IfName::new(""),
            Err(InvalidIfName(IfNameError::Empty))
        ));
        assert!(matches!(
            IfName::new("0123456789abcdef"),
            Err(InvalidIfName(IfNameError::TooLong))
        ));
        assert!(matches!(
            IfName::new(".."),
            Err(InvalidIfName(IfNameError::Reserved))
        ));
        assert!(matches!(
            IfName::new("eth:0"),
            Err(InvalidIfName(IfNameError::InvalidByte(b':')))
        ));
        assert!(matches!(
            IfName::new("a\0b"),
            Err(InvalidIfName(IfNameError::InvalidByte(0)))
        ));
        assert_eq!(
            IfName::new("a b").unwrap_err().to_string(),
            "invalid interface name: name contains ' '"
        );
        assert_eq!(
            IfName::new("").unwrap_err().to_string(),
            "invalid interface name: name is empty"
        );
        assert_eq!(
            IfName::new("0123456789abcdef").unwrap_err().to_string(),
            "invalid interface name: name is longer than 15 bytes"
        );
    }

    #[test]
    fn ifname_conversions_validate() {
        let name: IfName = "eth0".parse().unwrap();
        assert_eq!(IfName::try_from("eth0").unwrap(), name);
        assert_eq!(IfName::try_from(String::from("eth0")).unwrap(), name);
        assert_eq!(IfName::try_from(&b"eth0"[..]).unwrap(), name);
        assert_eq!(IfName::try_from(b"eth0".to_vec()).unwrap(), name);
        assert_eq!(IfName::try_from(OsStr::new("eth0")).unwrap(), name);
        assert_eq!(IfName::try_from(c"eth0").unwrap(), name);
        let array: [u8; IFNAMSIZ] = name.into();
        assert_eq!(&array, b"eth0\0\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(IfName::try_from(array).unwrap(), name);

        assert_eq!(AsRef::<[u8]>::as_ref(&name), b"eth0");
        assert_eq!(AsRef::<OsStr>::as_ref(&name), OsStr::new("eth0"));
        assert_eq!(AsRef::<CStr>::as_ref(&name), c"eth0");
        assert_eq!(name.as_c_str(), c"eth0");
        assert_eq!(Vec::<u8>::from(name), b"eth0");
        assert_eq!(OsString::from(name), OsString::from("eth0"));

        assert!(matches!(
            "eth:0".parse::<IfName>(),
            Err(crate::Error::InvalidIfName(_))
        ));
        assert!(matches!(
            IfName::try_from(String::from("")),
            Err(crate::Error::InvalidIfName(_))
        ));
        // A kernel buffer without a terminator is not a name.
        assert!(matches!(
            IfName::try_from([b'a'; IFNAMSIZ]),
            Err(crate::Error::InvalidIfName(IfNameError::TooLong))
        ));

        let mut names = [name, IfName::new("br0").unwrap()];
        names.sort();
        assert_eq!(names[0].to_str(), Some("br0"));
        let set: std::collections::HashSet<IfName> = names.into();
        assert!(set.contains(&name));
    }

    #[test]
    fn ifname_accepts_bytes_that_are_not_utf8() {
        let raw = IfName::new(b"eth\xff0").unwrap();
        assert_eq!(raw.as_bytes(), b"eth\xff0");
        assert_eq!(raw.to_str(), None);
        assert_eq!(raw.to_string_lossy(), "eth\u{fffd}0");
        assert_eq!(raw.to_string(), "eth\u{fffd}0");
        assert_eq!(format!("{raw:?}"), "IfName(\"eth\\xFF0\")");
        assert_eq!(
            IfName::try_from(OsStr::from_bytes(b"eth\xff0")).unwrap(),
            raw
        );
        assert_eq!(Vec::<u8>::from(raw), b"eth\xff0");
        assert_ne!(raw, IfName::new("eth0").unwrap());
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

        let scoped = IpEndpoint::v6_scoped(link_local, eth0);
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

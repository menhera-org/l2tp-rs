// SPDX-License-Identifier: MIT

#[cfg(feature = "serde")]
use std::borrow::Cow;
use std::{ffi::OsStr, fmt, os::unix::ffi::OsStrExt};

pub use netlink_packet_l2tp::L2tpIfName;

/// Size of the kernel's interface name buffer (`IFNAMSIZ`), including the NUL
/// terminator; the length of [`L2tpIfName::as_array`].
pub const IFNAMSIZ: usize = 16;

/// Kernel tunnel identifier (`L2TP_ATTR_CONN_ID`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TunnelId(
    /// Raw numeric tunnel identifier.
    pub u32,
);

/// Kernel session identifier (`L2TP_ATTR_SESSION_ID`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SessionId(
    /// Raw numeric session identifier.
    pub u32,
);

macro_rules! id_conversions {
    ($id:ident) => {
        impl fmt::Display for $id {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<u32> for $id {
            fn from(raw: u32) -> Self {
                Self(raw)
            }
        }

        impl From<$id> for u32 {
            fn from(id: $id) -> Self {
                id.0
            }
        }
    };
}

id_conversions!(TunnelId);
id_conversions!(SessionId);

/// L2TP protocol version of a tunnel (`L2TP_ATTR_PROTO_VERSION`).
///
/// The kernel supports L2TPv2 (RFC 2661), whose sessions are PPP pseudowires
/// with 16-bit identifiers, and L2TPv3 (RFC 3931), which adds Ethernet
/// pseudowires, cookies and the L2-specific sublayer. Ethernet sessions
/// require version 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub enum L2tpVersion {
    /// L2TPv2.
    V2,
    /// L2TPv3, the default.
    #[default]
    V3,
}

impl L2tpVersion {
    /// Returns the raw protocol version number.
    pub fn number(self) -> u8 {
        match self {
            Self::V2 => 2,
            Self::V3 => 3,
        }
    }
}

impl fmt::Display for L2tpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.number().fmt(f)
    }
}

impl From<L2tpVersion> for u8 {
    fn from(version: L2tpVersion) -> Self {
        version.number()
    }
}

impl TryFrom<u8> for L2tpVersion {
    type Error = crate::Error;

    fn try_from(raw: u8) -> crate::Result<Self> {
        match raw {
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            other => Err(crate::Error::UnsupportedVersion(other)),
        }
    }
}

/// Session cookie, 0, 4 or 8 bytes (`L2TP_ATTR_COOKIE`).
///
/// Construct one with [`Cookie::none`], the `TryFrom` conversions from
/// `&[u8]` and `Vec<u8>`, the `From` conversions from `[u8; 4]` and
/// `[u8; 8]`, or by parsing a hexadecimal string. `Display` prints the bytes
/// as lowercase hexadecimal. With the `serde` feature a cookie is a
/// hexadecimal string in human-readable formats and bytes otherwise.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Cookie {
    bytes: [u8; 8],
    len: u8,
}

impl Cookie {
    /// Returns an empty cookie.
    pub fn none() -> Self {
        Self::default()
    }

    /// Returns the raw cookie bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Returns the cookie length in bytes: 0, 4 or 8.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Returns whether the cookie is absent.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl TryFrom<&[u8]> for Cookie {
    type Error = crate::Error;

    fn try_from(b: &[u8]) -> crate::Result<Self> {
        match b.len() {
            0 | 4 | 8 => {
                let mut bytes = [0; 8];
                bytes[..b.len()].copy_from_slice(b);
                Ok(Self {
                    bytes,
                    len: b.len() as u8,
                })
            }
            n => Err(crate::Error::InvalidCookieLength(n)),
        }
    }
}

impl TryFrom<Vec<u8>> for Cookie {
    type Error = crate::Error;

    fn try_from(b: Vec<u8>) -> crate::Result<Self> {
        Self::try_from(b.as_slice())
    }
}

impl From<[u8; 4]> for Cookie {
    fn from(b: [u8; 4]) -> Self {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&b);
        Self { bytes, len: 4 }
    }
}

impl From<[u8; 8]> for Cookie {
    fn from(bytes: [u8; 8]) -> Self {
        Self { bytes, len: 8 }
    }
}

impl AsRef<[u8]> for Cookie {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::str::FromStr for Cookie {
    type Err = crate::Error;

    /// Parses a hexadecimal string of 0, 8 or 16 digits.
    fn from_str(s: &str) -> crate::Result<Self> {
        let digits = s.as_bytes();
        // `from_str_radix` would also accept a sign, so check the digits.
        if !digits.len().is_multiple_of(2)
            || !digits.iter().all(u8::is_ascii_hexdigit)
        {
            return Err(crate::Error::InvalidCookieHex);
        }
        let mut bytes = Vec::with_capacity(digits.len() / 2);
        for pair in digits.chunks(2) {
            let hex = std::str::from_utf8(pair)
                .map_err(|_| crate::Error::InvalidCookieHex)?;
            bytes.push(
                u8::from_str_radix(hex, 16)
                    .map_err(|_| crate::Error::InvalidCookieHex)?,
            );
        }
        Self::try_from(bytes.as_slice())
    }
}

impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cookie(\"{self}\")")
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Cookie {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Cookie {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        if deserializer.is_human_readable() {
            let hex = <Cow<'de, str>>::deserialize(deserializer)?;
            hex.parse().map_err(D::Error::custom)
        } else {
            let bytes = <Cow<'de, [u8]>>::deserialize(deserializer)?;
            Self::try_from(bytes.as_ref()).map_err(D::Error::custom)
        }
    }
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for netlink_packet_l2tp::L2tpIfName {}
}

/// Operating-system conversions for [`L2tpIfName`], the interface name type
/// of `netlink-packet-l2tp` that this crate re-exports.
///
/// Interface names are byte strings validated with the kernel's
/// `dev_valid_name()` rules; see [`L2tpIfName`] for its constructors and
/// accessors. Their `netlink_packet_core::DecodeError` converts into
/// [`Error::Netlink`](crate::Error::Netlink); [`from_name`](Self::from_name)
/// reports a rejected name as
/// [`Error::InvalidIfName`](crate::Error::InvalidIfName) instead.
pub trait L2tpIfNameExt: sealed::Sealed + Sized {
    /// Validates `name`, given as a string or bytes (for an `OsStr`, its
    /// `as_bytes()`), with the kernel's rules.
    ///
    /// This is [`L2tpIfName::new`] with this crate's error type: a rejected
    /// name is [`Error::InvalidIfName`](crate::Error::InvalidIfName), whose
    /// message names the broken rule.
    fn from_name(name: impl AsRef<[u8]>) -> crate::Result<Self>;

    /// Resolves the name to the interface's current index with
    /// `if_nametoindex(3)`.
    ///
    /// Interface indexes change when an interface is re-created, so resolve
    /// the name right before it is used. For example, build the scope ID of a
    /// link-local [`SocketAddrV6`](std::net::SocketAddrV6) just before
    /// creating or reconnecting a UDP tunnel socket. The error carries
    /// `ENODEV` when no interface has this name.
    fn index(&self) -> crate::Result<u32>;

    /// Looks up the name of the interface with `index` using
    /// `if_indextoname(3)`.
    ///
    /// The error carries `ENXIO` when no interface has this index.
    fn from_index(index: u32) -> crate::Result<Self>;

    /// Returns the name as an `OsStr`, which preserves non-UTF-8 bytes.
    fn as_os_str(&self) -> &OsStr;
}

impl L2tpIfNameExt for L2tpIfName {
    fn from_name(name: impl AsRef<[u8]>) -> crate::Result<Self> {
        Self::new(name)
            .map_err(|err| crate::Error::InvalidIfName(err.to_string()))
    }

    fn index(&self) -> crate::Result<u32> {
        // SAFETY: the array is NUL-terminated by construction (the name is at
        // most 15 of its 16 bytes) and outlives the call.
        let index =
            unsafe { libc::if_nametoindex(self.as_array().as_ptr().cast()) };
        if index == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(index)
    }

    fn from_index(index: u32) -> crate::Result<Self> {
        let mut buf = [0 as libc::c_char; IFNAMSIZ];
        // SAFETY: `buf` provides the `IFNAMSIZ` bytes the function requires.
        let ptr = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
        if ptr.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        // On success the buffer holds a NUL-terminated name.
        Ok(Self::try_from(buf.map(|c| c as u8))?)
    }

    fn as_os_str(&self) -> &OsStr {
        OsStr::from_bytes(self.as_bytes())
    }
}

/// `serde` adapter for `Option<L2tpIfName>` fields: a string when the name
/// is UTF-8, bytes otherwise, and `null` for `None`.
#[cfg(feature = "serde")]
pub(crate) mod ifname_serde {
    use std::fmt;

    use serde::{Deserializer, Serializer, de::Visitor};

    use super::{IFNAMSIZ, L2tpIfName};

    pub(crate) fn serialize<S: Serializer>(
        name: &Option<L2tpIfName>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match name {
            None => serializer.serialize_none(),
            Some(name) => match name.to_str() {
                Ok(utf8) => serializer.serialize_some(utf8),
                Err(_) => serializer.serialize_some(name.as_bytes()),
            },
        }
    }

    struct NameVisitor;

    impl<'de> Visitor<'de> for NameVisitor {
        type Value = L2tpIfName;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a Linux interface name as a string or bytes")
        }

        fn visit_str<E: serde::de::Error>(
            self,
            v: &str,
        ) -> Result<L2tpIfName, E> {
            L2tpIfName::new(v).map_err(E::custom)
        }

        fn visit_bytes<E: serde::de::Error>(
            self,
            v: &[u8],
        ) -> Result<L2tpIfName, E> {
            L2tpIfName::new(v).map_err(E::custom)
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<L2tpIfName, A::Error> {
            // A valid name fits the kernel buffer, so stop collecting as
            // soon as the sequence is too long for one.
            let mut bytes = Vec::with_capacity(IFNAMSIZ);
            while let Some(byte) = seq.next_element::<u8>()? {
                if bytes.len() == IFNAMSIZ {
                    return Err(serde::de::Error::invalid_length(
                        bytes.len() + 1,
                        &self,
                    ));
                }
                bytes.push(byte);
            }
            L2tpIfName::new(bytes).map_err(serde::de::Error::custom)
        }
    }

    struct OptionVisitor;

    impl<'de> Visitor<'de> for OptionVisitor {
        type Value = Option<L2tpIfName>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an optional Linux interface name")
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserializer.deserialize_any(NameVisitor).map(Some)
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<L2tpIfName>, D::Error> {
        deserializer.deserialize_option(OptionVisitor)
    }
}

/// UDP socket endpoint used for UDP encapsulated tunnels.
///
/// It displays, parses and serializes as a socket address such as
/// `192.0.2.1:1701` or `[fe80::1%2]:1701`.
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
    /// [`L2tpIfNameExt::index`] right before creating or reconnecting the
    /// socket. Unmanaged tunnels cannot use link-local addresses.
    pub fn is_link_local(&self) -> bool {
        match self {
            Self::V4(_) => false,
            Self::V6(addr) => addr.ip().is_unicast_link_local(),
        }
    }
}

impl From<std::net::SocketAddr> for UdpEndpoint {
    fn from(addr: std::net::SocketAddr) -> Self {
        match addr {
            std::net::SocketAddr::V4(v4) => Self::V4(v4),
            std::net::SocketAddr::V6(v6) => Self::V6(v6),
        }
    }
}

impl From<UdpEndpoint> for std::net::SocketAddr {
    fn from(endpoint: UdpEndpoint) -> Self {
        match endpoint {
            UdpEndpoint::V4(v4) => Self::V4(v4),
            UdpEndpoint::V6(v6) => Self::V6(v6),
        }
    }
}

impl fmt::Display for UdpEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(addr) => addr.fmt(f),
            Self::V6(addr) => addr.fmt(f),
        }
    }
}

impl std::str::FromStr for UdpEndpoint {
    type Err = crate::Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        s.parse::<std::net::SocketAddr>()
            .map(Self::from)
            .map_err(|e| crate::Error::InvalidEndpoint(format!("{s}: {e}")))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for UdpEndpoint {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for UdpEndpoint {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let text = <Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// IP endpoint used for IP encapsulated (`L2TPIP`) tunnels.
///
/// It displays and parses as an IP address with an optional `%scope` suffix
/// naming the interface of a link-local IPv6 address, such as
/// `192.0.2.1` or `fe80::1%eth0`. With the `serde` feature it serializes as
/// that string, except that a non-UTF-8 scope name is written as a map
/// `{"addr": ..., "scope": [bytes]}`, which deserialization accepts too.
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
        scope: Option<L2tpIfName>,
    },
}

impl fmt::Display for IpEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(addr) => addr.fmt(f),
            Self::V6 { addr, scope: None } => addr.fmt(f),
            Self::V6 {
                addr,
                scope: Some(scope),
            } => write!(f, "{addr}%{scope}"),
        }
    }
}

impl std::str::FromStr for IpEndpoint {
    type Err = crate::Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        let invalid = |reason: String| {
            crate::Error::InvalidEndpoint(format!("{s}: {reason}"))
        };
        match s.split_once('%') {
            None => s
                .parse::<std::net::IpAddr>()
                .map(Self::from)
                .map_err(|e| invalid(e.to_string())),
            Some((addr, scope)) => {
                let addr =
                    addr.parse::<std::net::Ipv6Addr>().map_err(|_| {
                        invalid(
                            "only an IPv6 address takes a %scope".to_string(),
                        )
                    })?;
                let scope = L2tpIfName::new(scope)
                    .map_err(|e| invalid(e.to_string()))?;
                Ok(Self::v6_scoped(addr, scope))
            }
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for IpEndpoint {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        match self {
            Self::V6 {
                addr,
                scope: Some(scope),
            } if scope.to_str().is_err() => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("addr", addr)?;
                map.serialize_entry("scope", scope.as_bytes())?;
                map.end()
            }
            _ => serializer.collect_str(self),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for IpEndpoint {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Scoped {
            addr: std::net::Ipv6Addr,
            #[serde(default, with = "ifname_serde")]
            scope: Option<L2tpIfName>,
        }

        struct EndpointVisitor;

        impl<'de> serde::de::Visitor<'de> for EndpointVisitor {
            type Value = IpEndpoint;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "an IP address with an optional %scope, or a map with \
                     `addr` and `scope`",
                )
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<IpEndpoint, E> {
                v.parse().map_err(E::custom)
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<IpEndpoint, A::Error> {
                let scoped = <Scoped as serde::Deserialize>::deserialize(
                    serde::de::value::MapAccessDeserializer::new(map),
                )?;
                Ok(IpEndpoint::V6 {
                    addr: scoped.addr,
                    scope: scoped.scope,
                })
            }
        }

        deserializer.deserialize_any(EndpointVisitor)
    }
}

impl IpEndpoint {
    /// Creates an IPv6 endpoint without an interface scope.
    pub fn v6(addr: std::net::Ipv6Addr) -> Self {
        Self::V6 { addr, scope: None }
    }

    /// Creates an IPv6 endpoint scoped to an interface, as link-local
    /// addresses require.
    pub fn v6_scoped(addr: std::net::Ipv6Addr, scope: L2tpIfName) -> Self {
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

    /// Returns the IP address without its scope.
    pub fn ip(&self) -> std::net::IpAddr {
        match self {
            Self::V4(addr) => std::net::IpAddr::V4(*addr),
            Self::V6 { addr, .. } => std::net::IpAddr::V6(*addr),
        }
    }

    /// Returns the interface scope of an IPv6 endpoint.
    pub fn scope(&self) -> Option<&L2tpIfName> {
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

impl From<std::net::IpAddr> for IpEndpoint {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(v4) => Self::V4(v4),
            std::net::IpAddr::V6(v6) => Self::v6(v6),
        }
    }
}

/// Tunnel encapsulation parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
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
        #[cfg_attr(feature = "serde", serde(default = "default_true"))]
        udp_csum: bool,
        /// Whether IPv6 packets are sent with a zero UDP checksum.
        #[cfg_attr(feature = "serde", serde(default))]
        udp_zero_csum6_tx: bool,
        /// Whether IPv6 packets with a zero UDP checksum are accepted.
        #[cfg_attr(feature = "serde", serde(default))]
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

#[cfg(feature = "serde")]
fn default_true() -> bool {
    true
}

/// Session pseudowire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
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
        let c0 = Cookie::try_from(&[][..]).unwrap();
        let c4 = Cookie::try_from(vec![1, 2, 3, 4]).unwrap();
        let c8 = Cookie::try_from(&[1u8, 2, 3, 4, 5, 6, 7, 8][..]).unwrap();
        assert!(c0.as_bytes().is_empty());
        assert!(c0.is_empty());
        assert_eq!(c4.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(c4.len(), 4);
        assert_eq!(c8.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(Cookie::from([1, 2, 3, 4]), c4);
        assert_eq!(Cookie::from([1, 2, 3, 4, 5, 6, 7, 8]), c8);
        assert_eq!(Cookie::none(), Cookie::default());
    }

    #[test]
    fn cookie_rejects_invalid_length() {
        let err = Cookie::try_from(vec![1, 2, 3]).unwrap_err();
        match err {
            crate::Error::InvalidCookieLength(3) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn cookie_hex_round_trips() {
        let cookie: Cookie = "deadbeef".parse().unwrap();
        assert_eq!(cookie.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(cookie.to_string(), "deadbeef");
        assert_eq!(format!("{cookie:?}"), "Cookie(\"deadbeef\")");
        assert_eq!("".parse::<Cookie>().unwrap(), Cookie::none());
        assert_eq!(
            "0011223344556677".parse::<Cookie>().unwrap().to_string(),
            "0011223344556677"
        );
        for bad in ["abc", "zz", "éé", "aabbcc", "+1+2+3+4"] {
            assert!(bad.parse::<Cookie>().is_err(), "{bad}");
        }
        assert!(matches!(
            "abc".parse::<Cookie>(),
            Err(crate::Error::InvalidCookieHex)
        ));
        assert!(matches!(
            "aabbcc".parse::<Cookie>(),
            Err(crate::Error::InvalidCookieLength(3))
        ));
    }

    #[test]
    fn ids_convert_and_display() {
        let tunnel = TunnelId::from(7);
        assert_eq!(u32::from(tunnel), 7);
        assert_eq!(tunnel.to_string(), "7");
        assert!(TunnelId(1) < TunnelId(2));
        let session: SessionId = 9.into();
        assert_eq!(session.to_string(), "9");
    }

    #[test]
    fn versions_convert() {
        assert_eq!(L2tpVersion::default(), L2tpVersion::V3);
        assert_eq!(u8::from(L2tpVersion::V2), 2);
        assert_eq!(L2tpVersion::try_from(3).unwrap(), L2tpVersion::V3);
        assert_eq!(L2tpVersion::V2.to_string(), "2");
        assert!(matches!(
            L2tpVersion::try_from(4),
            Err(crate::Error::UnsupportedVersion(4))
        ));
    }

    #[test]
    fn ifname_errors_map_to_netlink_errors() {
        let err = L2tpIfName::new("eth:0").unwrap_err();
        let err = crate::Error::from(err);
        assert!(matches!(err, crate::Error::Netlink(_)), "{err:?}");
        assert!(err.to_string().contains("invalid interface name"));
    }

    #[test]
    fn from_name_reports_invalid_names_with_the_crate_error() {
        assert_eq!(
            L2tpIfName::from_name("eth0").unwrap(),
            L2tpIfName::new("eth0").unwrap()
        );
        assert_eq!(
            L2tpIfName::from_name(OsStr::new("eth0").as_bytes()).unwrap(),
            L2tpIfName::new("eth0").unwrap()
        );
        assert_eq!(
            L2tpIfName::from_name(b"eth\xff0".as_slice()).unwrap(),
            L2tpIfName::new(b"eth\xff0").unwrap()
        );
        for invalid in ["", "this-interface-name-is-way-too-long", "eth 0"] {
            let err = L2tpIfName::from_name(invalid).unwrap_err();
            assert!(matches!(err, crate::Error::InvalidIfName(_)), "{err:?}");
            assert!(err.to_string().starts_with("invalid interface name"));
            assert!(err.raw_os_error().is_none());
        }
    }

    #[test]
    fn ifname_extension_conversions() {
        let raw = L2tpIfName::new(b"eth\xff0").unwrap();
        assert_eq!(raw.as_os_str().as_bytes(), b"eth\xff0");
        assert_eq!(IFNAMSIZ, raw.as_array().len());

        // Loopback always exists on Linux.
        let lo = L2tpIfName::new("lo").unwrap();
        let index = lo.index().unwrap();
        assert_ne!(index, 0);
        assert_eq!(L2tpIfName::from_index(index).unwrap(), lo);

        let missing = L2tpIfName::new("l2tp-no-such0").unwrap();
        let err = missing.index().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV));

        let err = L2tpIfName::from_index(u32::MAX).unwrap_err();
        assert!(matches!(err, crate::Error::Io(_)));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trips_names_cookies_and_endpoints() {
        let name = L2tpIfName::new("eth0").unwrap();
        let endpoint = IpEndpoint::v6_scoped(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            name,
        );
        let json = serde_json::to_string(&endpoint).unwrap();
        assert_eq!(json, "\"fe80::1%eth0\"");
        assert_eq!(
            serde_json::from_str::<IpEndpoint>(&json).unwrap(),
            endpoint
        );
        assert_eq!(
            serde_json::to_string(&IpEndpoint::V4(Ipv4Addr::LOCALHOST))
                .unwrap(),
            "\"127.0.0.1\""
        );
        assert_eq!(
            serde_json::from_str::<IpEndpoint>("\"::1\"").unwrap(),
            IpEndpoint::v6(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            serde_json::from_str::<IpEndpoint>("{\"addr\":\"::1\"}").unwrap(),
            IpEndpoint::v6(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            serde_json::from_str::<IpEndpoint>(
                "{\"addr\":\"::1\",\"scope\":[101,116,104,48]}"
            )
            .unwrap(),
            IpEndpoint::v6_scoped(Ipv6Addr::LOCALHOST, name)
        );
        assert!(serde_json::from_str::<IpEndpoint>("\"::1%eth:0\"").is_err());
        assert!(
            serde_json::from_str::<IpEndpoint>("\"10.0.0.1%eth0\"").is_err()
        );
        let raw = IpEndpoint::v6_scoped(
            Ipv6Addr::LOCALHOST,
            L2tpIfName::new(b"eth\xff0").unwrap(),
        );
        let json = serde_json::to_string(&raw).unwrap();
        assert_eq!(json, "{\"addr\":\"::1\",\"scope\":[101,116,104,255,48]}");
        assert_eq!(serde_json::from_str::<IpEndpoint>(&json).unwrap(), raw);

        let udp =
            UdpEndpoint::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1701, 0, 3));
        let json = serde_json::to_string(&udp).unwrap();
        assert_eq!(json, "\"[::1%3]:1701\"");
        assert_eq!(serde_json::from_str::<UdpEndpoint>(&json).unwrap(), udp);
        assert!(serde_json::from_str::<UdpEndpoint>("\"::1\"").is_err());

        let cookie: Cookie = "deadbeef".parse().unwrap();
        assert_eq!(serde_json::to_string(&cookie).unwrap(), "\"deadbeef\"");
        assert_eq!(
            serde_json::from_str::<Cookie>("\"deadbeef\"").unwrap(),
            cookie
        );
        assert!(serde_json::from_str::<Cookie>("\"abc\"").is_err());

        let udp = Encapsulation::Udp {
            local: UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)),
            remote: UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2)),
            udp_csum: true,
            udp_zero_csum6_tx: false,
            udp_zero_csum6_rx: false,
        };
        let json = serde_json::to_string(&udp).unwrap();
        assert_eq!(serde_json::from_str::<Encapsulation>(&json).unwrap(), udp);
        // Checksum flags default to the kernel's defaults.
        let parsed: Encapsulation = serde_json::from_str(
            "{\"Udp\":{\"local\":\"127.0.0.1:1\",\"remote\":\"127.0.0.1:2\"}}",
        )
        .unwrap();
        assert_eq!(parsed, udp);
        assert_eq!(serde_json::to_string(&TunnelId(5)).unwrap(), "5");
        assert_eq!(serde_json::to_string(&L2tpVersion::V2).unwrap(), "\"V2\"");
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
        assert_eq!(ip6.ip(), std::net::IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            UdpEndpoint::from(std::net::SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                1701
            ))),
            udp4
        );
        assert_eq!(
            IpEndpoint::from(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ip4
        );
    }

    #[test]
    fn endpoints_display_and_parse() {
        let eth0 = L2tpIfName::new("eth0").unwrap();
        let scoped = IpEndpoint::v6_scoped(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            eth0,
        );
        assert_eq!(scoped.to_string(), "fe80::1%eth0");
        assert_eq!("fe80::1%eth0".parse::<IpEndpoint>().unwrap(), scoped);
        assert_eq!(
            "192.0.2.1".parse::<IpEndpoint>().unwrap(),
            IpEndpoint::V4(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(IpEndpoint::v6(Ipv6Addr::LOCALHOST).to_string(), "::1");
        for bad in ["", "eth0", "192.0.2.1%eth0", "fe80::1%", "fe80::1%a b"] {
            assert!(
                matches!(
                    bad.parse::<IpEndpoint>(),
                    Err(crate::Error::InvalidEndpoint(_))
                ),
                "{bad:?}"
            );
        }

        let udp = UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1701));
        assert_eq!(udp.to_string(), "127.0.0.1:1701");
        assert_eq!("127.0.0.1:1701".parse::<UdpEndpoint>().unwrap(), udp);
        let udp6 =
            UdpEndpoint::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1, 0, 2));
        assert_eq!(udp6.to_string(), "[::1%2]:1");
        assert_eq!("[::1%2]:1".parse::<UdpEndpoint>().unwrap(), udp6);
        assert!(matches!(
            "127.0.0.1".parse::<UdpEndpoint>(),
            Err(crate::Error::InvalidEndpoint(_))
        ));
    }

    #[test]
    fn link_local_endpoints_are_detected_and_scoped() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let eth0 = L2tpIfName::new("eth0").unwrap();

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
    fn l2spec_default_is_none() {
        assert_eq!(L2SpecType::default(), L2SpecType::None);
    }
}

// SPDX-License-Identifier: MIT

use std::{io, net::Ipv6Addr};

use netlink_packet_core::DecodeError;

use crate::L2tpIfName;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A netlink message or attribute value is invalid.
    ///
    /// This covers kernel replies that fail to decode and attribute values
    /// rejected by `netlink-packet-l2tp`, such as interface names that break
    /// the kernel's rules; `netlink_packet_core::DecodeError` converts into
    /// this variant.
    #[error("netlink error: {0}")]
    Netlink(String),

    /// An interface name breaks the kernel's `dev_valid_name()` rules.
    ///
    /// Returned by
    /// [`L2tpIfNameExt::from_name`](crate::L2tpIfNameExt::from_name) and by
    /// the CLI's name arguments; the message names the rule that was
    /// broken.
    #[error("{0}")]
    InvalidIfName(String),

    /// The kernel sent a well-formed reply that this crate cannot use.
    #[error("unexpected kernel reply: {0}")]
    UnexpectedReply(String),

    /// Generic-netlink family discovery for `l2tp` failed.
    #[error("genetlink family resolution failed: {0}")]
    FamilyResolution(String),

    /// I/O failure returned by a socket, thread or netlink operation.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Cookie validation failed because the byte length is invalid.
    #[error("invalid cookie length {0}: must be 0, 4, or 8")]
    InvalidCookieLength(usize),

    /// A cookie string is not an even number of hexadecimal digits.
    #[error("invalid cookie: expected 0, 8 or 16 hexadecimal digits")]
    InvalidCookieHex,

    /// An endpoint string could not be parsed.
    #[error("invalid endpoint {0}")]
    InvalidEndpoint(String),

    /// The kernel supports only L2TP protocol versions 2 and 3.
    #[error("unsupported L2TP protocol version {0}")]
    UnsupportedVersion(u8),

    /// L2TPv2 tunnel and session identifiers are 16-bit.
    #[error("identifier {0} does not fit the 16 bits of an L2TPv2 identifier")]
    V2IdTooLarge(u32),

    /// Local and remote endpoint address families do not match.
    #[error(
        "address family mismatch: local and remote must be the same IP version"
    )]
    AddressFamilyMismatch,

    /// The operation does not match the socket's encapsulation (UDP or IP).
    #[error("encapsulation mismatch: operation does not apply to this socket")]
    EncapsulationMismatch,

    /// A link-local IPv6 endpoint was given without an interface scope.
    ///
    /// The kernel refuses to bind or connect a link-local address without an
    /// interface; see [`IpEndpoint::v6_scoped`](crate::IpEndpoint::v6_scoped).
    #[error("link-local IPv6 address {0} requires an interface scope")]
    ScopeRequired(Ipv6Addr),

    /// The endpoints and device of one socket name different interfaces.
    #[error("interface scope mismatch: {expected} and {found}")]
    ScopeMismatch {
        /// The interface named first.
        expected: L2tpIfName,
        /// The conflicting interface.
        found: L2tpIfName,
    },

    /// Unmanaged tunnels cannot use link-local IPv6 endpoints, because the
    /// kernel creates their socket without an interface scope.
    #[error(
        "unmanaged tunnels cannot use link-local IPv6 endpoints; use a \
         managed TunnelSocket with an interface scope"
    )]
    UnmanagedLinkLocal,

    /// Operation requires an owned tunnel socket fd in this process.
    #[error(
        "operation requires a managed socket (tunnel was created without \
         L2TP_ATTR_FD)"
    )]
    UnmanagedSocket,

    /// The kernel cannot disable IPv4 UDP checksums on an unmanaged IPv6
    /// socket connected to an IPv4-mapped peer.
    #[error(
        "disabling UDP checksums for an IPv4-mapped peer requires a managed \
         socket; use IPv4 endpoints or the managed tunnel API"
    )]
    UnmanagedUdpChecksum,

    /// Kernel returned an error code and message.
    #[error("kernel error {code}: {message}")]
    KernelError {
        /// Positive errno value.
        code: i32,
        /// Human-readable kernel error text.
        message: String,
    },
}

impl Error {
    /// Returns the OS error code, for kernel and OS-level I/O errors.
    pub fn raw_os_error(&self) -> Option<i32> {
        match self {
            Self::KernelError { code, .. } => Some(*code),
            Self::Io(err) => err.raw_os_error(),
            _ => None,
        }
    }

    /// Returns the I/O error kind, so callers can match kernel errors such
    /// as [`io::ErrorKind::AlreadyExists`] without depending on `libc`.
    pub fn kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::KernelError { code, .. } => {
                Some(io::Error::from_raw_os_error(*code).kind())
            }
            Self::Io(err) => Some(err.kind()),
            _ => None,
        }
    }

    pub(crate) fn other(message: impl Into<String>) -> Self {
        Self::Io(io::Error::other(message.into()))
    }
}

impl From<DecodeError> for Error {
    fn from(err: DecodeError) -> Self {
        Self::Netlink(err.to_string())
    }
}

/// Crate-local result type.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use std::io;

    use super::{Error, Ipv6Addr, L2tpIfName};

    #[test]
    fn kernel_error_exposes_os_code_and_kind() {
        let err = Error::KernelError {
            code: libc::EEXIST,
            message: "exists".to_string(),
        };
        assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
        assert_eq!(err.kind(), Some(io::ErrorKind::AlreadyExists));
        assert_eq!(Error::AddressFamilyMismatch.kind(), None);
        assert_eq!(Error::UnmanagedLinkLocal.raw_os_error(), None);
    }

    #[test]
    fn scope_errors_name_the_interfaces() {
        let err = Error::ScopeMismatch {
            expected: L2tpIfName::new("eth0").unwrap(),
            found: L2tpIfName::new("eth1").unwrap(),
        };
        assert_eq!(err.to_string(), "interface scope mismatch: eth0 and eth1");
        let err =
            Error::ScopeRequired(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert!(err.to_string().contains("fe80::1"));
    }

    #[test]
    fn netlink_decode_error_keeps_message() {
        let err =
            Error::from(netlink_packet_core::DecodeError::from("truncated"));
        assert_eq!(err.to_string(), "netlink error: truncated");
    }
}

// SPDX-License-Identifier: MIT

use std::io;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Failed to decode a netlink message.
    #[error("netlink error: {0}")]
    Netlink(String),

    /// The kernel sent a well-formed reply that this crate cannot use.
    #[error("unexpected kernel reply: {0}")]
    UnexpectedReply(String),

    /// Generic-netlink family discovery for `l2tp` failed.
    #[error("genetlink family resolution failed: {0}")]
    FamilyResolution(String),

    /// I/O failure returned by a socket or netlink operation.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Interface name validation failed.
    #[error("invalid interface name: {0}")]
    InvalidIfName(String),

    /// Cookie validation failed because the byte length is invalid.
    #[error("invalid cookie length {0}: must be 0, 4, or 8")]
    InvalidCookieLength(usize),

    /// Local and remote endpoint address families do not match.
    #[error(
        "address family mismatch: local and remote must be the same IP version"
    )]
    AddressFamilyMismatch,

    /// The operation does not match the socket's encapsulation (UDP or IP).
    #[error("encapsulation mismatch: operation does not apply to this socket")]
    EncapsulationMismatch,

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

    pub(crate) fn netlink(err: netlink_packet_core::DecodeError) -> Self {
        Self::Netlink(err.to_string())
    }
}

/// Crate-local result type.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use std::io;

    use super::Error;

    #[test]
    fn kernel_error_exposes_os_code_and_kind() {
        let err = Error::KernelError {
            code: libc::EEXIST,
            message: "exists".to_string(),
        };
        assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
        assert_eq!(err.kind(), Some(io::ErrorKind::AlreadyExists));
        assert_eq!(Error::AddressFamilyMismatch.kind(), None);
    }

    #[test]
    fn netlink_decode_error_keeps_message() {
        let err =
            Error::netlink(netlink_packet_core::DecodeError::from("truncated"));
        assert_eq!(err.to_string(), "netlink error: truncated");
    }
}

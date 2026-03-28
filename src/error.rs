/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to decode a netlink payload.
    #[error("netlink error: {0}")]
    Netlink(#[from] netlink_packet_core::DecodeError),

    /// Generic-netlink family discovery for `l2tp` failed.
    #[error("genetlink family resolution failed: {0}")]
    FamilyResolution(String),

    /// I/O failure returned by a socket or netlink operation.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Interface name validation failed.
    #[error("invalid interface name: {0}")]
    InvalidIfName(String),

    /// Cookie validation failed because the byte length is invalid.
    #[error("invalid cookie length {0}: must be 0, 4, or 8")]
    InvalidCookieLength(usize),

    /// Local and remote endpoint address families do not match.
    #[error("address family mismatch: local and remote must be the same IP version")]
    AddressFamilyMismatch,

    /// Operation requires an owned tunnel socket fd in this process.
    #[error("operation requires a managed socket (tunnel was created without L2TP_ATTR_FD)")]
    UnmanagedSocket,

    /// Kernel returned an error code and message.
    #[error("kernel error {code}: {message}")]
    KernelError {
        /// Positive errno value.
        code: i32,
        /// Human-readable kernel error text.
        message: String,
    },
}

/// Crate-local result type.
pub type Result<T> = std::result::Result<T, Error>;

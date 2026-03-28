#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("netlink error: {0}")]
    Netlink(#[from] netlink_packet_core::DecodeError),

    #[error("genetlink family resolution failed: {0}")]
    FamilyResolution(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid interface name: {0}")]
    InvalidIfName(String),

    #[error("invalid cookie length {0}: must be 0, 4, or 8")]
    InvalidCookieLength(usize),

    #[error("address family mismatch: local and remote must be the same IP version")]
    AddressFamilyMismatch,

    #[error("operation requires a managed socket (tunnel was created without L2TP_ATTR_FD)")]
    UnmanagedSocket,

    #[error("kernel error {code}: {message}")]
    KernelError { code: i32, message: String },
}

pub type Result<T> = std::result::Result<T, Error>;

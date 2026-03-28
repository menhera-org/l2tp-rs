//! High-level async Linux L2TPv3 management over Generic Netlink.

/// Error definitions and crate-local [`Result`](crate::Result) type.
pub mod error;
/// Async netlink handle for tunnel/session management.
pub mod handle;
mod netlink;
/// Session configuration and handles.
pub mod session;
/// Managed tunnel socket helpers.
pub mod socket;
/// Tunnel/session statistics types.
pub mod stats;
/// Tunnel configuration and handles.
pub mod tunnel;
/// Core identifiers and protocol parameter types.
pub mod types;

/// Crate error type.
pub use error::{Error, Result};
/// Shared async L2TP management handle.
pub use handle::L2tpHandle;
/// Session-facing public API.
pub use session::{SessionConfig, SessionHandle, SessionInfo, SessionModify};
/// Owned managed tunnel socket.
pub use socket::TunnelSocket;
/// Statistics structs for tunnels and sessions.
pub use stats::{SessionStats, TunnelStats};
/// Tunnel-facing public API.
pub use tunnel::{TunnelConfig, TunnelHandle, TunnelInfo, TunnelModify};
/// Core shared type definitions.
pub use types::{
    Cookie, Encapsulation, IfName, IpEndpoint, L2SpecType, PseudowireType, SessionId, TunnelId,
    UdpEndpoint,
};

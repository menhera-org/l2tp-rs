// SPDX-License-Identifier: MIT

//! High-level async Linux L2TPv3 management over Generic Netlink.
//!
//! All public types are re-exported at the crate root.
//!
//! The API is only available on Linux; on other platforms this crate is empty.

#![cfg(target_os = "linux")]
#![warn(missing_docs)]

mod error;
mod handle;
mod netlink;
mod session;
mod socket;
mod stats;
mod tunnel;
mod types;

pub use error::{Error, Result};
pub use handle::L2tpHandle;
pub use session::{SessionConfig, SessionHandle, SessionInfo, SessionModify};
pub use socket::TunnelSocket;
pub use stats::{SessionStats, TunnelStats};
pub use tunnel::{TunnelConfig, TunnelHandle, TunnelInfo};
pub use types::{
    Cookie, Encapsulation, IfName, IpEndpoint, L2SpecType, PseudowireType,
    SessionId, TunnelId, UdpEndpoint,
};

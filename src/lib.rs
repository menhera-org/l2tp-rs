// SPDX-License-Identifier: MIT

// The README is the crate documentation, so its examples are doctested.
#![doc = include_str!("../README.md")]
//!
//! All public types are re-exported at the crate root.
//!
//! The API is only available on Linux; on other platforms this crate is empty.

#![cfg(target_os = "linux")]
#![warn(missing_docs)]

pub mod blocking;
mod error;
mod event;
mod handle;
mod link;
mod netlink;
mod netns;
mod ppp;
mod session;
mod socket;
mod stats;
mod tunnel;
mod types;

pub use error::{Error, Result};
pub use event::{Events, L2tpEvent};
pub use handle::L2tpHandle;
/// The error of [`L2tpIfName`]'s own constructors (`new`, `parse` and the
/// `TryFrom` conversions), re-exported so it can be named without
/// depending on `netlink-packet-core`; it converts into
/// [`Error::Netlink`]. [`L2tpIfNameExt::from_name`] reports the same
/// failures as [`Error::InvalidIfName`].
pub use netlink_packet_core::DecodeError;
pub use netns::NetNs;
pub use ppp::{PppChannel, PppSocket, PppUnit};
pub use session::{SessionConfig, SessionHandle, SessionInfo, SessionModify};
pub use socket::{PmtuDiscovery, TunnelSocket};
pub use stats::{SessionStats, TunnelStats};
pub use tunnel::{TunnelConfig, TunnelHandle, TunnelInfo};
pub use types::{
    Cookie, Encapsulation, IFNAMSIZ, IpEndpoint, L2SpecType, L2tpIfName,
    L2tpIfNameExt, L2tpVersion, PseudowireType, SessionId, TunnelId,
    UdpEndpoint,
};

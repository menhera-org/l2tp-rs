// SPDX-License-Identifier: MIT

//! Captures the interface index of a new session device from the kernel's
//! `RTM_NEWLINK` broadcast instead of looking the name up afterwards.
//!
//! L2TP netlink never reports the index of an `l2tpeth` device, and the
//! name it reports is frozen at creation. A name lookup after the fact can
//! be defeated by udev or networkd renaming the new device at once. The
//! kernel, however, broadcasts the device's registration on `RTNLGRP_LINK`
//! synchronously, before it acknowledges `SESSION_CREATE`, so a socket that
//! joined the group beforehand already holds that notification, with the
//! index, when the session exists.

use std::{
    io,
    os::fd::{AsRawFd, RawFd},
};

use netlink_packet_core::{NetlinkBuffer, NlasIterator};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

use crate::{L2tpIfName, netns::Owner};

const RTM_NEWLINK: u16 = 16;
const RTNLGRP_LINK: u32 = 1;
const IFLA_IFNAME: u16 = 3;
/// `sizeof(struct ifinfomsg)`.
const IFINFOMSG_LEN: usize = 16;

/// A `NETLINK_ROUTE` socket subscribed to link notifications in a
/// namespace.
pub(crate) struct LinkMonitor {
    socket: Socket,
}

impl LinkMonitor {
    /// Joins `RTNLGRP_LINK` in `netns`, which needs no privilege.
    pub(crate) fn open(netns: &Owner) -> io::Result<Self> {
        let socket = netns.run_in(|| -> io::Result<Socket> {
            let mut socket = Socket::new(NETLINK_ROUTE)?;
            socket.bind(&SocketAddr::new(0, 1 << (RTNLGRP_LINK - 1)))?;
            socket.set_non_blocking(true)?;
            Ok(socket)
        })??;
        Ok(Self { socket })
    }

    /// Drains the queued notifications and returns the index of the last
    /// device registered under `ifname` among them.
    ///
    /// The kernel marks a registration with an all-ones change mask;
    /// renames and other changes carry a zero mask, so a device that merely
    /// took over the name is not mistaken for the new one. Only messages
    /// from the kernel (port 0) count; a unicast from another process would
    /// need `CAP_NET_ADMIN` on `NETLINK_ROUTE` anyway. The error is the
    /// socket's, typically `ENOBUFS` when notifications were lost.
    pub(crate) fn registered_index(
        &self,
        ifname: &L2tpIfName,
    ) -> io::Result<Option<u32>> {
        let mut found = None;
        loop {
            match self.socket.recv_from_full() {
                Ok((datagram, source)) => {
                    if source.port_number() != 0 {
                        continue;
                    }
                    if let Some(index) = registration_in(&datagram, ifname) {
                        found = Some(index);
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(found);
                }
                Err(err) => return Err(err),
            }
        }
    }
}

impl AsRawFd for LinkMonitor {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// The index of the device registered as `ifname` by the last such message
/// in `datagram`, which may hold several netlink messages.
fn registration_in(datagram: &[u8], ifname: &L2tpIfName) -> Option<u32> {
    let mut rest = datagram;
    let mut found = None;
    while let Ok(message) = NetlinkBuffer::new_checked(rest) {
        if message.message_type() == RTM_NEWLINK
            && let Some(index) = registration(message.payload(), ifname)
        {
            found = Some(index);
        }
        // Messages are padded to four bytes.
        let len = (message.length() as usize).next_multiple_of(4);
        if len == 0 || len > rest.len() {
            break;
        }
        rest = &rest[len..];
    }
    found
}

/// Decodes an `RTM_NEWLINK` payload: `struct ifinfomsg` followed by
/// attributes. Returns the index when it is the registration of `ifname`.
fn registration(payload: &[u8], ifname: &L2tpIfName) -> Option<u32> {
    let header = payload.get(..IFINFOMSG_LEN)?;
    let index = u32::from_ne_bytes(header[4..8].try_into().ok()?);
    let change = u32::from_ne_bytes(header[12..16].try_into().ok()?);
    if change != u32::MAX {
        return None;
    }
    for nla in NlasIterator::new(&payload[IFINFOMSG_LEN..]) {
        let nla = nla.ok()?;
        if nla.kind() != IFLA_IFNAME {
            continue;
        }
        let value = nla.value();
        let name = value.strip_suffix(&[0]).unwrap_or(value);
        return (L2tpIfName::new(name).ok()? == *ifname).then_some(index);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `RTM_NEWLINK` message as the kernel emits it.
    fn new_link(index: u32, name: &[u8], change: u32) -> Vec<u8> {
        let mut nla = Vec::new();
        let nla_len = 4 + name.len() + 1;
        nla.extend_from_slice(&(nla_len as u16).to_ne_bytes());
        nla.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
        nla.extend_from_slice(name);
        nla.push(0);
        nla.resize(nla_len.next_multiple_of(4), 0);

        let mut payload = Vec::new();
        payload.extend_from_slice(&[libc::AF_UNSPEC as u8, 0]);
        payload.extend_from_slice(&(libc::ARPHRD_ETHER).to_ne_bytes());
        payload.extend_from_slice(&index.to_ne_bytes());
        payload.extend_from_slice(&0u32.to_ne_bytes());
        payload.extend_from_slice(&change.to_ne_bytes());
        payload.extend_from_slice(&nla);

        let mut message = Vec::new();
        message.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        message.extend_from_slice(&RTM_NEWLINK.to_ne_bytes());
        message.extend_from_slice(&0u16.to_ne_bytes());
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(&payload);
        message
    }

    #[test]
    fn registrations_are_told_from_renames() {
        let wanted = L2tpIfName::new("l2tp0").unwrap();
        assert_eq!(
            registration_in(&new_link(7, b"l2tp0", u32::MAX), &wanted),
            Some(7)
        );
        // A rename that gives another device this name carries a zero mask.
        assert_eq!(registration_in(&new_link(8, b"l2tp0", 0), &wanted), None);
        // The registration of a different device does not match.
        assert_eq!(
            registration_in(&new_link(9, b"l2tp1", u32::MAX), &wanted),
            None
        );
        // Several messages in one datagram: the last registration counts.
        let mut datagram = new_link(7, b"l2tp0", u32::MAX);
        datagram.extend(new_link(10, b"l2tp0", u32::MAX));
        datagram.extend(new_link(11, b"l2tp0", 0));
        assert_eq!(registration_in(&datagram, &wanted), Some(10));
        // Non-UTF-8 names compare as bytes.
        let raw = L2tpIfName::new(b"eth\xff0").unwrap();
        assert_eq!(
            registration_in(&new_link(3, b"eth\xff0", u32::MAX), &raw),
            Some(3)
        );
        // Truncated input is ignored rather than misread.
        assert_eq!(registration_in(&[0; 7], &wanted), None);
        let mut short = new_link(7, b"l2tp0", u32::MAX);
        short.truncate(20);
        assert_eq!(registration_in(&short, &wanted), None);
    }

    #[test]
    fn monitors_open_without_privileges_and_report_nothing_when_idle() {
        let monitor = LinkMonitor::open(&Owner::here(None).unwrap()).unwrap();
        let name = L2tpIfName::new("l2tp-no-such0").unwrap();
        // No notification concerns this name, and an idle socket does not
        // block.
        assert_eq!(monitor.registered_index(&name).unwrap(), None);
        // The fallback lookup resolves names on this very socket, in its
        // namespace: the kernel hands SIOCGIFINDEX down to the device layer
        // for netlink sockets too.
        let lo = L2tpIfName::new("lo").unwrap();
        assert_eq!(
            crate::socket::interface_index(monitor.as_raw_fd(), &lo).unwrap(),
            crate::L2tpIfNameExt::index(&lo).unwrap()
        );
        assert_eq!(
            crate::socket::interface_index(monitor.as_raw_fd(), &name)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENODEV)
        );
    }
}

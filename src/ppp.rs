// SPDX-License-Identifier: MIT

//! PPP pseudowire data plane: `PPPoL2TP` sockets and PPP units.
//!
//! The kernel's `l2tp_ppp` module turns an L2TP session into a PPP channel
//! once a `PPPoL2TP` socket is connected to it. [`PppSocket::connect`]
//! attaches to a session of a tunnel that this crate created through netlink;
//! the socket then carries PPP frames, so PPP negotiation (LCP, IPCP and so
//! on) is done by user space on that descriptor, for example by `pppd` with
//! its `pppol2tp <fd>` option. [`PppUnit`] creates a `pppN` network interface
//! and connects such a channel to it when the application implements PPP
//! itself.

use std::{
    fs::OpenOptions,
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
        unix::fs::OpenOptionsExt,
    },
};

use crate::{L2tpIfName, L2tpVersion, SessionId, TunnelId};

const PX_PROTO_OL2TP: libc::c_int = 1;

// The `_IOC` request encoding of `asm-generic/ioctl.h`. MIPS, PowerPC and
// SPARC use different direction bits and a narrower size field
// (`asm/ioctl.h` of each), so the requests are computed per architecture.
#[cfg(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "sparc",
    target_arch = "sparc64",
))]
mod ioc {
    pub(super) const NONE: u32 = 1;
    pub(super) const READ: u32 = 2;
    pub(super) const WRITE: u32 = 4;
    pub(super) const SIZE_BITS: u32 = 13;
}
#[cfg(not(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "sparc",
    target_arch = "sparc64",
)))]
mod ioc {
    pub(super) const NONE: u32 = 0;
    pub(super) const WRITE: u32 = 1;
    pub(super) const READ: u32 = 2;
    pub(super) const SIZE_BITS: u32 = 14;
}

/// `_IOC(dir, 't', nr, size)`. The request type differs between C
/// libraries, so the value is cast.
const fn ppp_ioctl(dir: u32, nr: u8, size: usize) -> libc::Ioctl {
    const TYPE_SHIFT: u32 = 8;
    const SIZE_SHIFT: u32 = 16;
    const DIR_SHIFT: u32 = SIZE_SHIFT + ioc::SIZE_BITS;
    ((dir << DIR_SHIFT)
        | ((size as u32) << SIZE_SHIFT)
        | ((b't' as u32) << TYPE_SHIFT)
        | nr as u32) as libc::Ioctl
}

// From `linux/ppp-ioctl.h`.
const INT: usize = size_of::<libc::c_int>();
const PPPIOCGCHAN: libc::Ioctl = ppp_ioctl(ioc::READ, 55, INT);
const PPPIOCATTCHAN: libc::Ioctl = ppp_ioctl(ioc::WRITE, 56, INT);
const PPPIOCDISCONN: libc::Ioctl = ppp_ioctl(ioc::NONE, 57, 0);
const PPPIOCCONNECT: libc::Ioctl = ppp_ioctl(ioc::WRITE, 58, INT);
const PPPIOCNEWUNIT: libc::Ioctl = ppp_ioctl(ioc::READ | ioc::WRITE, 62, INT);

// `sizeof(struct sockaddr_pppol2tp)` and `sizeof(struct sockaddr_pppol2tpv3)`
// from `linux/if_pppox.h`. The structs are packed, and the kernel selects the
// protocol version from the address length.
const SOCKADDR_PPPOL2TP_LEN: usize = 38;
const SOCKADDR_PPPOL2TPV3_LEN: usize = 46;

/// A connected `PPPoL2TP` socket: the data plane of a PPP pseudowire.
///
/// The session lives only as long as this socket: when the last descriptor
/// of the socket is closed, for example by dropping it, the kernel deletes
/// the session from its tunnel, whether the session was created through
/// netlink or by [`connect`](Self::connect) itself. The kernel announces no
/// event for this deletion. A session handle for it should have auto-delete
/// disabled, or its deletion will report `ENODEV`.
#[derive(Debug)]
pub struct PppSocket {
    fd: OwnedFd,
}

impl PppSocket {
    /// Attaches a PPP channel to a session of an existing tunnel.
    ///
    /// The tunnel must have been created through netlink, so the kernel owns
    /// or knows its socket; `version` must match the tunnel. When the session
    /// does not exist yet, the kernel creates a plain PPP session with these
    /// identifiers, without cookies; create it through
    /// [`L2tpHandle::create_session`](crate::L2tpHandle::create_session) first
    /// to control its parameters. Both sessions and tunnels of L2TPv2 use
    /// 16-bit identifiers.
    ///
    /// Requires the `l2tp_ppp` module. The kernel returns `ENOENT` when the
    /// tunnel does not exist, `EPROTOTYPE` when the session is not a PPP
    /// pseudowire and `EEXIST` when it is attached already.
    pub fn connect(
        version: L2tpVersion,
        tunnel_id: TunnelId,
        peer_tunnel_id: TunnelId,
        session_id: SessionId,
        peer_session_id: SessionId,
    ) -> crate::Result<Self> {
        let address = sockaddr_pppol2tp(
            version,
            tunnel_id,
            peer_tunnel_id,
            session_id,
            peer_session_id,
        )?;
        // SAFETY: plain socket creation; the descriptor is owned exactly once.
        let raw = unsafe {
            libc::socket(
                libc::AF_PPPOX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                PX_PROTO_OL2TP,
            )
        };
        if raw == -1 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: `raw` is a freshly created descriptor.
        let fd =
            unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) };
        // SAFETY: `address` is a fully initialized sockaddr buffer of the
        // length passed, and `fd` is an open socket.
        let rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                address.as_ptr().cast(),
                address.len() as libc::socklen_t,
            )
        };
        if rc == -1 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self { fd })
    }

    /// Returns the PPP channel index (`PPPIOCGCHAN`), as `pppd` and
    /// [`PppUnit::connect_channel`] need it.
    pub fn channel_index(&self) -> crate::Result<i32> {
        let mut index: libc::c_int = 0;
        // SAFETY: the ioctl writes one `c_int` through the pointer.
        let rc = unsafe {
            libc::ioctl(self.fd.as_raw_fd(), PPPIOCGCHAN, &mut index)
        };
        if rc == -1 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(index)
    }

    /// Takes the descriptor out of the socket, for example to pass it to
    /// `pppd`.
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }
}

impl AsFd for PppSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for PppSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

/// A PPP network interface (`pppN`) created through `/dev/ppp`.
///
/// The interface exists while this value is alive. Connect a PPP channel to
/// it with [`connect_channel`](Self::connect_channel); PPP control frames are
/// then read from and written to the unit descriptor, while configured
/// network protocols flow through the interface.
#[derive(Debug)]
pub struct PppUnit {
    fd: OwnedFd,
    index: i32,
    ifname: L2tpIfName,
}

impl PppUnit {
    /// Creates a PPP unit with a kernel-chosen index.
    pub fn new() -> crate::Result<Self> {
        Self::create(-1)
    }

    /// Creates the PPP unit with the given index, failing with `EEXIST` when
    /// it is taken.
    pub fn with_index(index: i32) -> crate::Result<Self> {
        Self::create(index)
    }

    fn create(requested: i32) -> crate::Result<Self> {
        let fd: OwnedFd = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/ppp")?
            .into();
        let mut index: libc::c_int = requested;
        // SAFETY: the ioctl reads and writes one `c_int` through the pointer.
        let rc =
            unsafe { libc::ioctl(fd.as_raw_fd(), PPPIOCNEWUNIT, &mut index) };
        if rc == -1 {
            return Err(io::Error::last_os_error().into());
        }
        let ifname = L2tpIfName::new(format!("ppp{index}"))?;
        Ok(Self { fd, index, ifname })
    }

    /// Returns the unit index, `N` of `pppN`.
    pub fn index(&self) -> i32 {
        self.index
    }

    /// Returns the interface name, `pppN`.
    pub fn ifname(&self) -> &L2tpIfName {
        &self.ifname
    }

    /// Connects a PPP channel to this unit (`PPPIOCATTCHAN` followed by
    /// `PPPIOCCONNECT`).
    ///
    /// The returned [`PppChannel`] must stay alive for as long as the channel
    /// should remain connected to the unit.
    pub fn connect_channel(
        &self,
        socket: &PppSocket,
    ) -> crate::Result<PppChannel> {
        let mut channel: libc::c_int = socket.channel_index()?;
        let fd: OwnedFd = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/ppp")?
            .into();
        // SAFETY: both ioctls read one `c_int` through the pointer.
        let rc =
            unsafe { libc::ioctl(fd.as_raw_fd(), PPPIOCATTCHAN, &mut channel) };
        if rc == -1 {
            return Err(io::Error::last_os_error().into());
        }
        let mut unit: libc::c_int = self.index;
        // SAFETY: as above.
        let rc =
            unsafe { libc::ioctl(fd.as_raw_fd(), PPPIOCCONNECT, &mut unit) };
        if rc == -1 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(PppChannel { fd })
    }
}

impl AsFd for PppUnit {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for PppUnit {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

/// A PPP channel attached to a [`PppUnit`]; dropping it disconnects the
/// channel from the unit (`PPPIOCDISCONN`), so the channel can be connected
/// to another unit while its [`PppSocket`] lives on. Closing the descriptor
/// alone would leave the channel connected.
#[derive(Debug)]
pub struct PppChannel {
    fd: OwnedFd,
}

impl Drop for PppChannel {
    fn drop(&mut self) {
        // Best effort: the kernel also disconnects the channel when the
        // `PppSocket` is released, and a failure here cannot be reported.
        // SAFETY: the ioctl takes no argument.
        unsafe {
            libc::ioctl(self.fd.as_raw_fd(), PPPIOCDISCONN);
        }
    }
}

impl AsFd for PppChannel {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for PppChannel {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

fn v2_id(id: u32) -> crate::Result<u16> {
    u16::try_from(id).map_err(|_| crate::Error::V2IdTooLarge(id))
}

/// Builds the packed `sockaddr_pppol2tp` (L2TPv2) or `sockaddr_pppol2tpv3`
/// (L2TPv3) address. The kernel reads only the protocol, the descriptor and
/// the identifiers; the IPv4 variants serve both address families.
fn sockaddr_pppol2tp(
    version: L2tpVersion,
    tunnel_id: TunnelId,
    peer_tunnel_id: TunnelId,
    session_id: SessionId,
    peer_session_id: SessionId,
) -> crate::Result<Vec<u8>> {
    let len = match version {
        L2tpVersion::V2 => SOCKADDR_PPPOL2TP_LEN,
        L2tpVersion::V3 => SOCKADDR_PPPOL2TPV3_LEN,
    };
    let mut buf = vec![0u8; len];
    buf[0..2].copy_from_slice(&(libc::AF_PPPOX as u16).to_ne_bytes());
    buf[2..6].copy_from_slice(&(PX_PROTO_OL2TP as u32).to_ne_bytes());
    // `pppol2tp*_addr`: pid, fd, sockaddr_in, then the identifiers. The
    // descriptor is `-1`: the tunnel already exists.
    buf[10..14].copy_from_slice(&(-1i32).to_ne_bytes());
    let ids = 6 + 4 + 4 + 16;
    match version {
        L2tpVersion::V2 => {
            buf[ids..ids + 2]
                .copy_from_slice(&v2_id(tunnel_id.0)?.to_ne_bytes());
            buf[ids + 2..ids + 4]
                .copy_from_slice(&v2_id(session_id.0)?.to_ne_bytes());
            buf[ids + 4..ids + 6]
                .copy_from_slice(&v2_id(peer_tunnel_id.0)?.to_ne_bytes());
            buf[ids + 6..ids + 8]
                .copy_from_slice(&v2_id(peer_session_id.0)?.to_ne_bytes());
        }
        L2tpVersion::V3 => {
            buf[ids..ids + 4].copy_from_slice(&tunnel_id.0.to_ne_bytes());
            buf[ids + 4..ids + 8].copy_from_slice(&session_id.0.to_ne_bytes());
            buf[ids + 8..ids + 12]
                .copy_from_slice(&peer_tunnel_id.0.to_ne_bytes());
            buf[ids + 12..ids + 16]
                .copy_from_slice(&peer_session_id.0.to_ne_bytes());
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_requests_match_the_kernel_headers() {
        // Values of `linux/ppp-ioctl.h` for each `_IOC` encoding.
        #[cfg(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64",
        ))]
        let expected: [u32; 5] = [
            0x4004_7437,
            0x8004_7438,
            0x2000_7439,
            0x8004_743a,
            0xc004_743e,
        ];
        #[cfg(not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64",
        )))]
        let expected: [u32; 5] = [
            0x8004_7437,
            0x4004_7438,
            0x0000_7439,
            0x4004_743a,
            0xc004_743e,
        ];
        let actual = [
            PPPIOCGCHAN,
            PPPIOCATTCHAN,
            PPPIOCDISCONN,
            PPPIOCCONNECT,
            PPPIOCNEWUNIT,
        ];
        assert_eq!(actual.map(|v| v as u32), expected);
    }

    #[test]
    fn sockaddr_layouts_match_the_kernel() {
        let v3 = sockaddr_pppol2tp(
            L2tpVersion::V3,
            TunnelId(0x0102_0304),
            TunnelId(0x0506_0708),
            SessionId(0x090a_0b0c),
            SessionId(0x0d0e_0f10),
        )
        .unwrap();
        assert_eq!(v3.len(), SOCKADDR_PPPOL2TPV3_LEN);
        assert_eq!(v3[0..2], (libc::AF_PPPOX as u16).to_ne_bytes());
        assert_eq!(v3[2..6], 1u32.to_ne_bytes());
        assert_eq!(v3[10..14], (-1i32).to_ne_bytes());
        assert_eq!(v3[30..34], 0x0102_0304u32.to_ne_bytes());
        assert_eq!(v3[34..38], 0x090a_0b0cu32.to_ne_bytes());
        assert_eq!(v3[38..42], 0x0506_0708u32.to_ne_bytes());
        assert_eq!(v3[42..46], 0x0d0e_0f10u32.to_ne_bytes());

        let v2 = sockaddr_pppol2tp(
            L2tpVersion::V2,
            TunnelId(1),
            TunnelId(2),
            SessionId(3),
            SessionId(4),
        )
        .unwrap();
        assert_eq!(v2.len(), SOCKADDR_PPPOL2TP_LEN);
        assert_eq!(v2[30..32], 1u16.to_ne_bytes());
        assert_eq!(v2[32..34], 3u16.to_ne_bytes());
        assert_eq!(v2[34..36], 2u16.to_ne_bytes());
        assert_eq!(v2[36..38], 4u16.to_ne_bytes());

        assert!(matches!(
            sockaddr_pppol2tp(
                L2tpVersion::V2,
                TunnelId(0x1_0000),
                TunnelId(2),
                SessionId(3),
                SessionId(4),
            ),
            Err(crate::Error::V2IdTooLarge(0x1_0000))
        ));
    }

    #[test]
    fn connecting_to_a_missing_tunnel_is_reported() {
        // Needs the l2tp_ppp module; without it the socket cannot be created.
        match PppSocket::connect(
            L2tpVersion::V3,
            TunnelId(0xfffe_0001),
            TunnelId(0xfffe_0002),
            SessionId(1),
            SessionId(2),
        ) {
            Ok(_) => panic!("a missing tunnel cannot be attached"),
            Err(crate::Error::Io(e)) => {
                let errno = e.raw_os_error();
                assert!(
                    errno == Some(libc::ENOENT)
                        || errno == Some(libc::EAFNOSUPPORT)
                        || errno == Some(libc::EPROTONOSUPPORT)
                        || errno == Some(libc::EPERM)
                        || errno == Some(libc::EACCES),
                    "{e}"
                );
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
}

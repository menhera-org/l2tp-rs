use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::{IfName, IpEndpoint, UdpEndpoint};

const AF_L2TPIP: libc::c_int = 28;
const IPPROTO_L2TP: libc::c_int = 115;

/// Owned tunnel socket used by managed tunnels (`L2TP_ATTR_FD`).
///
/// Dropping this type closes the file descriptor.
pub struct TunnelSocket {
    fd: OwnedFd,
    encap: SocketEncap,
    family: SocketFamily,
}

enum SocketEncap {
    Udp,
    Ip,
}

#[derive(Clone, Copy)]
enum SocketFamily {
    V4,
    V6,
}

impl SocketFamily {
    fn from_udp(endpoint: &UdpEndpoint) -> Self {
        match endpoint {
            UdpEndpoint::V4(_) => Self::V4,
            UdpEndpoint::V6(_) => Self::V6,
        }
    }

    fn from_ip(endpoint: &IpEndpoint) -> Self {
        match endpoint {
            IpEndpoint::V4(_) => Self::V4,
            IpEndpoint::V6(_) => Self::V6,
        }
    }

    fn ip_version(self) -> u8 {
        match self {
            Self::V4 => 4,
            Self::V6 => 6,
        }
    }
}

#[repr(C)]
struct SockaddrL2tpIp {
    l2tp_family: libc::sa_family_t,
    l2tp_unused: u16,
    l2tp_addr: libc::in_addr,
    l2tp_conn_id: u32,
    _pad: [u8; 4],
}

#[repr(C)]
struct SockaddrL2tpIp6 {
    l2tp_family: libc::sa_family_t,
    l2tp_unused: u16,
    l2tp_flowinfo: u32,
    l2tp_addr: libc::in6_addr,
    l2tp_scope_id: u32,
    l2tp_conn_id: u32,
}

enum SockAddr {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
    L2tpV4(SockaddrL2tpIp),
    L2tpV6(SockaddrL2tpIp6),
}

impl SockAddr {
    fn as_ptr(&self) -> *const libc::sockaddr {
        match self {
            Self::V4(v) => v as *const libc::sockaddr_in as *const libc::sockaddr,
            Self::V6(v) => v as *const libc::sockaddr_in6 as *const libc::sockaddr,
            Self::L2tpV4(v) => v as *const SockaddrL2tpIp as *const libc::sockaddr,
            Self::L2tpV6(v) => v as *const SockaddrL2tpIp6 as *const libc::sockaddr,
        }
    }

    fn len(&self) -> libc::socklen_t {
        match self {
            Self::V4(_) => size_of::<libc::sockaddr_in>() as libc::socklen_t,
            Self::V6(_) => size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            Self::L2tpV4(_) => size_of::<SockaddrL2tpIp>() as libc::socklen_t,
            Self::L2tpV6(_) => size_of::<SockaddrL2tpIp6>() as libc::socklen_t,
        }
    }
}

impl TunnelSocket {
    /// Creates and connects a UDP socket for an L2TP tunnel.
    ///
    /// If `device` is provided, `SO_BINDTODEVICE` is applied before bind/connect.
    pub fn udp(
        local: &UdpEndpoint,
        remote: &UdpEndpoint,
        device: Option<&IfName>,
    ) -> crate::Result<Self> {
        if local.ip_version() != remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }

        let family = match local {
            UdpEndpoint::V4(_) => libc::AF_INET,
            UdpEndpoint::V6(_) => libc::AF_INET6,
        };

        let fd = socket(family, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;

        if let Some(device) = device {
            set_bind_to_device(fd.as_raw_fd(), device)?;
        }

        let local_addr = udp_sockaddr(local);
        bind(fd.as_raw_fd(), &local_addr)?;

        let remote_addr = udp_sockaddr(remote);
        connect(fd.as_raw_fd(), &remote_addr)?;

        Ok(Self {
            fd,
            encap: SocketEncap::Udp,
            family: SocketFamily::from_udp(local),
        })
    }

    /// Creates and connects an IP-encapsulated L2TP socket.
    ///
    /// The local bind uses `tunnel_id` as `l2tp_conn_id`; the remote connect
    /// uses conn_id `0`.
    pub fn ip(
        local: &IpEndpoint,
        remote: &IpEndpoint,
        device: Option<&IfName>,
        tunnel_id: u32,
    ) -> crate::Result<Self> {
        if local.ip_version() != remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }

        let family = match local {
            IpEndpoint::V4(_) => AF_L2TPIP,
            IpEndpoint::V6(_) => libc::AF_INET6,
        };

        let fd = socket(family, libc::SOCK_DGRAM, IPPROTO_L2TP)?;

        if let Some(device) = device {
            set_bind_to_device(fd.as_raw_fd(), device)?;
        }

        let local_addr = l2tp_sockaddr(local, tunnel_id);
        bind(fd.as_raw_fd(), &local_addr)?;

        let remote_addr = l2tp_sockaddr(remote, 0);
        connect(fd.as_raw_fd(), &remote_addr)?;

        Ok(Self {
            fd,
            encap: SocketEncap::Ip,
            family: SocketFamily::from_ip(local),
        })
    }

    /// Applies `SO_BINDTODEVICE` on this socket.
    pub fn bind_to_device(&self, device: &IfName) -> crate::Result<()> {
        set_bind_to_device(self.fd.as_raw_fd(), device)
    }

    /// Sets `IPV6_DONTFRAG` for this socket.
    pub fn set_ipv6_dontfrag(&self, dontfrag: bool) -> crate::Result<()> {
        let value: libc::c_int = if dontfrag { 1 } else { 0 };
        // SAFETY: `value` is a valid pointer to a `c_int`, and `self.fd` is an
        // open socket descriptor owned by this struct.
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_DONTFRAG,
                (&value as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if rc == -1 {
            let err = std::io::Error::last_os_error();
            return Err(crate::Error::KernelError {
                code: err.raw_os_error().unwrap_or(libc::EINVAL),
                message: err.to_string(),
            });
        }

        Ok(())
    }

    /// Reconnects a managed UDP tunnel socket to a new remote endpoint.
    pub fn reconnect_udp(&self, new_remote: &UdpEndpoint) -> crate::Result<()> {
        if let SocketEncap::Ip = self.encap {
            return Err(crate::Error::UnmanagedSocket);
        }
        if self.family.ip_version() != new_remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }

        let remote_addr = udp_sockaddr(new_remote);
        connect(self.fd.as_raw_fd(), &remote_addr)
    }

    /// Reconnects a managed IP tunnel socket to a new remote endpoint.
    pub fn reconnect_ip(&self, new_remote: &IpEndpoint) -> crate::Result<()> {
        if let SocketEncap::Udp = self.encap {
            return Err(crate::Error::UnmanagedSocket);
        }
        if self.family.ip_version() != new_remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }

        let remote_addr = l2tp_sockaddr(new_remote, 0);
        connect(self.fd.as_raw_fd(), &remote_addr)
    }

    /// Returns the current local UDP socket address.
    ///
    /// This is only valid for UDP-encapsulated managed sockets.
    pub fn local_addr_udp(&self) -> crate::Result<UdpEndpoint> {
        if let SocketEncap::Ip = self.encap {
            return Err(crate::Error::UnmanagedSocket);
        }

        // SAFETY: zero-initialization is valid for `sockaddr_storage`.
        let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
        let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        // SAFETY: storage points to valid writable memory with size `len`, and
        // `self.fd` is an open socket descriptor.
        let rc = unsafe {
            libc::getsockname(
                self.fd.as_raw_fd(),
                (&mut storage as *mut libc::sockaddr_storage).cast(),
                &mut len,
            )
        };
        if rc == -1 {
            return Err(std::io::Error::last_os_error().into());
        }

        match i32::from(storage.ss_family) {
            libc::AF_INET => {
                // SAFETY: kernel reported AF_INET, so interpreting as
                // `sockaddr_in` is valid.
                let sa = unsafe {
                    *(&storage as *const libc::sockaddr_storage as *const libc::sockaddr_in)
                };
                let ip = Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
                let port = u16::from_be(sa.sin_port);
                Ok(UdpEndpoint::V4(std::net::SocketAddrV4::new(ip, port)))
            }
            libc::AF_INET6 => {
                // SAFETY: kernel reported AF_INET6, so interpreting as
                // `sockaddr_in6` is valid.
                let sa = unsafe {
                    *(&storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6)
                };
                let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
                let port = u16::from_be(sa.sin6_port);
                Ok(UdpEndpoint::V6(std::net::SocketAddrV6::new(
                    ip,
                    port,
                    sa.sin6_flowinfo,
                    sa.sin6_scope_id,
                )))
            }
            family => Err(crate::Error::KernelError {
                code: libc::EAFNOSUPPORT,
                message: format!("unexpected socket family {family}"),
            }),
        }
    }
}

impl AsRawFd for TunnelSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

fn socket(domain: libc::c_int, ty: libc::c_int, protocol: libc::c_int) -> crate::Result<OwnedFd> {
    // SAFETY: parameters are passed directly to libc; on success this returns
    // a newly owned fd which is wrapped in `OwnedFd` exactly once.
    let fd = unsafe { libc::socket(domain, ty, protocol) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error().into());
    }

    // SAFETY: `fd` is a valid newly-created descriptor from `socket` above.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(owned)
}

fn bind(fd: RawFd, addr: &SockAddr) -> crate::Result<()> {
    // SAFETY: `addr` points to a properly initialized sockaddr value matching
    // `addr.len()`, and `fd` is assumed to be an open socket descriptor.
    let rc = unsafe { libc::bind(fd, addr.as_ptr(), addr.len()) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn connect(fd: RawFd, addr: &SockAddr) -> crate::Result<()> {
    // SAFETY: `addr` points to a properly initialized sockaddr value matching
    // `addr.len()`, and `fd` is assumed to be an open socket descriptor.
    let rc = unsafe { libc::connect(fd, addr.as_ptr(), addr.len()) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn set_bind_to_device(fd: RawFd, device: &IfName) -> crate::Result<()> {
    let bytes = device.as_str().as_bytes();
    // SAFETY: `bytes` points to readable memory of length `bytes.len()`, and
    // `fd` is assumed to be an open socket descriptor.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            bytes.as_ptr().cast(),
            bytes.len() as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn udp_sockaddr(endpoint: &UdpEndpoint) -> SockAddr {
    match endpoint {
        UdpEndpoint::V4(addr) => SockAddr::V4(libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: addr.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            },
            sin_zero: [0; 8],
        }),
        UdpEndpoint::V6(addr) => SockAddr::V6(libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: addr.port().to_be(),
            sin6_flowinfo: addr.flowinfo(),
            sin6_addr: libc::in6_addr {
                s6_addr: addr.ip().octets(),
            },
            sin6_scope_id: addr.scope_id(),
        }),
    }
}

fn l2tp_sockaddr(endpoint: &IpEndpoint, conn_id: u32) -> SockAddr {
    match endpoint {
        IpEndpoint::V4(addr) => SockAddr::L2tpV4(SockaddrL2tpIp {
            l2tp_family: AF_L2TPIP as libc::sa_family_t,
            l2tp_unused: 0,
            l2tp_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(addr.octets()),
            },
            l2tp_conn_id: conn_id,
            _pad: [0; 4],
        }),
        IpEndpoint::V6(addr) => SockAddr::L2tpV6(SockaddrL2tpIp6 {
            l2tp_family: libc::AF_INET6 as libc::sa_family_t,
            l2tp_unused: 0,
            l2tp_flowinfo: 0,
            l2tp_addr: libc::in6_addr {
                s6_addr: addr.octets(),
            },
            l2tp_scope_id: 0,
            l2tp_conn_id: conn_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::mem::size_of;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::time::Duration;

    fn as_v4(addr: SocketAddr) -> SocketAddrV4 {
        match addr {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(v6) => panic!("expected IPv4 address, got {v6}"),
        }
    }

    fn bind_v4_local() -> Option<UdpSocket> {
        match UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
            Ok(s) => Some(s),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => None,
            Err(e) => panic!("failed to bind local UDP socket: {e}"),
        }
    }

    #[test]
    fn udp_constructor_rejects_family_mismatch() {
        let local = UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1701));
        let remote = UdpEndpoint::V6(std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1701, 0, 0));

        let err = match TunnelSocket::udp(&local, &remote, None) {
            Ok(_) => panic!("expected address family mismatch"),
            Err(e) => e,
        };
        assert!(matches!(err, crate::Error::AddressFamilyMismatch));
    }

    #[test]
    fn ip_constructor_rejects_family_mismatch() {
        let local = IpEndpoint::V4(Ipv4Addr::LOCALHOST);
        let remote = IpEndpoint::V6(Ipv6Addr::LOCALHOST);

        let err = match TunnelSocket::ip(&local, &remote, None, 42) {
            Ok(_) => panic!("expected address family mismatch"),
            Err(e) => e,
        };
        assert!(matches!(err, crate::Error::AddressFamilyMismatch));
    }

    #[test]
    fn udp_local_addr_and_reconnect_work() {
        let Some(receiver1) = bind_v4_local() else {
            return;
        };
        let Some(receiver2) = bind_v4_local() else {
            return;
        };
        receiver1
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        receiver2
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();

        let receiver1_addr = as_v4(receiver1.local_addr().unwrap());
        let receiver2_addr = as_v4(receiver2.local_addr().unwrap());

        let tunnel_socket = match TunnelSocket::udp(
            &UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            &UdpEndpoint::V4(receiver1_addr),
            None,
        ) {
            Ok(s) => s,
            Err(crate::Error::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                return;
            }
            Err(e) => panic!("unexpected tunnel socket error: {e:?}"),
        };

        let local = tunnel_socket.local_addr_udp().unwrap();
        match local {
            UdpEndpoint::V4(v4) => assert_ne!(v4.port(), 0),
            UdpEndpoint::V6(v6) => panic!("unexpected v6 local address: {v6}"),
        }

        // SAFETY: the file descriptor is a valid connected UDP socket and
        // buffer pointers are valid for their length.
        let rc = unsafe { libc::send(tunnel_socket.as_raw_fd(), b"one".as_ptr().cast(), 3, 0) };
        assert_eq!(rc, 3);

        let mut buf = [0u8; 64];
        let (n1, _) = receiver1.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n1], b"one");

        tunnel_socket
            .reconnect_udp(&UdpEndpoint::V4(receiver2_addr))
            .unwrap();

        // SAFETY: the file descriptor is a valid connected UDP socket and
        // buffer pointers are valid for their length.
        let rc = unsafe { libc::send(tunnel_socket.as_raw_fd(), b"two".as_ptr().cast(), 3, 0) };
        assert_eq!(rc, 3);

        let (n2, _) = receiver2.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n2], b"two");

        let recv_again = receiver1.recv_from(&mut buf);
        assert!(matches!(
            recv_again,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut
        ));
    }

    #[test]
    fn reconnect_udp_and_local_addr_reject_unmanaged_socket() {
        let fd = match socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
            Ok(fd) => fd,
            Err(crate::Error::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                return;
            }
            Err(e) => panic!("unexpected socket create error: {e:?}"),
        };
        let sock = TunnelSocket {
            fd,
            encap: SocketEncap::Ip,
            family: SocketFamily::V4,
        };

        let err = sock
            .reconnect_udp(&UdpEndpoint::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                1701,
            )))
            .unwrap_err();
        assert!(matches!(err, crate::Error::UnmanagedSocket));

        let err = sock.local_addr_udp().unwrap_err();
        assert!(matches!(err, crate::Error::UnmanagedSocket));
    }

    #[test]
    fn set_ipv6_dontfrag_on_ipv4_socket_returns_kernel_error() {
        let Some(receiver) = bind_v4_local() else {
            return;
        };
        let receiver_addr = as_v4(receiver.local_addr().unwrap());

        let sock = match TunnelSocket::udp(
            &UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            &UdpEndpoint::V4(receiver_addr),
            None,
        ) {
            Ok(s) => s,
            Err(crate::Error::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                return;
            }
            Err(e) => panic!("unexpected tunnel socket error: {e:?}"),
        };

        let err = sock.set_ipv6_dontfrag(true).unwrap_err();
        assert!(matches!(err, crate::Error::KernelError { .. }));
    }

    #[test]
    fn reconnect_udp_rejects_family_mismatch_with_clear_error() {
        let Some(receiver) = bind_v4_local() else {
            return;
        };
        let receiver_addr = as_v4(receiver.local_addr().unwrap());

        let sock = match TunnelSocket::udp(
            &UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            &UdpEndpoint::V4(receiver_addr),
            None,
        ) {
            Ok(s) => s,
            Err(crate::Error::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                return;
            }
            Err(e) => panic!("unexpected tunnel socket error: {e:?}"),
        };

        let err = sock
            .reconnect_udp(&UdpEndpoint::V6(std::net::SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                1701,
                0,
                0,
            )))
            .unwrap_err();
        assert!(matches!(err, crate::Error::AddressFamilyMismatch));
    }

    #[test]
    fn reconnect_ip_rejects_udp_socket() {
        let fd = match socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
            Ok(fd) => fd,
            Err(crate::Error::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                return;
            }
            Err(e) => panic!("unexpected socket create error: {e:?}"),
        };
        let sock = TunnelSocket {
            fd,
            encap: SocketEncap::Udp,
            family: SocketFamily::V4,
        };

        let err = sock
            .reconnect_ip(&IpEndpoint::V4(Ipv4Addr::LOCALHOST))
            .unwrap_err();
        assert!(matches!(err, crate::Error::UnmanagedSocket));
    }

    #[test]
    fn reconnect_ip_rejects_family_mismatch_with_clear_error() {
        let fd = match socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
            Ok(fd) => fd,
            Err(crate::Error::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                return;
            }
            Err(e) => panic!("unexpected socket create error: {e:?}"),
        };
        let sock = TunnelSocket {
            fd,
            encap: SocketEncap::Ip,
            family: SocketFamily::V4,
        };

        let err = sock
            .reconnect_ip(&IpEndpoint::V6(Ipv6Addr::LOCALHOST))
            .unwrap_err();
        assert!(matches!(err, crate::Error::AddressFamilyMismatch));
    }

    #[test]
    fn sockaddr_l2tpip_matches_sockaddr_size() {
        assert_eq!(size_of::<SockaddrL2tpIp>(), size_of::<libc::sockaddr>());
    }
}

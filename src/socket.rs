use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::{IfName, IpEndpoint, UdpEndpoint};

const AF_L2TPIP: libc::c_int = 28;
const IPPROTO_L2TP: libc::c_int = 115;

pub struct TunnelSocket {
    fd: OwnedFd,
    encap: SocketEncap,
}

enum SocketEncap {
    Udp,
    Ip,
}

#[repr(C)]
struct SockaddrL2tpIp {
    l2tp_family: libc::sa_family_t,
    l2tp_unused: u16,
    l2tp_addr: libc::in_addr,
    l2tp_conn_id: u32,
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
        })
    }

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
        })
    }

    pub fn bind_to_device(&self, device: &IfName) -> crate::Result<()> {
        set_bind_to_device(self.fd.as_raw_fd(), device)
    }

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

    pub fn reconnect_udp(&self, new_remote: &UdpEndpoint) -> crate::Result<()> {
        if let SocketEncap::Ip = self.encap {
            return Err(crate::Error::UnmanagedSocket);
        }

        let remote_addr = udp_sockaddr(new_remote);
        connect(self.fd.as_raw_fd(), &remote_addr)
    }

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

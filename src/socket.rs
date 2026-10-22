// SPDX-License-Identifier: MIT

use std::{
    mem::{size_of, zeroed},
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{Encapsulation, IfName, IpEndpoint, TunnelId, UdpEndpoint};

const IPPROTO_L2TP: libc::c_int = 115;

/// Owned tunnel socket used by managed tunnels (`L2TP_ATTR_FD`).
///
/// Dropping this type closes the file descriptor.
/// Per the kernel L2TP API, closing the tunnel socket tears down the
/// associated tunnel and sessions.
///
/// The descriptor is created with `SOCK_CLOEXEC`, so child processes do not
/// inherit it and keep the tunnel alive.
#[derive(Debug)]
pub struct TunnelSocket {
    fd: OwnedFd,
    encap: SocketEncap,
    family: SocketFamily,
    /// Interface name that scopes an IP socket, resolved on every reconnect.
    scope: Option<IfName>,
    /// Whether the kernel has pinned the socket to an interface, through a
    /// link-local scope or `SO_BINDTODEVICE`. A link-local peer without a
    /// scope of its own needs that.
    pinned: AtomicBool,
}

#[derive(Debug)]
enum SocketEncap {
    Udp,
    Ip,
}

#[derive(Debug, Clone, Copy)]
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
            IpEndpoint::V6 { .. } => Self::V6,
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
            Self::V4(v) => {
                v as *const libc::sockaddr_in as *const libc::sockaddr
            }
            Self::V6(v) => {
                v as *const libc::sockaddr_in6 as *const libc::sockaddr
            }
            Self::L2tpV4(v) => {
                v as *const SockaddrL2tpIp as *const libc::sockaddr
            }
            Self::L2tpV6(v) => {
                v as *const SockaddrL2tpIp6 as *const libc::sockaddr
            }
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
    /// If `device` is provided, `SO_BINDTODEVICE` is applied before
    /// bind/connect.
    ///
    /// A link-local IPv6 endpoint needs an interface, which the kernel takes
    /// from the [`SocketAddrV6`](std::net::SocketAddrV6) scope ID (see
    /// [`IfName::index`]) or from `device`. A link-local `remote` may omit
    /// its scope ID when `local` or `device` already pins the socket to an
    /// interface. A missing scope is reported as
    /// [`Error::ScopeRequired`](crate::Error::ScopeRequired) before the
    /// socket is created.
    pub fn udp(
        local: &UdpEndpoint,
        remote: &UdpEndpoint,
        device: Option<&IfName>,
    ) -> crate::Result<Self> {
        if local.ip_version() != remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }
        require_udp_scope(local, device.is_some())?;
        require_udp_scope(
            remote,
            device.is_some() || has_link_local_scope(local),
        )?;

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

        // Validation above guarantees that a link-local endpoint came with a
        // scope or a device, each of which pins the socket.
        let pinned =
            device.is_some() || local.is_link_local() || remote.is_link_local();
        Ok(Self {
            fd,
            encap: SocketEncap::Udp,
            family: SocketFamily::from_udp(local),
            scope: None,
            pinned: AtomicBool::new(pinned),
        })
    }

    /// Creates and connects an IP-encapsulated L2TP socket.
    ///
    /// The local bind uses `tunnel_id` as `l2tp_conn_id`, so it must match the
    /// tunnel ID passed to [`L2tpHandle::create_tunnel`]; the remote connect
    /// uses conn_id `0`.
    ///
    /// Link-local IPv6 endpoints need an interface scope
    /// ([`IpEndpoint::v6_scoped`]). The scopes of `local` and `remote` and
    /// the `device` must name the same interface. That name is resolved to
    /// the interface index here and again on every
    /// [`reconnect_ip`](Self::reconnect_ip), so a re-created interface is
    /// picked up. Unlike `device`, a scope does not need `CAP_NET_RAW`.
    ///
    /// [`L2tpHandle::create_tunnel`]: crate::L2tpHandle::create_tunnel
    pub fn ip(
        local: &IpEndpoint,
        remote: &IpEndpoint,
        device: Option<&IfName>,
        tunnel_id: TunnelId,
    ) -> crate::Result<Self> {
        if local.ip_version() != remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }
        let scope =
            unified_scope([local.scope(), remote.scope(), device])?.copied();
        require_scope(local, scope.as_ref(), false)?;
        require_scope(remote, scope.as_ref(), false)?;
        let scope_id = resolve_scope(scope.as_ref())?;

        let family = match local {
            IpEndpoint::V4(_) => libc::AF_INET,
            IpEndpoint::V6 { .. } => libc::AF_INET6,
        };

        let fd = socket(family, libc::SOCK_DGRAM, IPPROTO_L2TP)?;

        if let Some(device) = device {
            set_bind_to_device(fd.as_raw_fd(), device)?;
        }

        let local_addr = l2tp_sockaddr(local, tunnel_id.0, scope_id);
        bind(fd.as_raw_fd(), &local_addr)?;

        let remote_addr = l2tp_sockaddr(remote, 0, scope_id);
        connect(fd.as_raw_fd(), &remote_addr)?;

        // The kernel only pins the socket for a device or a link-local scope.
        let pinned =
            device.is_some() || local.is_link_local() || remote.is_link_local();
        Ok(Self {
            fd,
            encap: SocketEncap::Ip,
            family: SocketFamily::from_ip(local),
            scope,
            pinned: AtomicBool::new(pinned),
        })
    }

    pub(crate) fn configure(
        &self,
        encapsulation: &Encapsulation,
    ) -> crate::Result<()> {
        match (encapsulation, &self.encap) {
            (
                Encapsulation::Udp {
                    local,
                    remote,
                    udp_csum,
                    udp_zero_csum6_tx,
                    udp_zero_csum6_rx,
                },
                SocketEncap::Udp,
            ) => {
                if self.family.ip_version() != local.ip_version()
                    || self.family.ip_version() != remote.ip_version()
                {
                    return Err(crate::Error::AddressFamilyMismatch);
                }
                // SO_NO_CHECK controls IPv4 transmission, including mapped IPv4
                // traffic on a dual-stack IPv6 socket.
                set_socket_bool(
                    self.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NO_CHECK,
                    !udp_csum,
                )?;
                if matches!(self.family, SocketFamily::V6) {
                    set_socket_bool(
                        self.as_raw_fd(),
                        libc::IPPROTO_UDP,
                        libc::UDP_NO_CHECK6_TX,
                        *udp_zero_csum6_tx,
                    )?;
                    set_socket_bool(
                        self.as_raw_fd(),
                        libc::IPPROTO_UDP,
                        libc::UDP_NO_CHECK6_RX,
                        *udp_zero_csum6_rx,
                    )?;
                }
            }
            (Encapsulation::Ip { local, remote }, SocketEncap::Ip) => {
                if self.family.ip_version() != local.ip_version()
                    || self.family.ip_version() != remote.ip_version()
                {
                    return Err(crate::Error::AddressFamilyMismatch);
                }
                // The socket is bound already; the scopes only have to agree.
                unified_scope([
                    local.scope(),
                    remote.scope(),
                    self.scope.as_ref(),
                ])?;
            }
            _ => return Err(crate::Error::EncapsulationMismatch),
        }
        Ok(())
    }

    /// Applies `SO_BINDTODEVICE` on this socket; this requires `CAP_NET_RAW`.
    ///
    /// Afterwards a link-local remote may omit its scope on reconnect.
    pub fn bind_to_device(&self, device: &IfName) -> crate::Result<()> {
        set_bind_to_device(self.fd.as_raw_fd(), device)?;
        self.pinned.store(true, Ordering::Relaxed);
        Ok(())
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
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(())
    }

    /// Reconnects a managed UDP tunnel socket to a new remote endpoint.
    ///
    /// A link-local `new_remote` needs a scope ID unless the socket is
    /// already pinned to an interface by its creation, by
    /// [`bind_to_device`](Self::bind_to_device) or by an earlier scoped
    /// reconnect.
    pub fn reconnect_udp(&self, new_remote: &UdpEndpoint) -> crate::Result<()> {
        if let SocketEncap::Ip = self.encap {
            return Err(crate::Error::EncapsulationMismatch);
        }
        if self.family.ip_version() != new_remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }
        require_udp_scope(new_remote, self.pinned.load(Ordering::Relaxed))?;

        let remote_addr = udp_sockaddr(new_remote);
        connect(self.fd.as_raw_fd(), &remote_addr)?;
        if new_remote.is_link_local() {
            self.pinned.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Reconnects a managed IP tunnel socket to a new remote endpoint.
    ///
    /// A link-local `new_remote` needs an interface scope unless the socket
    /// is already pinned to an interface. The socket's own scope is used when
    /// `new_remote` has none, and the two must agree otherwise. The name is
    /// resolved to the interface index on every call.
    pub fn reconnect_ip(&self, new_remote: &IpEndpoint) -> crate::Result<()> {
        if let SocketEncap::Udp = self.encap {
            return Err(crate::Error::EncapsulationMismatch);
        }
        if self.family.ip_version() != new_remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }
        let scope = unified_scope([new_remote.scope(), self.scope.as_ref()])?;
        require_scope(new_remote, scope, self.pinned.load(Ordering::Relaxed))?;
        let scope_id = resolve_scope(scope)?;

        let remote_addr = l2tp_sockaddr(new_remote, 0, scope_id);
        connect(self.fd.as_raw_fd(), &remote_addr)?;
        if new_remote.is_link_local() {
            self.pinned.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Returns the current local UDP socket address.
    ///
    /// This is only valid for UDP-encapsulated sockets.
    pub fn local_addr_udp(&self) -> crate::Result<UdpEndpoint> {
        if let SocketEncap::Ip = self.encap {
            return Err(crate::Error::EncapsulationMismatch);
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
                    *(&storage as *const libc::sockaddr_storage
                        as *const libc::sockaddr_in)
                };
                let ip = Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
                let port = u16::from_be(sa.sin_port);
                Ok(UdpEndpoint::V4(std::net::SocketAddrV4::new(ip, port)))
            }
            libc::AF_INET6 => {
                // SAFETY: kernel reported AF_INET6, so interpreting as
                // `sockaddr_in6` is valid.
                let sa = unsafe {
                    *(&storage as *const libc::sockaddr_storage
                        as *const libc::sockaddr_in6)
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
            _ => {
                Err(std::io::Error::from_raw_os_error(libc::EAFNOSUPPORT)
                    .into())
            }
        }
    }
}

impl AsRawFd for TunnelSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

fn socket(
    domain: libc::c_int,
    ty: libc::c_int,
    protocol: libc::c_int,
) -> crate::Result<OwnedFd> {
    // SAFETY: parameters are passed directly to libc; on success this returns
    // a newly owned fd which is wrapped in `OwnedFd` exactly once.
    let fd = unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, protocol) };
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

fn set_socket_bool(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    enabled: bool,
) -> crate::Result<()> {
    let value = libc::c_int::from(enabled);
    // SAFETY: value is an initialized c_int and its size is passed exactly.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn set_bind_to_device(fd: RawFd, device: &IfName) -> crate::Result<()> {
    let bytes = device.as_bytes();
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

/// Returns the single interface named by `scopes`, or an error when they
/// disagree.
fn unified_scope<'a>(
    scopes: impl IntoIterator<Item = Option<&'a IfName>>,
) -> crate::Result<Option<&'a IfName>> {
    let mut unified: Option<&IfName> = None;
    for scope in scopes.into_iter().flatten() {
        match unified {
            None => unified = Some(scope),
            Some(expected) if expected != scope => {
                return Err(crate::Error::ScopeMismatch {
                    expected: *expected,
                    found: *scope,
                });
            }
            Some(_) => {}
        }
    }
    Ok(unified)
}

/// The kernel cannot bind or connect a link-local address without an
/// interface, given by a scope or by a socket already pinned to one.
fn require_scope(
    endpoint: &IpEndpoint,
    scope: Option<&IfName>,
    pinned: bool,
) -> crate::Result<()> {
    match endpoint {
        IpEndpoint::V6 { addr, .. }
            if addr.is_unicast_link_local() && scope.is_none() && !pinned =>
        {
            Err(crate::Error::ScopeRequired(*addr))
        }
        _ => Ok(()),
    }
}

/// UDP endpoints carry their scope as the `SocketAddrV6` scope ID.
fn require_udp_scope(
    endpoint: &UdpEndpoint,
    pinned: bool,
) -> crate::Result<()> {
    match endpoint {
        UdpEndpoint::V6(addr)
            if addr.ip().is_unicast_link_local()
                && addr.scope_id() == 0
                && !pinned =>
        {
            Err(crate::Error::ScopeRequired(*addr.ip()))
        }
        _ => Ok(()),
    }
}

/// Whether binding or connecting `endpoint` pins the socket to an interface.
fn has_link_local_scope(endpoint: &UdpEndpoint) -> bool {
    matches!(
        endpoint,
        UdpEndpoint::V6(addr)
            if addr.ip().is_unicast_link_local() && addr.scope_id() != 0
    )
}

/// Resolves the scope to the interface index at the time of use, so a
/// re-created interface keeps working.
fn resolve_scope(scope: Option<&IfName>) -> crate::Result<u32> {
    match scope {
        Some(name) => name.index(),
        None => Ok(0),
    }
}

fn l2tp_sockaddr(
    endpoint: &IpEndpoint,
    conn_id: u32,
    scope_id: u32,
) -> SockAddr {
    match endpoint {
        IpEndpoint::V4(addr) => SockAddr::L2tpV4(SockaddrL2tpIp {
            l2tp_family: libc::AF_INET as libc::sa_family_t,
            l2tp_unused: 0,
            l2tp_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(addr.octets()),
            },
            l2tp_conn_id: conn_id,
            _pad: [0; 4],
        }),
        IpEndpoint::V6 { addr, .. } => SockAddr::L2tpV6(SockaddrL2tpIp6 {
            l2tp_family: libc::AF_INET6 as libc::sa_family_t,
            l2tp_unused: 0,
            l2tp_flowinfo: 0,
            l2tp_addr: libc::in6_addr {
                s6_addr: addr.octets(),
            },
            l2tp_scope_id: scope_id,
            l2tp_conn_id: conn_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        mem::size_of,
        net::{
            Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
            UdpSocket,
        },
        time::Duration,
    };

    use super::*;

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

    fn socket_option(
        fd: RawFd,
        level: libc::c_int,
        option: libc::c_int,
    ) -> libc::c_int {
        let mut value = 0 as libc::c_int;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: value is writable for len bytes and fd is an open socket.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                option,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        value
    }

    #[test]
    fn managed_udp_checksum_options_follow_configuration() {
        for family in [SocketFamily::V4, SocketFamily::V6] {
            let domain = match family {
                SocketFamily::V4 => libc::AF_INET,
                SocketFamily::V6 => libc::AF_INET6,
            };
            let fd = match socket(domain, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
                Ok(fd) => fd,
                Err(crate::Error::Io(e))
                    if e.kind() == io::ErrorKind::PermissionDenied =>
                {
                    return;
                }
                Err(e) => panic!("{e}"),
            };
            let sock = TunnelSocket {
                fd,
                encap: SocketEncap::Udp,
                family,
                scope: None,
                pinned: AtomicBool::new(false),
            };
            let endpoint = match family {
                SocketFamily::V4 => UdpEndpoint::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    1701,
                )),
                SocketFamily::V6 => {
                    UdpEndpoint::V6(std::net::SocketAddrV6::new(
                        Ipv6Addr::LOCALHOST,
                        1701,
                        0,
                        0,
                    ))
                }
            };
            for enabled in [true, false] {
                sock.configure(&Encapsulation::Udp {
                    local: endpoint.clone(),
                    remote: endpoint.clone(),
                    udp_csum: !enabled,
                    udp_zero_csum6_tx: enabled,
                    udp_zero_csum6_rx: enabled,
                })
                .unwrap();
                assert_eq!(
                    socket_option(
                        sock.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_NO_CHECK
                    ),
                    i32::from(enabled)
                );
                if matches!(family, SocketFamily::V6) {
                    assert_eq!(
                        socket_option(
                            sock.as_raw_fd(),
                            libc::IPPROTO_UDP,
                            libc::UDP_NO_CHECK6_TX
                        ),
                        i32::from(enabled)
                    );
                    assert_eq!(
                        socket_option(
                            sock.as_raw_fd(),
                            libc::IPPROTO_UDP,
                            libc::UDP_NO_CHECK6_RX
                        ),
                        i32::from(enabled)
                    );
                }
            }
            assert!(matches!(
                sock.configure(&Encapsulation::Ip {
                    local: IpEndpoint::V4(Ipv4Addr::LOCALHOST),
                    remote: IpEndpoint::V4(Ipv4Addr::LOCALHOST),
                }),
                Err(crate::Error::EncapsulationMismatch)
            ));
        }
    }

    #[test]
    fn ipv4_l2tp_sockaddr_uses_inet_family() {
        let SockAddr::L2tpV4(addr) =
            l2tp_sockaddr(&IpEndpoint::V4(Ipv4Addr::LOCALHOST), 42, 0)
        else {
            panic!("expected IPv4 L2TP address");
        };
        assert_eq!(i32::from(addr.l2tp_family), libc::AF_INET);
        assert_eq!(addr.l2tp_conn_id, 42);
    }

    #[test]
    fn ipv6_l2tp_sockaddr_carries_scope_and_conn_id() {
        let SockAddr::L2tpV6(addr) =
            l2tp_sockaddr(&IpEndpoint::v6(Ipv6Addr::LOCALHOST), 42, 7)
        else {
            panic!("expected IPv6 L2TP address");
        };
        assert_eq!(i32::from(addr.l2tp_family), libc::AF_INET6);
        assert_eq!(addr.l2tp_addr.s6_addr, Ipv6Addr::LOCALHOST.octets());
        assert_eq!(addr.l2tp_scope_id, 7);
        assert_eq!(addr.l2tp_conn_id, 42);
    }

    #[test]
    fn link_local_ip_endpoints_require_one_scope() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let eth0 = IfName::new("eth0").unwrap();
        let eth1 = IfName::new("eth1").unwrap();

        // Validation runs before any socket is created.
        let err = TunnelSocket::ip(
            &IpEndpoint::v6(link_local),
            &IpEndpoint::v6(Ipv6Addr::LOCALHOST),
            None,
            TunnelId(1),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            crate::Error::ScopeRequired(addr) if addr == link_local
        ));

        let err = TunnelSocket::ip(
            &IpEndpoint::v6(Ipv6Addr::UNSPECIFIED),
            &IpEndpoint::v6(link_local),
            None,
            TunnelId(1),
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::ScopeRequired(_)));

        let err = TunnelSocket::ip(
            &IpEndpoint::v6_scoped(link_local, eth0),
            &IpEndpoint::v6_scoped(link_local, eth1),
            None,
            TunnelId(1),
        )
        .unwrap_err();
        assert!(matches!(
            &err,
            crate::Error::ScopeMismatch { expected, found }
                if *expected == eth0 && *found == eth1
        ));

        let err = TunnelSocket::ip(
            &IpEndpoint::v6_scoped(link_local, eth0),
            &IpEndpoint::v6(link_local),
            Some(&eth1),
            TunnelId(1),
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::ScopeMismatch { .. }));

        // A scope that names no interface fails before the socket is created.
        let missing = IfName::new("l2tp-no-such0").unwrap();
        let err = TunnelSocket::ip(
            &IpEndpoint::v6_scoped(link_local, missing),
            &IpEndpoint::v6(link_local),
            None,
            TunnelId(1),
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV));
    }

    #[test]
    fn configure_checks_ip_scopes_against_the_socket() {
        let fd =
            match socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
                Ok(fd) => fd,
                Err(crate::Error::Io(e))
                    if e.kind() == io::ErrorKind::PermissionDenied =>
                {
                    return;
                }
                Err(e) => panic!("unexpected socket create error: {e:?}"),
            };
        let lo = IfName::new("lo").unwrap();
        let sock = TunnelSocket {
            fd,
            encap: SocketEncap::Ip,
            family: SocketFamily::V6,
            scope: Some(lo),
            pinned: AtomicBool::new(false),
        };
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        sock.configure(&Encapsulation::Ip {
            local: IpEndpoint::v6_scoped(link_local, lo),
            remote: IpEndpoint::v6(link_local),
        })
        .unwrap();
        let err = sock
            .configure(&Encapsulation::Ip {
                local: IpEndpoint::v6_scoped(
                    link_local,
                    IfName::new("eth0").unwrap(),
                ),
                remote: IpEndpoint::v6(link_local),
            })
            .unwrap_err();
        assert!(matches!(err, crate::Error::ScopeMismatch { .. }));

        // Reconnecting to another interface is rejected the same way, and a
        // link-local peer still needs a scope on an unscoped socket.
        let err = sock
            .reconnect_ip(&IpEndpoint::v6_scoped(
                link_local,
                IfName::new("eth0").unwrap(),
            ))
            .unwrap_err();
        assert!(matches!(err, crate::Error::ScopeMismatch { .. }));
        let unscoped = TunnelSocket {
            scope: None,
            ..sock
        };
        let err = unscoped
            .reconnect_ip(&IpEndpoint::v6(link_local))
            .unwrap_err();
        assert!(matches!(err, crate::Error::ScopeRequired(_)));
    }

    /// Returns an interface with a link-local address, when the host has one.
    fn link_local_interface() -> Option<(Ipv6Addr, IfName)> {
        let table = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
        table.lines().find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [hex, _index, _prefix, scope, _flags, name] = fields[..] else {
                return None;
            };
            // IPV6_ADDR_LINKLOCAL scope value.
            if scope != "20" || hex.len() != 32 {
                return None;
            }
            let mut octets = [0u8; 16];
            for (i, octet) in octets.iter_mut().enumerate() {
                *octet = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
            }
            Some((Ipv6Addr::from(octets), IfName::new(name).ok()?))
        })
    }

    #[test]
    fn link_local_ip_socket_binds_to_the_scoped_interface() {
        let Some((addr, ifname)) = link_local_interface() else {
            return;
        };
        let local = IpEndpoint::v6_scoped(addr, ifname);
        // The peer takes its scope from the local endpoint.
        let remote =
            IpEndpoint::v6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1234));
        let tunnel_id = TunnelId(0x4c32_5450 ^ std::process::id());
        let sock = match TunnelSocket::ip(&local, &remote, None, tunnel_id) {
            Ok(sock) => sock,
            // No l2tp_ip6 support, no permission, or no usable link here.
            Err(crate::Error::Io(e))
                if e.kind() == io::ErrorKind::PermissionDenied
                    || matches!(
                        e.raw_os_error(),
                        Some(
                            libc::EPROTONOSUPPORT
                                | libc::ESOCKTNOSUPPORT
                                | libc::EAFNOSUPPORT
                                | libc::EADDRINUSE
                                | libc::EADDRNOTAVAIL
                                | libc::ENETUNREACH
                        )
                    ) =>
            {
                return;
            }
            Err(e) => panic!("unexpected link-local socket error: {e:?}"),
        };
        assert_eq!(sock.scope, Some(ifname));
        assert!(sock.pinned.load(Ordering::Relaxed));

        // SAFETY: zero-initialization is valid for this plain C struct.
        let mut bound: SockaddrL2tpIp6 = unsafe { zeroed() };
        let mut len = size_of::<SockaddrL2tpIp6>() as libc::socklen_t;
        // SAFETY: `bound` is writable for `len` bytes and the fd is open.
        let rc = unsafe {
            libc::getsockname(
                sock.as_raw_fd(),
                (&mut bound as *mut SockaddrL2tpIp6).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        assert_eq!(bound.l2tp_scope_id, ifname.index().unwrap());
        assert_eq!(bound.l2tp_conn_id, tunnel_id.0);

        // Reconnecting resolves the socket's own scope again.
        sock.reconnect_ip(&IpEndpoint::v6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 0x5678,
        )))
        .unwrap();
    }

    #[test]
    fn udp_link_local_endpoints_require_a_scope() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let any =
            UdpEndpoint::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
        let unscoped =
            UdpEndpoint::V6(SocketAddrV6::new(link_local, 1701, 0, 0));
        let scoped = UdpEndpoint::V6(SocketAddrV6::new(link_local, 1701, 0, 1));
        let lo = IfName::new("lo").unwrap();

        // Validation runs before any socket is created.
        let err = TunnelSocket::udp(&unscoped, &any, None).unwrap_err();
        assert!(matches!(
            err,
            crate::Error::ScopeRequired(addr) if addr == link_local
        ));
        let err = TunnelSocket::udp(&any, &unscoped, None).unwrap_err();
        assert!(matches!(err, crate::Error::ScopeRequired(_)));

        // A device or a scoped local endpoint pins the socket, so the peer
        // may omit its scope. These attempts reach the kernel, which may
        // reject them for other reasons here.
        for (local, remote, device) in [
            (&unscoped, &any, Some(&lo)),
            (&any, &unscoped, Some(&lo)),
            (&scoped, &unscoped, None),
        ] {
            match TunnelSocket::udp(local, remote, device) {
                Ok(_) | Err(crate::Error::Io(_)) => {}
                Err(e) => panic!("unexpected validation error: {e:?}"),
            }
        }
    }

    #[test]
    fn reconnect_udp_requires_a_scope_on_an_unpinned_socket() {
        let fd =
            match socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
                Ok(fd) => fd,
                Err(crate::Error::Io(e))
                    if e.kind() == io::ErrorKind::PermissionDenied =>
                {
                    return;
                }
                Err(e) => panic!("unexpected socket create error: {e:?}"),
            };
        let sock = TunnelSocket {
            fd,
            encap: SocketEncap::Udp,
            family: SocketFamily::V6,
            scope: None,
            pinned: AtomicBool::new(false),
        };
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let err = sock
            .reconnect_udp(&UdpEndpoint::V6(SocketAddrV6::new(
                link_local, 1701, 0, 0,
            )))
            .unwrap_err();
        assert!(matches!(
            err,
            crate::Error::ScopeRequired(addr) if addr == link_local
        ));
    }

    #[test]
    fn udp_link_local_socket_binds_to_the_scoped_interface() {
        let Some((addr, ifname)) = link_local_interface() else {
            return;
        };
        let index = ifname.index().unwrap();
        let local = UdpEndpoint::V6(SocketAddrV6::new(addr, 0, 0, index));
        // The peer takes the interface from the local endpoint.
        let remote = UdpEndpoint::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1234),
            1701,
            0,
            0,
        ));
        let sock = match TunnelSocket::udp(&local, &remote, None) {
            Ok(sock) => sock,
            // No permission or no usable link here.
            Err(crate::Error::Io(e))
                if e.kind() == io::ErrorKind::PermissionDenied
                    || matches!(
                        e.raw_os_error(),
                        Some(libc::EADDRNOTAVAIL | libc::ENETUNREACH)
                    ) =>
            {
                return;
            }
            Err(e) => panic!("unexpected link-local socket error: {e:?}"),
        };
        assert!(sock.pinned.load(Ordering::Relaxed));

        let UdpEndpoint::V6(bound) = sock.local_addr_udp().unwrap() else {
            panic!("expected an IPv6 local address");
        };
        assert_eq!(*bound.ip(), addr);
        assert_eq!(bound.scope_id(), index);

        // The pinned socket accepts an unscoped link-local peer.
        sock.reconnect_udp(&UdpEndpoint::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x5678),
            1701,
            0,
            0,
        )))
        .unwrap();
    }

    #[test]
    fn sockaddr_l2tpip6_matches_kernel_size() {
        assert_eq!(size_of::<SockaddrL2tpIp6>(), 32);
    }

    #[test]
    fn udp_constructor_rejects_family_mismatch() {
        let local =
            UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1701));
        let remote = UdpEndpoint::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            1701,
            0,
            0,
        ));

        let err = match TunnelSocket::udp(&local, &remote, None) {
            Ok(_) => panic!("expected address family mismatch"),
            Err(e) => e,
        };
        assert!(matches!(err, crate::Error::AddressFamilyMismatch));
    }

    #[test]
    fn ip_constructor_rejects_family_mismatch() {
        let local = IpEndpoint::V4(Ipv4Addr::LOCALHOST);
        let remote = IpEndpoint::v6(Ipv6Addr::LOCALHOST);

        let err = match TunnelSocket::ip(&local, &remote, None, TunnelId(42)) {
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
            Err(crate::Error::Io(e))
                if e.kind() == io::ErrorKind::PermissionDenied =>
            {
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
        let rc = unsafe {
            libc::send(tunnel_socket.as_raw_fd(), b"one".as_ptr().cast(), 3, 0)
        };
        assert_eq!(rc, 3);

        let mut buf = [0u8; 64];
        let (n1, _) = receiver1.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n1], b"one");

        tunnel_socket
            .reconnect_udp(&UdpEndpoint::V4(receiver2_addr))
            .unwrap();

        // SAFETY: the file descriptor is a valid connected UDP socket and
        // buffer pointers are valid for their length.
        let rc = unsafe {
            libc::send(tunnel_socket.as_raw_fd(), b"two".as_ptr().cast(), 3, 0)
        };
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
    fn reconnect_udp_and_local_addr_reject_ip_socket() {
        let fd =
            match socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
                Ok(fd) => fd,
                Err(crate::Error::Io(e))
                    if e.kind() == io::ErrorKind::PermissionDenied =>
                {
                    return;
                }
                Err(e) => panic!("unexpected socket create error: {e:?}"),
            };
        let sock = TunnelSocket {
            fd,
            encap: SocketEncap::Ip,
            family: SocketFamily::V4,
            scope: None,
            pinned: AtomicBool::new(false),
        };

        let err = sock
            .reconnect_udp(&UdpEndpoint::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                1701,
            )))
            .unwrap_err();
        assert!(matches!(err, crate::Error::EncapsulationMismatch));

        let err = sock.local_addr_udp().unwrap_err();
        assert!(matches!(err, crate::Error::EncapsulationMismatch));
    }

    #[test]
    fn set_ipv6_dontfrag_on_ipv4_socket_returns_io_error() {
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
            Err(crate::Error::Io(e))
                if e.kind() == io::ErrorKind::PermissionDenied =>
            {
                return;
            }
            Err(e) => panic!("unexpected tunnel socket error: {e:?}"),
        };

        let err = sock.set_ipv6_dontfrag(true).unwrap_err();
        assert!(matches!(err, crate::Error::Io(_)));
        assert!(err.raw_os_error().is_some());
    }

    #[test]
    fn sockets_are_close_on_exec() {
        let fd = match socket(libc::AF_INET, libc::SOCK_DGRAM, 0) {
            Ok(fd) => fd,
            Err(crate::Error::Io(e))
                if e.kind() == io::ErrorKind::PermissionDenied =>
            {
                return;
            }
            Err(e) => panic!("unexpected socket create error: {e:?}"),
        };
        // SAFETY: `fd` is an open descriptor owned by this test.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags, -1);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
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
            Err(crate::Error::Io(e))
                if e.kind() == io::ErrorKind::PermissionDenied =>
            {
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
        let fd =
            match socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
                Ok(fd) => fd,
                Err(crate::Error::Io(e))
                    if e.kind() == io::ErrorKind::PermissionDenied =>
                {
                    return;
                }
                Err(e) => panic!("unexpected socket create error: {e:?}"),
            };
        let sock = TunnelSocket {
            fd,
            encap: SocketEncap::Udp,
            family: SocketFamily::V4,
            scope: None,
            pinned: AtomicBool::new(false),
        };

        let err = sock
            .reconnect_ip(&IpEndpoint::V4(Ipv4Addr::LOCALHOST))
            .unwrap_err();
        assert!(matches!(err, crate::Error::EncapsulationMismatch));
    }

    #[test]
    fn reconnect_ip_rejects_family_mismatch_with_clear_error() {
        let fd =
            match socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
                Ok(fd) => fd,
                Err(crate::Error::Io(e))
                    if e.kind() == io::ErrorKind::PermissionDenied =>
                {
                    return;
                }
                Err(e) => panic!("unexpected socket create error: {e:?}"),
            };
        let sock = TunnelSocket {
            fd,
            encap: SocketEncap::Ip,
            family: SocketFamily::V4,
            scope: None,
            pinned: AtomicBool::new(false),
        };

        let err = sock
            .reconnect_ip(&IpEndpoint::v6(Ipv6Addr::LOCALHOST))
            .unwrap_err();
        assert!(matches!(err, crate::Error::AddressFamilyMismatch));
    }

    #[test]
    fn sockaddr_l2tpip_matches_sockaddr_size() {
        assert_eq!(size_of::<SockaddrL2tpIp>(), size_of::<libc::sockaddr>());
    }
}

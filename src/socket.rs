// SPDX-License-Identifier: MIT

use std::{
    io,
    mem::{size_of, zeroed},
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    sync::{Mutex, MutexGuard, PoisonError},
};

use crate::{
    Encapsulation, IFNAMSIZ, IpEndpoint, L2tpIfName, TunnelConfig, TunnelId,
    UdpEndpoint,
};

const IPPROTO_L2TP: libc::c_int = 115;

/// Path MTU discovery mode of a tunnel socket (`IP_MTU_DISCOVER` and
/// `IPV6_MTU_DISCOVER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub enum PmtuDiscovery {
    /// Never set the don't-fragment flag; fragment locally.
    Dont,
    /// Follow the per-route setting, the kernel default.
    Want,
    /// Always set the don't-fragment flag and perform discovery.
    Do,
    /// Set the don't-fragment flag but ignore the discovered path MTU.
    Probe,
}

impl PmtuDiscovery {
    fn value(self) -> libc::c_int {
        // The IPv6 constants have the same values.
        match self {
            Self::Dont => libc::IP_PMTUDISC_DONT,
            Self::Want => libc::IP_PMTUDISC_WANT,
            Self::Do => libc::IP_PMTUDISC_DO,
            Self::Probe => libc::IP_PMTUDISC_PROBE,
        }
    }
}

/// Owned tunnel socket used by managed tunnels (`L2TP_ATTR_FD`).
///
/// Dropping this type closes the file descriptor.
/// Per the kernel L2TP API, closing the tunnel socket tears down the
/// associated tunnel and sessions.
///
/// The descriptor is created with `SOCK_CLOEXEC`, so child processes do not
/// inherit it and keep the tunnel alive. A socket prepared elsewhere is
/// adopted with [`TunnelSocket::from_fd`].
#[derive(Debug)]
pub struct TunnelSocket {
    fd: OwnedFd,
    encap: SocketEncap,
    family: SocketFamily,
    /// Interface name that scopes an IP socket, resolved on every reconnect.
    scope: Option<L2tpIfName>,
    /// Connection ID an IP socket is bound with; `None` for UDP.
    conn_id: Option<u32>,
    /// Peer tunnel identifier repeated on reconnect; unknown for adopted
    /// IPv4 IP sockets unless explicitly supplied, and unused for UDP.
    peer_conn_id: Option<u32>,
    /// Connection state the kernel does not report back. Every syscall that
    /// changes it runs under this lock together with its update, so
    /// concurrent reconnects and disconnects cannot leave the cache behind.
    link: Mutex<Link>,
}

/// Cached connection state of a [`TunnelSocket`].
#[derive(Debug, Clone, Copy)]
struct Link {
    /// Whether the kernel has pinned the socket to an interface, through a
    /// link-local scope or `SO_BINDTODEVICE`. A link-local peer without a
    /// scope of its own needs that.
    pinned: bool,
    /// Peer of an IPv4 L2TP/IP socket as connected by this type, since the
    /// kernel never reports it; `0` when unknown.
    peer_v4: u32,
    /// Whether the socket has a peer. Cleared by `disconnect`, because the
    /// kernel keeps reporting the old peer of an IPv6 L2TP/IP socket.
    connected: bool,
    /// Device the socket is bound to with `SO_BINDTODEVICE`. The kernel
    /// forgets it on `disconnect`. Unlike `scope`, it is never resolved to
    /// an index by this type: the kernel routes through it by itself, so
    /// its disappearance only matters to the kernel.
    device: Option<L2tpIfName>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketEncap {
    Udp,
    Ip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    fn domain(self) -> libc::c_int {
        match self {
            Self::V4 => libc::AF_INET,
            Self::V6 => libc::AF_INET6,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrL2tpIp {
    l2tp_family: libc::sa_family_t,
    l2tp_unused: u16,
    l2tp_addr: libc::in_addr,
    l2tp_conn_id: u32,
    _pad: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
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
    /// from the [`SocketAddrV6`] scope ID (see
    /// [`L2tpIfNameExt::index`](crate::L2tpIfNameExt::index)) or
    /// from `device`. A link-local `remote` may omit its scope ID when
    /// `local` or `device` already pins the socket to an interface. A
    /// missing scope is reported as
    /// [`Error::ScopeRequired`](crate::Error::ScopeRequired) before the
    /// socket is created.
    pub fn udp(
        local: &UdpEndpoint,
        remote: &UdpEndpoint,
        device: Option<&L2tpIfName>,
    ) -> crate::Result<Self> {
        if local.ip_version() != remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }
        require_udp_scope(local, device.is_some())?;
        require_udp_scope(
            remote,
            device.is_some() || has_link_local_scope(local),
        )?;

        let family = SocketFamily::from_udp(local);
        let fd = socket(family.domain(), libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;

        if let Some(device) = device {
            set_bind_to_device(fd.as_raw_fd(), device)?;
        }

        bind(fd.as_raw_fd(), &udp_sockaddr(local))?;
        connect(fd.as_raw_fd(), &udp_sockaddr(remote))?;

        // Validation above guarantees that a link-local endpoint came with a
        // scope or a device, each of which pins the socket.
        let pinned =
            device.is_some() || local.is_link_local() || remote.is_link_local();
        Ok(Self {
            fd,
            encap: SocketEncap::Udp,
            family,
            scope: None,
            conn_id: None,
            peer_conn_id: None,
            link: Mutex::new(Link {
                pinned,
                peer_v4: 0,
                connected: true,
                device: device.copied(),
            }),
        })
    }

    /// Creates and connects an IP-encapsulated L2TP socket.
    ///
    /// The local bind uses `tunnel_id` as `l2tp_conn_id`, so it must match the
    /// tunnel ID of the [`TunnelConfig`] the socket is used with; the connect
    /// records `peer_tunnel_id` as the peer connection ID.
    ///
    /// Link-local IPv6 endpoints need an interface scope
    /// ([`IpEndpoint::v6_scoped`]) or a `device`, which pins the socket with
    /// `SO_BINDTODEVICE`. The scopes of `local` and `remote` and the
    /// `device` must name the same interface. A scope is resolved to the
    /// interface index whenever a link-local address is bound or connected,
    /// here and on every [`reconnect_ip`](Self::reconnect_ip); the `device`
    /// is only ever handed to the kernel by name. If the interface is
    /// re-created, first [`disconnect`](Self::disconnect) to clear the old
    /// binding; reapply [`bind_to_device`](Self::bind_to_device) if needed,
    /// then reconnect. The lookup happens in the socket's own network
    /// namespace, even when the socket was created through
    /// [`NetNs::run`](crate::NetNs::run) and is reconnected from a thread
    /// in another namespace. Unlike `device`, a scope does not need
    /// `CAP_NET_RAW`.
    pub fn ip(
        local: &IpEndpoint,
        remote: &IpEndpoint,
        device: Option<&L2tpIfName>,
        tunnel_id: TunnelId,
        peer_tunnel_id: TunnelId,
    ) -> crate::Result<Self> {
        if local.ip_version() != remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }
        // The device may stand in for a missing scope, but it is not one:
        // the kernel pins the socket to it by name, so it is kept apart from
        // the scope that link-local addresses resolve on every reconnect.
        let pinning = unified_scope([local.scope(), remote.scope(), device])?;
        require_scope(local, pinning, false)?;
        require_scope(remote, pinning, false)?;
        let scope = unified_scope([local.scope(), remote.scope()])?.copied();

        let family = SocketFamily::from_ip(local);
        let fd = socket(family.domain(), libc::SOCK_DGRAM, IPPROTO_L2TP)?;
        let scope_id = if local.is_link_local() || remote.is_link_local() {
            resolve_scope(fd.as_raw_fd(), scope.as_ref())?
        } else {
            // The kernel ignores the scope of other addresses.
            0
        };

        if let Some(device) = device {
            set_bind_to_device(fd.as_raw_fd(), device)?;
        }

        bind(fd.as_raw_fd(), &l2tp_sockaddr(local, tunnel_id.0, scope_id))?;
        connect(
            fd.as_raw_fd(),
            &l2tp_sockaddr(remote, peer_tunnel_id.0, scope_id),
        )?;

        // The kernel only pins the socket for a device or a link-local scope.
        let pinned =
            device.is_some() || local.is_link_local() || remote.is_link_local();
        Ok(Self {
            fd,
            encap: SocketEncap::Ip,
            family,
            scope,
            conn_id: Some(tunnel_id.0),
            peer_conn_id: Some(peer_tunnel_id.0),
            link: Mutex::new(Link {
                pinned,
                peer_v4: v4_bits(remote),
                connected: true,
                device: device.copied(),
            }),
        })
    }

    /// Creates the socket a [`TunnelConfig`] describes and applies its UDP
    /// checksum settings, ready for
    /// [`L2tpHandle::create_tunnel`](crate::L2tpHandle::create_tunnel).
    pub fn for_config(
        config: &TunnelConfig,
        device: Option<&L2tpIfName>,
    ) -> crate::Result<Self> {
        let socket = match config.encapsulation() {
            Encapsulation::Udp { local, remote, .. } => {
                Self::udp(local, remote, device)?
            }
            Encapsulation::Ip { local, remote } => Self::ip(
                local,
                remote,
                device,
                config.tunnel_id(),
                config.peer_tunnel_id(),
            )?,
        };
        socket.configure(config.encapsulation())?;
        Ok(socket)
    }

    /// Adopts a bound and connected datagram socket prepared elsewhere, for
    /// example with `socket2` or through socket activation.
    ///
    /// The socket must be an `AF_INET` or `AF_INET6` `SOCK_DGRAM` socket of
    /// protocol UDP or `IPPROTO_L2TP`; anything else fails with
    /// `EAFNOSUPPORT`, `ESOCKTNOSUPPORT` or `EPROTONOSUPPORT`, and the
    /// descriptor is closed with the error, as it is on any other failure
    /// here. The bound device, link-local scope and local connection ID are
    /// read back from the kernel, as is the peer connection ID for IPv6
    /// L2TP/IP sockets; the scope is the name of the interface a link-local
    /// local address is bound to, which must still exist.
    /// Build the tunnel configuration from the adopted socket with
    /// [`TunnelConfig::for_socket`], except for an IPv4 L2TP/IP socket,
    /// whose peer the kernel does not report (see
    /// [`peer_addr_ip`](Self::peer_addr_ip)); describe that one with
    /// [`TunnelConfig::new`]. Reconnecting an IPv4 L2TP/IP socket adopted
    /// here fails with
    /// [`Error::UnknownPeerConnId`](crate::Error::UnknownPeerConnId).
    /// Use [`from_fd_with_peer`](Self::from_fd_with_peer) to supply its peer
    /// connection ID and allow reconnects.
    pub fn from_fd(fd: OwnedFd) -> crate::Result<Self> {
        let raw = fd.as_raw_fd();
        let family =
            match socket_option(raw, libc::SOL_SOCKET, libc::SO_DOMAIN)? {
                libc::AF_INET => SocketFamily::V4,
                libc::AF_INET6 => SocketFamily::V6,
                _ => return Err(errno(libc::EAFNOSUPPORT)),
            };
        if socket_option(raw, libc::SOL_SOCKET, libc::SO_TYPE)?
            != libc::SOCK_DGRAM
        {
            return Err(errno(libc::ESOCKTNOSUPPORT));
        }
        let encap =
            match socket_option(raw, libc::SOL_SOCKET, libc::SO_PROTOCOL)? {
                libc::IPPROTO_UDP => SocketEncap::Udp,
                IPPROTO_L2TP => SocketEncap::Ip,
                _ => return Err(errno(libc::EPROTONOSUPPORT)),
            };
        let device = bound_device(raw)?;
        // The interface a bound link-local address is scoped to, by name.
        let scope_name = |addr: Ipv6Addr, scope_id: u32| {
            (addr.is_unicast_link_local() && scope_id != 0)
                .then(|| interface_name(raw, scope_id))
                .transpose()
        };
        let (scope, conn_id, peer_conn_id) = match (encap, family) {
            (SocketEncap::Udp, SocketFamily::V6) => {
                let addr = sockaddr_in6(&socket_name(raw, false)?)?;
                (scope_name(*addr.ip(), addr.scope_id())?, None, None)
            }
            (SocketEncap::Udp, SocketFamily::V4) => (None, None, None),
            (SocketEncap::Ip, SocketFamily::V6) => {
                let local = l2tp_sockaddr_in6(&socket_name(raw, false)?)?;
                (
                    scope_name(
                        Ipv6Addr::from(local.l2tp_addr.s6_addr),
                        local.l2tp_scope_id,
                    )?,
                    Some(local.l2tp_conn_id),
                    Some(peer_conn_id_in6(raw)),
                )
            }
            (SocketEncap::Ip, SocketFamily::V4) => {
                let local = l2tp_sockaddr_in(&socket_name(raw, false)?)?;
                let peer = socket_name(raw, true)
                    .ok()
                    .and_then(|name| l2tp_sockaddr_in(&name).ok());
                (
                    None,
                    Some(local.l2tp_conn_id),
                    peer.map(|peer| peer.l2tp_conn_id),
                )
            }
        };
        Ok(Self {
            fd,
            encap,
            family,
            scope,
            conn_id,
            peer_conn_id,
            link: Mutex::new(Link {
                pinned: device.is_some() || scope.is_some(),
                peer_v4: 0,
                connected: true,
                device,
            }),
        })
    }

    /// Adopts an L2TP/IP socket with an explicit peer connection ID for
    /// subsequent [`reconnect_ip`](Self::reconnect_ip) calls.
    ///
    /// This has the same requirements as [`from_fd`](Self::from_fd), but
    /// rejects UDP sockets with
    /// [`Error::EncapsulationMismatch`](crate::Error::EncapsulationMismatch).
    /// The supplied ID is remembered without changing the socket's current
    /// connection. It should match the descriptor's peer tunnel ID and may
    /// be zero. This is needed for adopted IPv4 L2TP/IP sockets because the
    /// kernel does not report their peer connection ID. Their peer address
    /// remains unknown until a successful reconnect.
    pub fn from_fd_with_peer(
        fd: OwnedFd,
        peer_tunnel_id: TunnelId,
    ) -> crate::Result<Self> {
        let mut socket = Self::from_fd(fd)?;
        if socket.encap != SocketEncap::Ip {
            return Err(crate::Error::EncapsulationMismatch);
        }
        socket.peer_conn_id = Some(peer_tunnel_id.0);
        Ok(socket)
    }

    pub(crate) fn conn_id(&self) -> Option<u32> {
        self.conn_id
    }

    /// The cached connection state; a poisoned lock still holds valid data.
    fn link(&self) -> MutexGuard<'_, Link> {
        self.link.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn configure(
        &self,
        encapsulation: &Encapsulation,
    ) -> crate::Result<()> {
        match (encapsulation, self.encap) {
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
                if self.family == SocketFamily::V6 {
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
                // The socket is bound already; the scopes only have to agree
                // with each other and with the device the socket is on.
                let link = self.link();
                unified_scope([
                    local.scope(),
                    remote.scope(),
                    self.scope.as_ref(),
                    link.device.as_ref(),
                ])?;
            }
            _ => return Err(crate::Error::EncapsulationMismatch),
        }
        Ok(())
    }

    /// Describes the socket's current addresses and UDP checksum options as
    /// an [`Encapsulation`].
    pub(crate) fn encapsulation(&self) -> crate::Result<Encapsulation> {
        let raw = self.fd.as_raw_fd();
        match self.encap {
            SocketEncap::Udp => {
                let udp_csum =
                    socket_option(raw, libc::SOL_SOCKET, libc::SO_NO_CHECK)?
                        == 0;
                let (udp_zero_csum6_tx, udp_zero_csum6_rx) = match self.family {
                    SocketFamily::V4 => (false, false),
                    SocketFamily::V6 => (
                        socket_option(
                            raw,
                            libc::IPPROTO_UDP,
                            libc::UDP_NO_CHECK6_TX,
                        )? != 0,
                        socket_option(
                            raw,
                            libc::IPPROTO_UDP,
                            libc::UDP_NO_CHECK6_RX,
                        )? != 0,
                    ),
                };
                Ok(Encapsulation::Udp {
                    local: self.local_addr_udp()?,
                    remote: self.peer_addr_udp()?,
                    udp_csum,
                    udp_zero_csum6_tx,
                    udp_zero_csum6_rx,
                })
            }
            SocketEncap::Ip => Ok(Encapsulation::Ip {
                local: self.local_addr_ip()?,
                remote: self.peer_addr_ip()?,
            }),
        }
    }

    /// Applies `SO_BINDTODEVICE` on this socket; this requires `CAP_NET_RAW`.
    ///
    /// Afterwards a link-local remote may omit its scope on reconnect.
    pub fn bind_to_device(&self, device: &L2tpIfName) -> crate::Result<()> {
        let mut link = self.link();
        set_bind_to_device(self.fd.as_raw_fd(), device)?;
        link.pinned = true;
        link.device = Some(*device);
        Ok(())
    }

    /// Disconnects the socket from its peer with `connect(AF_UNSPEC)`.
    ///
    /// The kernel drops the peer address, the source address it selected and
    /// `SO_BINDTODEVICE`, so the socket is no longer pinned to an interface.
    /// The connection ID of an L2TP/IP socket stays bound and the tunnel keeps
    /// receiving, but the kernel also forgets the local address, so the next
    /// [`reconnect_ip`](Self::reconnect_ip) selects the source address afresh,
    /// for example after the interface's addresses changed. Apply
    /// [`bind_to_device`](Self::bind_to_device) again before reconnecting if
    /// the socket must stay on its device. A UDP socket keeps an explicitly
    /// bound address and port, but a port the kernel chose is replaced on
    /// [`reconnect_udp`](Self::reconnect_udp).
    pub fn disconnect(&self) -> crate::Result<()> {
        let mut link = self.link();
        // SAFETY: an all-zero sockaddr is a valid value; only its family is
        // read for `AF_UNSPEC`, and the length passed is the struct's size.
        let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
        addr.sa_family = libc::AF_UNSPEC as libc::sa_family_t;
        // SAFETY: `addr` is initialized, `fd` is an open socket descriptor.
        let rc = unsafe {
            libc::connect(
                self.fd.as_raw_fd(),
                &addr,
                size_of::<libc::sockaddr>() as libc::socklen_t,
            )
        };
        if rc == -1 {
            return Err(io::Error::last_os_error().into());
        }
        *link = Link {
            pinned: false,
            peer_v4: 0,
            connected: false,
            device: None,
        };
        Ok(())
    }

    /// Sets `IPV6_DONTFRAG` for this socket.
    pub fn set_ipv6_dontfrag(&self, dontfrag: bool) -> crate::Result<()> {
        set_socket_bool(
            self.fd.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_DONTFRAG,
            dontfrag,
        )
    }

    /// Sets the IPv4 type of service or the IPv6 traffic class, including the
    /// DSCP and ECN bits, of transmitted tunnel packets.
    pub fn set_tos(&self, tos: u8) -> crate::Result<()> {
        let (level, option) = match self.family {
            SocketFamily::V4 => (libc::IPPROTO_IP, libc::IP_TOS),
            SocketFamily::V6 => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
        };
        set_socket_int(self.fd.as_raw_fd(), level, option, tos.into())
    }

    /// Sets the IPv4 time to live or the IPv6 hop limit of transmitted tunnel
    /// packets.
    pub fn set_hop_limit(&self, hops: u8) -> crate::Result<()> {
        let (level, option) = match self.family {
            SocketFamily::V4 => (libc::IPPROTO_IP, libc::IP_TTL),
            SocketFamily::V6 => (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
        };
        set_socket_int(self.fd.as_raw_fd(), level, option, hops.into())
    }

    /// Sets the packet mark (`SO_MARK`) used for routing and filtering, which
    /// requires `CAP_NET_ADMIN`.
    pub fn set_mark(&self, mark: u32) -> crate::Result<()> {
        set_socket_int(
            self.fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            mark as libc::c_int,
        )
    }

    /// Sets the path MTU discovery mode (`IP_MTU_DISCOVER` or
    /// `IPV6_MTU_DISCOVER`).
    pub fn set_pmtu_discovery(&self, mode: PmtuDiscovery) -> crate::Result<()> {
        let (level, option) = match self.family {
            SocketFamily::V4 => (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
            SocketFamily::V6 => (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER),
        };
        set_socket_int(self.fd.as_raw_fd(), level, option, mode.value())
    }

    /// Reconnects a managed UDP tunnel socket to a new remote endpoint.
    ///
    /// A link-local `new_remote` needs a scope ID unless the socket is
    /// already pinned to an interface by its creation, by
    /// [`bind_to_device`](Self::bind_to_device) or by an earlier scoped
    /// reconnect.
    pub fn reconnect_udp(&self, new_remote: &UdpEndpoint) -> crate::Result<()> {
        if self.encap != SocketEncap::Udp {
            return Err(crate::Error::EncapsulationMismatch);
        }
        if self.family.ip_version() != new_remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }
        let mut link = self.link();
        require_udp_scope(new_remote, link.pinned)?;

        connect(self.fd.as_raw_fd(), &udp_sockaddr(new_remote))?;
        if new_remote.is_link_local() {
            link.pinned = true;
        }
        link.connected = true;
        Ok(())
    }

    /// Reconnects a managed IP tunnel socket to a new remote endpoint.
    ///
    /// A link-local `new_remote` needs an interface scope unless the socket
    /// is already pinned to an interface. The socket's own scope is used when
    /// `new_remote` has none, and the two must agree otherwise. The name is
    /// resolved to the interface index on every call that connects a
    /// link-local address, in the socket's own network namespace; other
    /// addresses need no scope and resolve none, so a device the socket was
    /// bound to may have disappeared.
    ///
    /// If the interface was re-created, call [`disconnect`](Self::disconnect)
    /// first to clear the old interface index. Reapply
    /// [`bind_to_device`](Self::bind_to_device) if needed, then reconnect;
    /// resolving the new index alone does not replace the kernel's binding.
    ///
    /// An IPv4 L2TP/IP socket adopted with [`from_fd`](Self::from_fd) has no
    /// known peer connection ID and returns
    /// [`Error::UnknownPeerConnId`](crate::Error::UnknownPeerConnId). Adopt
    /// it with [`from_fd_with_peer`](Self::from_fd_with_peer) to allow
    /// reconnects.
    pub fn reconnect_ip(&self, new_remote: &IpEndpoint) -> crate::Result<()> {
        if self.encap != SocketEncap::Ip {
            return Err(crate::Error::EncapsulationMismatch);
        }
        if self.family.ip_version() != new_remote.ip_version() {
            return Err(crate::Error::AddressFamilyMismatch);
        }
        let peer_conn_id =
            self.peer_conn_id.ok_or(crate::Error::UnknownPeerConnId)?;
        let scope = unified_scope([new_remote.scope(), self.scope.as_ref()])?;
        let mut link = self.link();
        require_scope(new_remote, scope, link.pinned)?;
        let scope_id = if new_remote.is_link_local() {
            resolve_scope(self.fd.as_raw_fd(), scope)?
        } else {
            0
        };

        connect(
            self.fd.as_raw_fd(),
            &l2tp_sockaddr(new_remote, peer_conn_id, scope_id),
        )?;
        if new_remote.is_link_local() {
            link.pinned = true;
        }
        link.peer_v4 = v4_bits(new_remote);
        link.connected = true;
        Ok(())
    }

    /// Returns the current local address of a UDP socket.
    pub fn local_addr_udp(&self) -> crate::Result<UdpEndpoint> {
        if self.encap != SocketEncap::Udp {
            return Err(crate::Error::EncapsulationMismatch);
        }
        let name = socket_name(self.fd.as_raw_fd(), false)?;
        self.udp_endpoint(&name)
    }

    /// Returns the current peer address of a UDP socket.
    pub fn peer_addr_udp(&self) -> crate::Result<UdpEndpoint> {
        if self.encap != SocketEncap::Udp {
            return Err(crate::Error::EncapsulationMismatch);
        }
        // Held across the lookup, so a concurrent disconnect cannot slip in
        // between the check and the kernel's answer.
        let link = self.link();
        if !link.connected {
            return Err(errno(libc::ENOTCONN));
        }
        let name = socket_name(self.fd.as_raw_fd(), true)?;
        self.udp_endpoint(&name)
    }

    /// Returns the current local address of an IP socket. A link-local
    /// address carries its current interface name, resolved in the socket's
    /// network namespace.
    pub fn local_addr_ip(&self) -> crate::Result<IpEndpoint> {
        if self.encap != SocketEncap::Ip {
            return Err(crate::Error::EncapsulationMismatch);
        }
        let name = socket_name(self.fd.as_raw_fd(), false)?;
        self.ip_endpoint(&name)
    }

    /// Returns the current peer address of an IP socket.
    ///
    /// The kernel never records a peer port for IPv4 L2TP/IP sockets and so
    /// reports `ENOTCONN` for every one of them through `getpeername`; this
    /// type therefore remembers the peer it connected to with
    /// [`TunnelSocket::ip`], [`reconnect_ip`](Self::reconnect_ip) or
    /// [`disconnect`](Self::disconnect). An IPv4 L2TP/IP socket adopted with
    /// [`from_fd`](Self::from_fd) or
    /// [`from_fd_with_peer`](Self::from_fd_with_peer) has no known peer
    /// address and fails with `ENOTCONN` until reconnected. For IPv6 the
    /// kernel reports `ENOTCONN` only when the peer connection ID is zero,
    /// which only a `peer_tunnel_id` of 0 produces, and it keeps reporting
    /// the old peer after
    /// [`disconnect`](Self::disconnect); this method reports `ENOTCONN` for
    /// a disconnected socket of either family instead.
    pub fn peer_addr_ip(&self) -> crate::Result<IpEndpoint> {
        if self.encap != SocketEncap::Ip {
            return Err(crate::Error::EncapsulationMismatch);
        }
        let link = self.link();
        if !link.connected {
            return Err(errno(libc::ENOTCONN));
        }
        if self.family == SocketFamily::V4 && link.peer_v4 != 0 {
            return Ok(IpEndpoint::V4(Ipv4Addr::from(link.peer_v4)));
        }
        let name = socket_name(self.fd.as_raw_fd(), true)?;
        self.ip_endpoint(&name)
    }

    fn udp_endpoint(
        &self,
        name: &libc::sockaddr_storage,
    ) -> crate::Result<UdpEndpoint> {
        Ok(match self.family {
            SocketFamily::V4 => UdpEndpoint::V4(sockaddr_in(name)?),
            SocketFamily::V6 => UdpEndpoint::V6(sockaddr_in6(name)?),
        })
    }

    fn ip_endpoint(
        &self,
        name: &libc::sockaddr_storage,
    ) -> crate::Result<IpEndpoint> {
        Ok(match self.family {
            SocketFamily::V4 => IpEndpoint::V4(Ipv4Addr::from(
                l2tp_sockaddr_in(name)?.l2tp_addr.s_addr.to_ne_bytes(),
            )),
            SocketFamily::V6 => {
                let sa = l2tp_sockaddr_in6(name)?;
                let addr = Ipv6Addr::from(sa.l2tp_addr.s6_addr);
                IpEndpoint::V6 {
                    addr,
                    scope: if addr.is_unicast_link_local()
                        && sa.l2tp_scope_id != 0
                    {
                        Some(interface_name(
                            self.fd.as_raw_fd(),
                            sa.l2tp_scope_id,
                        )?)
                    } else {
                        None
                    },
                }
            }
        })
    }

    /// Duplicates the descriptor, for example to receive the L2TP control
    /// messages that the kernel delivers on the tunnel socket.
    pub fn try_clone_fd(&self) -> io::Result<OwnedFd> {
        self.fd.try_clone()
    }

    /// Takes the descriptor out of the socket.
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }
}

impl AsFd for TunnelSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for TunnelSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl TryFrom<OwnedFd> for TunnelSocket {
    type Error = crate::Error;

    fn try_from(fd: OwnedFd) -> crate::Result<Self> {
        Self::from_fd(fd)
    }
}

impl From<TunnelSocket> for OwnedFd {
    fn from(socket: TunnelSocket) -> Self {
        socket.fd
    }
}

fn errno(code: libc::c_int) -> crate::Error {
    io::Error::from_raw_os_error(code).into()
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
        return Err(io::Error::last_os_error().into());
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
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn connect(fd: RawFd, addr: &SockAddr) -> crate::Result<()> {
    // SAFETY: `addr` points to a properly initialized sockaddr value matching
    // `addr.len()`, and `fd` is assumed to be an open socket descriptor.
    let rc = unsafe { libc::connect(fd, addr.as_ptr(), addr.len()) };
    if rc == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn set_socket_int(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> crate::Result<()> {
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
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn set_socket_bool(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    enabled: bool,
) -> crate::Result<()> {
    set_socket_int(fd, level, option, libc::c_int::from(enabled))
}

fn socket_option(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
) -> crate::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` is writable for `len` bytes and `fd` is an open socket.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(value)
}

fn set_bind_to_device(fd: RawFd, device: &L2tpIfName) -> crate::Result<()> {
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
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Returns the device the socket is bound to with `SO_BINDTODEVICE`.
fn bound_device(fd: RawFd) -> crate::Result<Option<L2tpIfName>> {
    let mut buf = [0u8; IFNAMSIZ];
    let mut len = IFNAMSIZ as libc::socklen_t;
    // SAFETY: `buf` is writable for `len` bytes and `fd` is an open socket.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error().into());
    }
    if len == 0 || buf[0] == 0 {
        return Ok(None);
    }
    Ok(Some(L2tpIfName::try_from(buf)?))
}

fn socket_name(fd: RawFd, peer: bool) -> crate::Result<libc::sockaddr_storage> {
    // SAFETY: zero-initialization is valid for `sockaddr_storage`.
    let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let ptr = (&mut storage as *mut libc::sockaddr_storage).cast();
    // SAFETY: storage points to valid writable memory with size `len`, and
    // `fd` is an open socket descriptor.
    let rc = unsafe {
        if peer {
            libc::getpeername(fd, ptr, &mut len)
        } else {
            libc::getsockname(fd, ptr, &mut len)
        }
    };
    if rc == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(storage)
}

fn check_family(
    name: &libc::sockaddr_storage,
    family: libc::c_int,
) -> crate::Result<()> {
    if libc::c_int::from(name.ss_family) != family {
        return Err(errno(libc::EAFNOSUPPORT));
    }
    Ok(())
}

fn sockaddr_in(name: &libc::sockaddr_storage) -> crate::Result<SocketAddrV4> {
    check_family(name, libc::AF_INET)?;
    // SAFETY: the kernel reported AF_INET, so the storage holds a
    // `sockaddr_in`; the read copies it out without alignment assumptions.
    let sa: libc::sockaddr_in = unsafe {
        std::ptr::read_unaligned((name as *const libc::sockaddr_storage).cast())
    };
    Ok(SocketAddrV4::new(
        Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(sa.sin_port),
    ))
}

fn sockaddr_in6(name: &libc::sockaddr_storage) -> crate::Result<SocketAddrV6> {
    check_family(name, libc::AF_INET6)?;
    // SAFETY: the kernel reported AF_INET6, so the storage holds a
    // `sockaddr_in6`.
    let sa: libc::sockaddr_in6 = unsafe {
        std::ptr::read_unaligned((name as *const libc::sockaddr_storage).cast())
    };
    Ok(SocketAddrV6::new(
        Ipv6Addr::from(sa.sin6_addr.s6_addr),
        u16::from_be(sa.sin6_port),
        sa.sin6_flowinfo,
        sa.sin6_scope_id,
    ))
}

fn l2tp_sockaddr_in(
    name: &libc::sockaddr_storage,
) -> crate::Result<SockaddrL2tpIp> {
    check_family(name, libc::AF_INET)?;
    // SAFETY: an AF_INET L2TP/IP socket name is a `sockaddr_l2tpip`.
    Ok(unsafe {
        std::ptr::read_unaligned((name as *const libc::sockaddr_storage).cast())
    })
}

fn l2tp_sockaddr_in6(
    name: &libc::sockaddr_storage,
) -> crate::Result<SockaddrL2tpIp6> {
    check_family(name, libc::AF_INET6)?;
    // SAFETY: an AF_INET6 L2TP/IP socket name is a `sockaddr_l2tpip6`.
    Ok(unsafe {
        std::ptr::read_unaligned((name as *const libc::sockaddr_storage).cast())
    })
}

/// The peer connection ID of an IPv6 L2TP/IP socket, or 0 when the kernel
/// reports the socket as not connected.
fn peer_conn_id_in6(fd: RawFd) -> u32 {
    socket_name(fd, true)
        .ok()
        .and_then(|name| l2tp_sockaddr_in6(&name).ok())
        .map_or(0, |peer| peer.l2tp_conn_id)
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
    scopes: impl IntoIterator<Item = Option<&'a L2tpIfName>>,
) -> crate::Result<Option<&'a L2tpIfName>> {
    let mut unified: Option<&L2tpIfName> = None;
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
    scope: Option<&L2tpIfName>,
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

/// The IPv4 address of an endpoint as the `peer_v4` field stores it; `0`
/// for IPv6.
fn v4_bits(endpoint: &IpEndpoint) -> u32 {
    match endpoint {
        IpEndpoint::V4(addr) => u32::from(*addr),
        IpEndpoint::V6 { .. } => 0,
    }
}

/// Resolves the scope to the current interface index. An old socket binding
/// must be cleared by disconnecting before using a re-created interface.
fn resolve_scope(fd: RawFd, scope: Option<&L2tpIfName>) -> crate::Result<u32> {
    match scope {
        Some(name) => interface_index(fd, name),
        None => Ok(0),
    }
}

/// Looks the interface up with `SIOCGIFINDEX` on the socket itself, which the
/// kernel answers for the namespace the socket lives in; `if_nametoindex(3)`
/// would use the calling thread's namespace. The error carries `ENODEV` when
/// no interface has this name.
pub(crate) fn interface_index(
    fd: RawFd,
    name: &L2tpIfName,
) -> crate::Result<u32> {
    // SAFETY: an all-zero `ifreq` is a valid value.
    let mut request: libc::ifreq = unsafe { zeroed() };
    for (dst, src) in request.ifr_name.iter_mut().zip(name.as_array()) {
        *dst = *src as libc::c_char;
    }
    // The request type differs between C libraries.
    #[allow(clippy::unnecessary_cast)]
    let code = libc::SIOCGIFINDEX as libc::Ioctl;
    // SAFETY: `request` is initialized, its name is NUL-terminated, and the
    // ioctl writes the index back into the same struct.
    let rc = unsafe { libc::ioctl(fd, code, &mut request) };
    if rc == -1 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: on success the kernel stored the index in this union member.
    let index = unsafe { request.ifr_ifru.ifru_ifindex };
    u32::try_from(index).map_err(|_| errno(libc::ENODEV))
}

/// Resolves an interface index in the socket's network namespace, including
/// a scope acquired after construction through reconnect or device binding.
fn interface_name(fd: RawFd, index: u32) -> crate::Result<L2tpIfName> {
    // SAFETY: an all-zero `ifreq` is a valid value.
    let mut request: libc::ifreq = unsafe { zeroed() };
    request.ifr_ifru.ifru_ifindex =
        i32::try_from(index).map_err(|_| errno(libc::ENODEV))?;
    #[allow(clippy::unnecessary_cast)]
    let code = libc::SIOCGIFNAME as libc::Ioctl;
    // SAFETY: `request` is initialized with the index, and the ioctl writes
    // a NUL-terminated interface name into the same struct.
    let rc = unsafe { libc::ioctl(fd, code, &mut request) };
    if rc == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(L2tpIfName::try_from(
        request.ifr_name.map(|byte| byte as u8),
    )?)
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
        net::{SocketAddr, UdpSocket},
        time::Duration,
    };

    use super::*;
    use crate::{L2tpIfNameExt, TunnelId};

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

    fn udp_fd(domain: libc::c_int) -> Option<OwnedFd> {
        match socket(domain, libc::SOCK_DGRAM, libc::IPPROTO_UDP) {
            Ok(fd) => Some(fd),
            Err(crate::Error::Io(e))
                if e.kind() == io::ErrorKind::PermissionDenied =>
            {
                None
            }
            Err(e) => panic!("unexpected socket create error: {e:?}"),
        }
    }

    fn raw_socket(
        fd: OwnedFd,
        encap: SocketEncap,
        family: SocketFamily,
        scope: Option<L2tpIfName>,
    ) -> TunnelSocket {
        TunnelSocket {
            fd,
            encap,
            family,
            scope,
            conn_id: (encap == SocketEncap::Ip).then_some(0),
            peer_conn_id: (encap == SocketEncap::Ip).then_some(0),
            link: Mutex::new(Link {
                pinned: false,
                peer_v4: 0,
                connected: true,
                device: None,
            }),
        }
    }

    #[test]
    fn interface_index_resolves_through_the_socket() {
        let Some(fd) = udp_fd(libc::AF_INET) else {
            return;
        };
        let lo = L2tpIfName::new("lo").unwrap();
        let index = interface_index(fd.as_raw_fd(), &lo).unwrap();
        assert_eq!(index, lo.index().unwrap());
        assert_eq!(interface_name(fd.as_raw_fd(), index).unwrap(), lo);
        assert_eq!(
            interface_name(fd.as_raw_fd(), 0)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENODEV)
        );
        let missing = L2tpIfName::new("l2tp-no-such0").unwrap();
        let err = interface_index(fd.as_raw_fd(), &missing).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV), "{err:?}");
        assert_eq!(resolve_scope(fd.as_raw_fd(), None).unwrap(), 0);
    }

    fn connected_v4_pair() -> Option<(TunnelSocket, UdpSocket)> {
        let receiver = bind_v4_local()?;
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
                return None;
            }
            Err(e) => panic!("unexpected tunnel socket error: {e:?}"),
        };
        Some((sock, receiver))
    }

    #[test]
    fn managed_udp_checksum_options_follow_configuration() {
        for family in [SocketFamily::V4, SocketFamily::V6] {
            let Some(fd) = udp_fd(family.domain()) else {
                return;
            };
            let sock = raw_socket(fd, SocketEncap::Udp, family, None);
            let endpoint = match family {
                SocketFamily::V4 => UdpEndpoint::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    1701,
                )),
                SocketFamily::V6 => UdpEndpoint::V6(SocketAddrV6::new(
                    Ipv6Addr::LOCALHOST,
                    1701,
                    0,
                    0,
                )),
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
                    )
                    .unwrap(),
                    i32::from(enabled)
                );
                if family == SocketFamily::V6 {
                    assert_eq!(
                        socket_option(
                            sock.as_raw_fd(),
                            libc::IPPROTO_UDP,
                            libc::UDP_NO_CHECK6_TX
                        )
                        .unwrap(),
                        i32::from(enabled)
                    );
                    assert_eq!(
                        socket_option(
                            sock.as_raw_fd(),
                            libc::IPPROTO_UDP,
                            libc::UDP_NO_CHECK6_RX
                        )
                        .unwrap(),
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
        let eth0 = L2tpIfName::new("eth0").unwrap();
        let eth1 = L2tpIfName::new("eth1").unwrap();
        let ids = (TunnelId(1), TunnelId(2));

        // Validation runs before any socket is created.
        let err = TunnelSocket::ip(
            &IpEndpoint::v6(link_local),
            &IpEndpoint::v6(Ipv6Addr::LOCALHOST),
            None,
            ids.0,
            ids.1,
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
            ids.0,
            ids.1,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::ScopeRequired(_)));

        let err = TunnelSocket::ip(
            &IpEndpoint::v6_scoped(link_local, eth0),
            &IpEndpoint::v6_scoped(link_local, eth1),
            None,
            ids.0,
            ids.1,
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
            ids.0,
            ids.1,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::ScopeMismatch { .. }));

        // A scope that names no interface fails before the socket is created.
        let missing = L2tpIfName::new("l2tp-no-such0").unwrap();
        let err = TunnelSocket::ip(
            &IpEndpoint::v6_scoped(link_local, missing),
            &IpEndpoint::v6(link_local),
            None,
            ids.0,
            ids.1,
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV));
    }

    #[test]
    fn configure_checks_ip_scopes_against_the_socket() {
        let Some(fd) = udp_fd(libc::AF_INET6) else {
            return;
        };
        let lo = L2tpIfName::new("lo").unwrap();
        let sock = raw_socket(fd, SocketEncap::Ip, SocketFamily::V6, Some(lo));
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
                    L2tpIfName::new("eth0").unwrap(),
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
                L2tpIfName::new("eth0").unwrap(),
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

        // The device the socket is bound to must agree with the scopes too.
        unscoped.link().device = Some(L2tpIfName::new("eth1").unwrap());
        let err = unscoped
            .configure(&Encapsulation::Ip {
                local: IpEndpoint::v6_scoped(link_local, lo),
                remote: IpEndpoint::v6(link_local),
            })
            .unwrap_err();
        assert!(matches!(err, crate::Error::ScopeMismatch { .. }));
    }

    #[test]
    fn device_bindings_are_not_resolved_as_scopes() {
        let tunnel_id = TunnelId(0x4c32_5100 ^ std::process::id());
        let localhost = IpEndpoint::v6(Ipv6Addr::LOCALHOST);
        let sock = match TunnelSocket::ip(
            &localhost,
            &localhost,
            None,
            tunnel_id,
            TunnelId(tunnel_id.0 ^ 1),
        ) {
            Ok(sock) => sock,
            Err(crate::Error::Io(e)) if skippable(&e) => return,
            Err(e) => panic!("unexpected IP socket error: {e:?}"),
        };
        assert_eq!(sock.scope, None);
        assert_eq!(sock.link().device, None);

        // A device that disappeared after SO_BINDTODEVICE was applied is the
        // kernel's business; reconnecting to a global address never looks
        // it up.
        let missing = L2tpIfName::new("l2tp-no-such0").unwrap();
        sock.link().device = Some(missing);
        sock.reconnect_ip(&localhost).unwrap();
        // Disconnecting forgets the device, as the kernel does.
        sock.disconnect().unwrap();
        assert_eq!(sock.link().device, None);
        sock.reconnect_ip(&localhost).unwrap();

        // A scope is resolved only when a link-local address needs it.
        let scoped = TunnelSocket {
            scope: Some(missing),
            ..sock
        };
        scoped.reconnect_ip(&localhost).unwrap();
        let err = scoped
            .reconnect_ip(&IpEndpoint::v6(Ipv6Addr::new(
                0xfe80, 0, 0, 0, 0, 0, 0, 1,
            )))
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV), "{err:?}");
    }

    #[tokio::test]
    async fn create_tunnel_rejects_a_mismatched_bound_connection_id() {
        use futures::FutureExt;

        let handle = match crate::L2tpHandle::new().await {
            Ok(handle) => handle,
            Err(crate::Error::Io(e)) if skippable(&e) => return,
            Err(e) => panic!("unexpected netlink socket error: {e:?}"),
        };
        for conn_id in [0, 42] {
            let Some(fd) = udp_fd(libc::AF_INET) else {
                return;
            };
            // Validation uses cached IP metadata, so no L2TP support or
            // privileged kernel request is needed for this regression.
            let mut socket =
                raw_socket(fd, SocketEncap::Ip, SocketFamily::V4, None);
            socket.conn_id = Some(conn_id);
            let config = TunnelConfig::new(
                TunnelId(43),
                TunnelId(73),
                Encapsulation::Ip {
                    local: IpEndpoint::V4(Ipv4Addr::LOCALHOST),
                    remote: IpEndpoint::V4(Ipv4Addr::LOCALHOST),
                },
            )
            .unwrap();
            let result = handle.create_tunnel(config, socket).now_or_never();
            assert!(matches!(
                result,
                Some(Err(crate::Error::TunnelIdMismatch {
                    socket: TunnelId(id),
                    config: TunnelId(43),
                })) if id == conn_id
            ));
        }
    }

    /// Returns an interface with a link-local address, when the host has one.
    fn link_local_interface() -> Option<(Ipv6Addr, L2tpIfName)> {
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
            Some((Ipv6Addr::from(octets), L2tpIfName::new(name).ok()?))
        })
    }

    fn skippable(e: &io::Error) -> bool {
        e.kind() == io::ErrorKind::PermissionDenied
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
            )
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
        let peer_tunnel_id = TunnelId(tunnel_id.0 ^ 1);
        let sock = match TunnelSocket::ip(
            &local,
            &remote,
            None,
            tunnel_id,
            peer_tunnel_id,
        ) {
            Ok(sock) => sock,
            // No l2tp_ip6 support, no permission, or no usable link here.
            Err(crate::Error::Io(e)) if skippable(&e) => return,
            Err(e) => panic!("unexpected link-local socket error: {e:?}"),
        };
        assert_eq!(sock.scope, Some(ifname));
        assert!(sock.link().pinned);

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

        // The accessors report the same, with the scope name attached.
        assert_eq!(sock.local_addr_ip().unwrap(), local);
        let peer = sock.peer_addr_ip().unwrap();
        assert_eq!(peer.ip(), remote.ip());
        let encapsulation = sock.encapsulation().unwrap();
        assert!(matches!(encapsulation, Encapsulation::Ip { .. }));
        let config =
            TunnelConfig::for_socket(tunnel_id, peer_tunnel_id, &sock).unwrap();
        assert_eq!(config.encapsulation(), &encapsulation);

        // Reconnecting resolves the socket's own scope again.
        sock.reconnect_ip(&IpEndpoint::v6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 0x5678,
        )))
        .unwrap();

        // An adopted descriptor reads the same state back from the kernel.
        let adopted = TunnelSocket::from_fd(sock.into_fd()).unwrap();
        assert_eq!(adopted.encap, SocketEncap::Ip);
        assert_eq!(adopted.family, SocketFamily::V6);
        assert!(adopted.link().pinned);
        assert_eq!(adopted.conn_id(), Some(tunnel_id.0));
        assert_eq!(adopted.peer_conn_id, Some(peer_tunnel_id.0));
    }

    #[test]
    fn reconnect_ip_preserves_a_new_link_local_scope_in_address_getters() {
        let Some((addr, ifname)) = link_local_interface() else {
            return;
        };
        let tunnel_id = TunnelId(0x4c32_5300 ^ std::process::id());
        let peer_tunnel_id = TunnelId(tunnel_id.0 ^ 1);
        let sock = match TunnelSocket::ip(
            &IpEndpoint::v6(Ipv6Addr::UNSPECIFIED),
            &IpEndpoint::v6(Ipv6Addr::LOCALHOST),
            None,
            tunnel_id,
            peer_tunnel_id,
        ) {
            Ok(sock) => sock,
            Err(crate::Error::Io(e)) if skippable(&e) => return,
            Err(e) => panic!("unexpected IP socket error: {e:?}"),
        };
        assert_eq!(sock.scope, None);
        sock.disconnect().unwrap();

        let endpoint = IpEndpoint::v6_scoped(addr, ifname);
        sock.reconnect_ip(&endpoint).unwrap();
        assert_eq!(sock.local_addr_ip().unwrap(), endpoint);
        assert_eq!(sock.peer_addr_ip().unwrap(), endpoint);

        // Reconstructing the configuration must preserve the newly acquired
        // scope, so the same endpoints can create a socket after this closes.
        let config =
            TunnelConfig::for_socket(tunnel_id, peer_tunnel_id, &sock).unwrap();
        drop(sock);
        let recreated = TunnelSocket::for_config(&config, None).unwrap();
        assert_eq!(recreated.local_addr_ip().unwrap(), endpoint);
        assert_eq!(recreated.peer_addr_ip().unwrap(), endpoint);
    }

    #[test]
    fn adopted_ip_sockets_keep_bound_and_peer_connection_ids() {
        for (index, endpoint) in [
            IpEndpoint::V4(Ipv4Addr::LOCALHOST),
            IpEndpoint::v6(Ipv6Addr::LOCALHOST),
        ]
        .into_iter()
        .enumerate()
        {
            for peer_tunnel_id in [TunnelId(73), TunnelId(0)] {
                let tunnel_id =
                    TunnelId(0x4c32_5000 ^ std::process::id() ^ index as u32);
                let socket = match TunnelSocket::ip(
                    &endpoint,
                    &endpoint,
                    None,
                    tunnel_id,
                    peer_tunnel_id,
                ) {
                    Ok(socket) => socket,
                    Err(crate::Error::Io(e)) if skippable(&e) => continue,
                    Err(e) => panic!("unexpected IP socket error: {e:?}"),
                };
                assert_eq!(socket.conn_id(), Some(tunnel_id.0));
                let adopted = TunnelSocket::from_fd(socket.into_fd()).unwrap();
                assert_eq!(adopted.conn_id(), Some(tunnel_id.0));
                if endpoint.ip_version() == 4 {
                    assert_eq!(adopted.peer_conn_id, None);
                    assert!(matches!(
                        adopted.reconnect_ip(&endpoint),
                        Err(crate::Error::UnknownPeerConnId)
                    ));
                } else {
                    assert_eq!(adopted.peer_conn_id, Some(peer_tunnel_id.0));
                    adopted.reconnect_ip(&endpoint).unwrap();
                }

                let adopted = TunnelSocket::from_fd_with_peer(
                    adopted.into_fd(),
                    peer_tunnel_id,
                )
                .unwrap();
                assert_eq!(adopted.conn_id(), Some(tunnel_id.0));
                assert_eq!(adopted.peer_conn_id, Some(peer_tunnel_id.0));
                adopted.disconnect().unwrap();
                adopted.reconnect_ip(&endpoint).unwrap();
                if endpoint.ip_version() == 6 && peer_tunnel_id.0 == 0 {
                    assert_eq!(
                        adopted.peer_addr_ip().unwrap_err().raw_os_error(),
                        Some(libc::ENOTCONN)
                    );
                } else {
                    assert_eq!(adopted.peer_addr_ip().unwrap(), endpoint);
                }
                let read_back =
                    TunnelSocket::from_fd(adopted.into_fd()).unwrap();
                assert_eq!(read_back.conn_id(), Some(tunnel_id.0));
                if endpoint.ip_version() == 6 {
                    assert_eq!(read_back.peer_conn_id, Some(peer_tunnel_id.0));
                }
            }
        }
    }

    #[test]
    fn udp_link_local_endpoints_require_a_scope() {
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let any =
            UdpEndpoint::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
        let unscoped =
            UdpEndpoint::V6(SocketAddrV6::new(link_local, 1701, 0, 0));
        let scoped = UdpEndpoint::V6(SocketAddrV6::new(link_local, 1701, 0, 1));
        let lo = L2tpIfName::new("lo").unwrap();

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
        let Some(fd) = udp_fd(libc::AF_INET6) else {
            return;
        };
        let sock = raw_socket(fd, SocketEncap::Udp, SocketFamily::V6, None);
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
            Err(crate::Error::Io(e)) if skippable(&e) => return,
            Err(e) => panic!("unexpected link-local socket error: {e:?}"),
        };
        assert!(sock.link().pinned);

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

        let adopted = TunnelSocket::from_fd(sock.into_fd()).unwrap();
        assert_eq!(adopted.encap, SocketEncap::Udp);
        assert!(adopted.link().pinned);
    }

    #[test]
    fn adopted_udp_socket_describes_itself() {
        let Some((sock, receiver)) = connected_v4_pair() else {
            return;
        };
        let receiver_addr = as_v4(receiver.local_addr().unwrap());
        sock.configure(&Encapsulation::Udp {
            local: UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            remote: UdpEndpoint::V4(receiver_addr),
            udp_csum: false,
            udp_zero_csum6_tx: false,
            udp_zero_csum6_rx: false,
        })
        .unwrap();
        let adopted = TunnelSocket::from_fd(sock.into_fd()).unwrap();
        assert_eq!(adopted.encap, SocketEncap::Udp);
        assert_eq!(adopted.family, SocketFamily::V4);
        assert_eq!(adopted.conn_id(), None);
        assert_eq!(adopted.peer_conn_id, None);
        assert!(!adopted.link().pinned);

        let config =
            TunnelConfig::for_socket(TunnelId(1), TunnelId(2), &adopted)
                .unwrap();
        let Encapsulation::Udp {
            local,
            remote,
            udp_csum,
            ..
        } = config.encapsulation()
        else {
            panic!("expected UDP encapsulation");
        };
        assert_eq!(*remote, UdpEndpoint::V4(receiver_addr));
        assert!(matches!(local, UdpEndpoint::V4(v4) if v4.port() != 0));
        assert!(!udp_csum);
        assert_eq!(adopted.peer_addr_udp().unwrap(), *remote);

        // Descriptors that are not datagram sockets are refused.
        let file: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        assert!(TunnelSocket::from_fd(file).is_err());
    }

    #[test]
    fn explicit_peer_connection_id_rejects_udp_sockets() {
        let Some((socket, _receiver)) = connected_v4_pair() else {
            return;
        };
        assert_eq!(socket.conn_id(), None);
        assert!(matches!(
            TunnelSocket::from_fd_with_peer(socket.into_fd(), TunnelId(73)),
            Err(crate::Error::EncapsulationMismatch)
        ));
    }

    #[test]
    fn disconnect_clears_the_peer_and_allows_a_reconnect() {
        let Some((sock, receiver)) = connected_v4_pair() else {
            return;
        };
        let receiver_addr = as_v4(receiver.local_addr().unwrap());
        assert_eq!(
            sock.peer_addr_udp().unwrap(),
            UdpEndpoint::V4(receiver_addr)
        );
        sock.link().pinned = true;

        sock.disconnect().unwrap();
        assert!(!sock.link().pinned);
        let err = sock.peer_addr_udp().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTCONN), "{err:?}");
        // Disconnecting twice is harmless.
        sock.disconnect().unwrap();

        sock.reconnect_udp(&UdpEndpoint::V4(receiver_addr)).unwrap();
        assert_eq!(
            sock.peer_addr_udp().unwrap(),
            UdpEndpoint::V4(receiver_addr)
        );
        assert!(!sock.link().pinned);
    }

    #[test]
    fn socket_options_apply_to_udp_sockets() {
        let Some((sock, _receiver)) = connected_v4_pair() else {
            return;
        };
        sock.set_tos(0xb8).unwrap();
        assert_eq!(
            socket_option(sock.as_raw_fd(), libc::IPPROTO_IP, libc::IP_TOS)
                .unwrap(),
            0xb8
        );
        sock.set_hop_limit(7).unwrap();
        assert_eq!(
            socket_option(sock.as_raw_fd(), libc::IPPROTO_IP, libc::IP_TTL)
                .unwrap(),
            7
        );
        sock.set_pmtu_discovery(PmtuDiscovery::Do).unwrap();
        assert_eq!(
            socket_option(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER
            )
            .unwrap(),
            libc::IP_PMTUDISC_DO
        );
        // SO_MARK needs CAP_NET_ADMIN.
        match sock.set_mark(42) {
            Ok(()) => assert_eq!(
                socket_option(
                    sock.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK
                )
                .unwrap(),
                42
            ),
            Err(e) => {
                assert_eq!(e.kind(), Some(io::ErrorKind::PermissionDenied))
            }
        }
        let duplicate = sock.try_clone_fd().unwrap();
        assert_ne!(duplicate.as_raw_fd(), sock.as_raw_fd());
        assert_eq!(sock.as_fd().as_raw_fd(), sock.as_raw_fd());
    }

    #[test]
    fn udp_constructor_rejects_family_mismatch() {
        let local =
            UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1701));
        let remote =
            UdpEndpoint::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1701, 0, 0));

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

        let err = match TunnelSocket::ip(
            &local,
            &remote,
            None,
            TunnelId(42),
            TunnelId(43),
        ) {
            Ok(_) => panic!("expected address family mismatch"),
            Err(e) => e,
        };
        assert!(matches!(err, crate::Error::AddressFamilyMismatch));
    }

    #[test]
    fn udp_local_addr_and_reconnect_work() {
        let Some((tunnel_socket, receiver1)) = connected_v4_pair() else {
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
        let receiver2_addr = as_v4(receiver2.local_addr().unwrap());

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
        let Some(fd) = udp_fd(libc::AF_INET) else {
            return;
        };
        let sock = raw_socket(fd, SocketEncap::Ip, SocketFamily::V4, None);

        let err = sock
            .reconnect_udp(&UdpEndpoint::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                1701,
            )))
            .unwrap_err();
        assert!(matches!(err, crate::Error::EncapsulationMismatch));

        let err = sock.local_addr_udp().unwrap_err();
        assert!(matches!(err, crate::Error::EncapsulationMismatch));
        let err = sock.peer_addr_udp().unwrap_err();
        assert!(matches!(err, crate::Error::EncapsulationMismatch));
    }

    #[test]
    fn set_ipv6_dontfrag_on_ipv4_socket_returns_io_error() {
        let Some((sock, _receiver)) = connected_v4_pair() else {
            return;
        };
        let err = sock.set_ipv6_dontfrag(true).unwrap_err();
        assert!(matches!(err, crate::Error::Io(_)));
        assert!(err.raw_os_error().is_some());
        assert!(matches!(
            sock.local_addr_ip(),
            Err(crate::Error::EncapsulationMismatch)
        ));
    }

    #[test]
    fn sockets_are_close_on_exec() {
        let Some(fd) = udp_fd(libc::AF_INET) else {
            return;
        };
        // SAFETY: `fd` is an open descriptor owned by this test.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags, -1);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn reconnect_udp_rejects_family_mismatch_with_clear_error() {
        let Some((sock, _receiver)) = connected_v4_pair() else {
            return;
        };
        let err = sock
            .reconnect_udp(&UdpEndpoint::V6(SocketAddrV6::new(
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
        let Some(fd) = udp_fd(libc::AF_INET) else {
            return;
        };
        let sock = raw_socket(fd, SocketEncap::Udp, SocketFamily::V4, None);

        let err = sock
            .reconnect_ip(&IpEndpoint::V4(Ipv4Addr::LOCALHOST))
            .unwrap_err();
        assert!(matches!(err, crate::Error::EncapsulationMismatch));
    }

    #[test]
    fn reconnect_ip_rejects_family_mismatch_with_clear_error() {
        let Some(fd) = udp_fd(libc::AF_INET) else {
            return;
        };
        let sock = raw_socket(fd, SocketEncap::Ip, SocketFamily::V4, None);

        let err = sock
            .reconnect_ip(&IpEndpoint::v6(Ipv6Addr::LOCALHOST))
            .unwrap_err();
        assert!(matches!(err, crate::Error::AddressFamilyMismatch));
    }

    #[test]
    fn reconnect_ip_requires_a_known_peer_connection_id() {
        let Some(fd) = udp_fd(libc::AF_INET) else {
            return;
        };
        let mut socket =
            raw_socket(fd, SocketEncap::Ip, SocketFamily::V4, None);
        socket.peer_conn_id = None;
        {
            let mut link = socket.link();
            link.connected = false;
            link.peer_v4 = u32::from(Ipv4Addr::LOCALHOST);
        }

        assert!(matches!(
            socket.reconnect_ip(&IpEndpoint::V4(Ipv4Addr::new(127, 0, 0, 2))),
            Err(crate::Error::UnknownPeerConnId)
        ));
        let link = socket.link();
        assert!(!link.connected);
        assert_eq!(link.peer_v4, u32::from(Ipv4Addr::LOCALHOST));
        assert_eq!(
            socket_name(socket.as_raw_fd(), true)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::ENOTCONN)
        );
    }

    #[test]
    fn sockaddr_layouts_match_the_kernel() {
        assert_eq!(size_of::<SockaddrL2tpIp>(), size_of::<libc::sockaddr>());
        assert_eq!(size_of::<SockaddrL2tpIp6>(), 32);
    }
}

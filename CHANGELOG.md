# Changelog

## 0.4.4 (2026-10-29)

### Added

- `TunnelSocket::tunnel_id` and `TunnelSocket::peer_tunnel_id` report the
  connection IDs of an L2TP/IP socket, `None` for UDP. For an adopted socket
  `tunnel_id` is what the kernel reported through `getsockname`;
  `peer_tunnel_id` is `None` for an adopted IPv4 L2TP/IP socket until
  `from_fd_with_peer` supplies it. Neither makes a syscall.
- `EventSocket`, a non-blocking socket joined to the `l2tp` multicast group
  that needs no runtime. It can be used from any thread and registered with
  an event loop wherever the caller likes. `try_next` returns what can be
  read without blocking, with the guarantees of `BoundedEvents`.
  `EventSocket::new` opens one from a family and group ID resolved without
  a handle; `L2tpHandle::event_socket` and `blocking::L2tpHandle::event_socket`
  open one in the handle's namespace.
- `BoundedEvents::from_socket` registers an `EventSocket` with the current
  Tokio runtime. `events_bounded` and `blocking::BoundedEventIter` are built
  on `EventSocket`, unchanged in behaviour.
- `Cookie::is_rfc3931` tells whether a cookie is 0, 4 or 8 bytes long.

### Changed

- Session queries, dumps and events no longer fail on a session created
  elsewhere with a cookie of a length other than 0, 4 or 8 bytes. The
  kernel accepts any length up to 8, and such a cookie is now reported as
  it is in `SessionInfo`. Replies are parsed with lengths
  `netlink-packet-l2tp` 0.4.0 refuses.
- Session creation refuses a cookie that is not 0, 4 or 8 bytes with
  `Error::InvalidCookieLength` before any request is sent. Before this, no
  constructor could produce one; the check guards cookies copied from a
  `SessionInfo`. Every public way of building a `Cookie`, including
  deserialization, still accepts 0, 4 or 8 bytes only.

## 0.4.3 (2026-10-28)

### Added

- `L2tpHandle::events_bounded` and `blocking::L2tpHandle::events_bounded`
  return `BoundedEvents` and `blocking::BoundedEventIter`, which read
  notifications straight from the socket with no queue in between. Memory
  is bounded by the socket's receive buffer, which `AsFd` lets callers size;
  an overflow is reported as `ENOBUFS` ahead of the notifications still
  queued, and the subscription continues. `events` is unchanged.

### Fixed

- `Events` skips messages not sent by the kernel. Another local process could
  unicast forged notifications to the event socket; the sender address from
  `recvmsg` is checked, not the forgeable header port.

## 0.4.2 (2026-10-28)

### Added

- `TunnelSocket::ip_unconnected` and `TunnelSocket::udp_unconnected` bind a
  tunnel socket without connecting a peer. The tunnel can be registered on
  it right away; the kernel drops what its sessions send until the first
  `reconnect_ip` or `reconnect_udp`.
- `TunnelSocket::bind_to_device_index` applies `SO_BINDTOIFINDEX`, binding
  by interface index instead of by name.

### Changed

- `TunnelConfig::for_socket` describes a socket without a peer, unconnected
  or disconnected, with the unspecified address of its family as the remote
  instead of failing with `ENOTCONN`. `create_tunnel` ignores the addresses of
  a tunnel created on a descriptor.

## 0.4.1 (2026-10-28)

### Fixed

- `L2tpHandle::new`, `PppSocket::connect` and `PppUnit::new` no longer need
  `/proc`; namespace identity comes from `SO_NETNS_COOKIE` (Linux 5.14+).
  A handle keeps a namespace descriptor only when `/proc` is readable; without
  one, opening further sockets from a thread in another namespace fails with
  an `Unsupported` I/O error instead of entering the handle's namespace.
  Without `/proc`, `L2tpHandle::new_in` cannot recognize the calling thread's
  own namespace and always enters `netns`, which needs `CAP_SYS_ADMIN`.
  Before Linux 5.14 namespace identity is unknown, and sockets a handle opens
  after its first connection, such as event connections, are created in the
  calling thread's namespace.
- `NetNs::current` falls back to `PIDFD_GET_NET_NAMESPACE` (Linux 6.11+) when
  `/proc` is unavailable.

## 0.4.0 (2026-10-22)

### Breaking changes

- Interface names are `L2tpIfName` from `netlink-packet-l2tp` 0.4, which this
  crate re-exports. The crate's own `IfName` and `IfNameError` are gone;
  `L2tpIfNameExt` adds `from_name`, `index`, `from_index` and `as_os_str`.
  Names are byte strings and need not be UTF-8, including in the netlink
  attributes. `IfName::new(s)` becomes `L2tpIfName::from_name(s)`, which
  reports a rejected name as `Error::InvalidIfName`, and `as_str()` becomes
  `to_str()` (fallible) or `to_string_lossy()`. The error of the upstream
  constructors is re-exported as `l2tp::DecodeError`.
- `TunnelInfo::proto_version` is `TunnelInfo::version`, an `L2tpVersion`.
- `TunnelSocket::ip` takes the peer tunnel identifier, so the kernel records
  the peer connection ID.
- `Cookie` is `Copy`; `try_from_bytes` is replaced by `TryFrom<&[u8]>`,
  `TryFrom<Vec<u8>>`, `From<[u8; 4]>` and `From<[u8; 8]>`.
- `PppUnit::new`, `PppUnit::with_index`, `PppUnit::connect_channel` and
  `PppSocket::channel_index` return `l2tp::Result`.
- `SessionInfo::l2spec_type` is an `Option<L2SpecType>`. The kernel never
  reports the sublayer type, so it is `None` instead of an invented
  `L2SpecType::None`.
- `delete_tunnel` and `TunnelHandle::delete` report a tunnel that is still
  listed after the wait as `Error::DeletionPending` instead of
  `Error::Io` of kind `TimedOut`; `Error::kind` still returns `TimedOut`
  for it. The deletion is acknowledged and completes on its own, so callers
  treat the tunnel as deleted.

### Added

- L2TPv2 tunnels: `TunnelConfig::with_version(L2tpVersion::V2)`.
- PPP pseudowires: `SessionConfig::ppp`, `PppSocket` to attach a `PPPoL2TP`
  socket to a session, and `PppUnit` and `PppChannel` to create a `pppN`
  interface and connect the channel to it.
- Kernel notifications: `L2tpHandle::events` streams `L2tpEvent`s from the
  `l2tp` multicast group.
- Session lookup, deletion, modification and statistics by interface name:
  `get_session_by_ifname`, `delete_session_by_ifname`,
  `modify_session_by_ifname`, `session_stats_by_ifname`.
- `SessionInfo` reports `peer_tunnel_id`, `cookie` and `peer_cookie`.
- Handles for existing objects: `open_tunnel`, `open_session` and
  `open_session_by_ifname`, with auto-delete disabled.
- Managed sockets: `TunnelSocket::for_config`, `TunnelSocket::from_fd` and
  `TunnelConfig::for_socket` for sockets prepared elsewhere; `set_tos`,
  `set_hop_limit`, `set_mark` and `set_pmtu_discovery`; `disconnect`
  (`connect(AF_UNSPEC)`, so a reconnect selects the source address afresh);
  `peer_addr_udp`, `local_addr_ip` and `peer_addr_ip`; `AsFd`,
  `try_clone_fd` and `into_fd`.
- `L2tpIfNameExt::from_name` validates a name with this crate's error type,
  `Error::InvalidIfName`.
- Blocking API: `l2tp::blocking::L2tpHandle`, `TunnelHandle`,
  `SessionHandle` and `EventIter`, backed by a dedicated thread and runtime
  so they work from `tokio::task::spawn_blocking` and other runtimes.
- Network namespaces: `NetNs`, `NetNs::run` and `L2tpHandle::new_in`.
- `serde` derives for the configuration, information, event, identifier and
  statistics types; `Cookie` serializes as hexadecimal and `L2tpIfName`
  fields as strings or bytes.
- `Display`, `Ord` and `From<u32>` for `TunnelId` and `SessionId`;
  `Cookie` parses from hexadecimal and prints as such; `From<SocketAddr>`
  for `UdpEndpoint` and `From<IpAddr>` for `IpEndpoint`.
- `UdpEndpoint` and `IpEndpoint` display, parse and serialize as strings
  such as `192.0.2.1:1701`, `[fe80::1%2]:1701` and `fe80::1%eth0`; a
  malformed string is `Error::InvalidEndpoint`.
- Netlink requests and failures are logged through `log`.
- CLI: `--proto-version`, `--ifname` as a session selector, cookies and
  peer tunnel identifiers in session output, and `l2tp monitor`.
- A handle re-resolves the `l2tp` family identifier once when the kernel
  answers `ENOENT`, so requests keep working after `l2tp_netlink` was
  reloaded under a different identifier.
- `SessionHandle::ifindex`: the interface index of an Ethernet session's
  device. `create_session` captures it from the kernel's `RTM_NEWLINK`
  registration broadcast, which it subscribes to before sending the
  request, so a rename by udev or networkd right after creation cannot
  make it name another device; the `open_*` methods look it up by name.

### Fixed

- No public function panics on its input. `run_creation` no longer unwraps
  the task result, the CLI output never unwraps JSON encoding, and the
  blocking handles never unwrap their inner state.
- Blocking API: dropping a `TunnelHandle` or `SessionHandle` with auto-delete
  enabled runs the deletion inside the worker's tracked task, so the worker
  no longer shuts down before it is sent. The worker reaps finished requests
  as they complete instead of holding every completed task until shutdown.
  `EventIter::next` blocks on a std channel and so works from any context,
  including an async task; it no longer panics inside a Tokio context.
- Dropping a `PppChannel` disconnects the channel from its unit with
  `PPPIOCDISCONN`; before, the channel stayed connected while its
  `PppSocket` lived and could not be connected again.
- The PPP ioctl requests are encoded per architecture; the fixed values were
  wrong on MIPS, PowerPC and SPARC.
- CLI: `tunnel create --proto-version 2` chooses random identifiers within
  the 16 bits of L2TPv2, so a `PPPoL2TP` socket can attach to the tunnel.
- `TunnelSocket` keeps its cached connection state (pinned interface, IPv4
  peer, connected) under one lock together with the syscall that changes it,
  so a concurrent `disconnect` and `reconnect_*` cannot leave the cache
  contradicting the kernel.
- `Cookie` deserializes from a byte string in binary formats, as it is
  serialized; formats that distinguish bytes from sequences, such as CBOR,
  previously rejected it and every session configuration with it.
- `delete_tunnel` needs no Tokio timer and no free blocking thread, so the
  blocking API's worker, runtimes built without a time driver and a
  `block_on` from a saturated blocking pool cannot panic or deadlock in it.
  A lookup that
  fails for a reason other than `ENODEV` is returned, and a tunnel still
  listed after the wait is reported as `Error::Io` of kind `TimedOut`.
- `TunnelSocket` resolves interface scopes with `SIOCGIFINDEX` on the socket
  itself, in the socket's own network namespace, so a socket created through
  `NetNs::run` reconnects correctly from any thread.
- `TunnelSocket::peer_addr_ip` reports `ENOTCONN` after `disconnect`; the
  kernel keeps reporting the old peer of an IPv6 L2TP/IP socket.
- Binary `serde` formats such as postcard round-trip `IpEndpoint` and
  interface-name fields, which are written as a struct and as bytes there
  instead of the string-or-map forms that need a self-describing format.
- `L2tpHandle::events` never delivered a notification: the listening socket
  was unbound, and the kernel skips sockets without a port for the
  notifications it sends without a sender port. The socket is now bound.
- `delete_tunnel` and `TunnelHandle::delete` wait until the kernel's
  deferred teardown has removed the tunnel, so a lookup right after no
  longer finds it and the identifier can be reused without `EEXIST`.
- `TunnelSocket::peer_addr_ip` and `TunnelConfig::for_socket` work for IPv4
  L2TP/IP sockets, whose peer the kernel never reports through
  `getpeername`; the socket reports the peer it connected to.
- Documentation: closing a `PPPoL2TP` socket deletes its session, and the
  kernel sends no event for the teardown it performs itself (closed managed
  sockets, sessions of a deleted tunnel, released `PPPoL2TP` sockets).
- A `device` given to `TunnelSocket::ip` was stored as the socket's
  link-local scope, so every `reconnect_ip` resolved the device name and
  failed with `ENODEV` once the device was gone, even for global addresses
  and after `disconnect` had cleared the binding. The device is now kept
  apart from the scope and never resolved; a scope is resolved only when a
  link-local address is bound or connected. `disconnect` forgets the device
  as the kernel does, and `TunnelConfig::for_socket` reports the scope of an
  adopted socket by the interface its link-local address is bound to.
- `Error::ScopeMismatch` escapes the interface names it prints, as
  `Error::InvalidIfName` does.
- Documentation: the kernel freezes a session's interface name at creation
  and does not follow renames, so `SessionInfo::ifname` and the
  `*_by_ifname` lookups use the original name; the name-to-index lookup is
  not atomic, and the README describes how to capture the index without it.
  `TunnelSocket::from_fd` closes the descriptor when it rejects it.

## 0.3.0 (2026-10-22)

### Breaking changes

- The crate is Linux-only. On other platforms it compiles to an empty library,
  and the `l2tp` binary reports that the platform is unsupported.
- The `l2tp` binary is behind the new `cli` feature
  (`cargo install --features cli l2tp`). The `serde` derives on `TunnelStats`
  and `SessionStats` are behind the new `serde` feature.
- Modules are private; every public type is exported from the crate root.
- `TunnelModify`, `TunnelHandle::modify` and `L2tpHandle::modify_tunnel` were
  removed. The kernel acknowledged these requests but never applied the UDP
  checksum setting.
- `TunnelSocket::ip` takes a `TunnelId` instead of a `u32`.
- `IpEndpoint::V6` is a struct variant with an `addr` and an optional
  interface `scope`. Construct it with `IpEndpoint::v6` or
  `IpEndpoint::v6_scoped`.
- `Error` is `#[non_exhaustive]`. `Error::Netlink` holds a message instead of a
  `netlink-packet-core` type. Malformed kernel replies are
  `Error::UnexpectedReply`, operations on a socket of the wrong encapsulation
  are `Error::EncapsulationMismatch`, and socket option failures are
  `Error::Io`.
- `PseudowireType` and `L2SpecType` are `#[non_exhaustive]` and gained
  `Other(..)` variants for values this crate does not name, so an unknown
  value no longer fails a whole listing.
- `TunnelInfo`, `SessionInfo`, `TunnelStats` and `SessionStats` are
  `#[non_exhaustive]`.
- Minimum supported Rust version is 1.89, required by the updated netlink
  dependencies (`netlink-packet-core` 0.9, `netlink-packet-generic` 0.5,
  `genetlink` 0.3).

### Fixed

- `list_sessions` returned the sessions of every tunnel; the kernel ignores
  the tunnel filter, so the result is now filtered client-side.
- IPv4 L2TP/IP sockets used address family 28 instead of `AF_INET`.
- Creating a UDP tunnel with `udp_csum: false` enabled checksums, because the
  kernel only checks whether the attribute is present.
- Managed UDP sockets now apply `udp_csum`, `udp_zero_csum6_tx` and
  `udp_zero_csum6_rx` as socket options before the tunnel is registered.
- Unmanaged tunnels reject disabling UDP checksums for IPv4-mapped peers,
  instead of silently sending checksums. The CLI explains how to use IPv4
  endpoints or the managed tunnel API for this setting.
- Tunnel sockets are created with `SOCK_CLOEXEC`, so child processes no
  longer keep a tunnel alive.
- Tunnel and session creation retains ownership through the kernel ACK when
  the caller is cancelled. Unclaimed successful creations are cleaned up while
  the Tokio runtime remains running; managed socket descriptors cannot be
  reused before registration completes.
- `create_session` deletes the session again when the follow-up lookup fails
  or is cancelled, instead of leaking it without a handle.
- Netlink replies are tracked explicitly: a missing ACK, a truncated reply
  stream, a failed or interrupted dump and an overrun are reported as errors
  instead of returning partial results.
- Mismatched local and remote address families return
  `Error::AddressFamilyMismatch` instead of panicking.
- CLI: `tunnel create` creates an unmanaged tunnel that outlives the process.
  Previously the tunnel was torn down when the command exited and closed its
  socket.
- CLI: a non-ASCII `--cookie` value is rejected instead of panicking.
- CLI: automatically chosen tunnel IDs come from `getrandom(2)`. A failure is
  reported instead of falling back to a time-and-pid mix.
- `L2tpHandle::new` returns `Error::Io` instead of panicking when the Tokio
  runtime was built without its I/O driver.
- Link-local IPv6 endpoints are rejected early where the kernel cannot use
  them: `Error::ScopeRequired` for a managed socket without an interface
  scope (an interface name for IP endpoints, a `SocketAddrV6` scope ID or
  `device` for UDP endpoints), and `Error::UnmanagedLinkLocal` for unmanaged
  tunnels, whose kernel-created socket has no scope. Previously the kernel
  returned a bare `EINVAL`.

### Added

- Interface scopes for link-local L2TP/IP endpoints: `IpEndpoint::v6_scoped`
  takes an interface name that is resolved to the interface index each time
  the socket binds, connects or reconnects, so a re-created interface keeps
  working. The scopes of both endpoints and the `device` must agree
  (`Error::ScopeMismatch`).
- `IpEndpoint::v6`, `IpEndpoint::scope`, `IpEndpoint::is_link_local` and
  `UdpEndpoint::is_link_local`.
- `TunnelHandle::delete` and `SessionHandle::delete`, which wait for the
  kernel's acknowledgement and keep running if the caller is cancelled.
- `Error::kind()` and `Error::raw_os_error()`, so callers can match kernel
  errors such as `AlreadyExists` or `Interrupted` without `libc`.
- `TunnelConfig` accessors and `SessionModify::is_empty()`.
- The README is the crate documentation and its examples are compiled as
  doctests.

### Documentation

- The kernel reports the IPv4 UDP checksum setting only for IPv4 sockets, so
  `TunnelInfo` shows `udp_csum: false` for every IPv6 tunnel.
- Every L2TP netlink command, including `get` and `list`, requires
  `CAP_NET_ADMIN`.

## 0.2.1 and earlier

Releases before 0.3.0 predate this changelog; see the git history.

# Changelog

## 0.3.0

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
  dependencies (`netlink-packet-l2tp` 0.3, `netlink-packet-core` 0.9,
  `netlink-packet-generic` 0.5, `genetlink` 0.3).

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
- `IfName` validation matches the kernel's `dev_valid_name()`.
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
  scope, and `Error::UnmanagedLinkLocal` for unmanaged tunnels, whose
  kernel-created socket has no scope. Previously the kernel returned a bare
  `EINVAL`.

### Added

- Interface scopes for link-local L2TP/IP endpoints: `IpEndpoint::v6_scoped`
  takes an `IfName` that is resolved to the interface index each time the
  socket binds, connects or reconnects, so a re-created interface keeps
  working. The scopes of both endpoints and the `device` must agree
  (`Error::ScopeMismatch`). `IfName::index` and `IfName::from_index` convert
  between names and indexes, for example to build `SocketAddrV6` scope IDs
  for UDP endpoints.
- `IfName` implements `FromStr`, `TryFrom<&str>`, `TryFrom<String>`,
  `TryFrom<&[u8]>`, `AsRef<str>`, `From<IfName> for String`, `Hash` and
  `Ord`, and has `as_bytes`. Non-UTF-8 names remain unsupported because
  `netlink-packet-l2tp` carries names as `String`.
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

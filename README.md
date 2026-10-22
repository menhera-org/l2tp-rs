# l2tp-rs

High-level async control API for the Linux kernel's L2TP subsystem, with a
blocking counterpart, over Generic Netlink.

This crate covers the tunnel and session lifecycle, lookups, statistics and
notifications of the kernel's `l2tp` family, the managed tunnel sockets behind
tunnels, and the `PPPoL2TP` sockets behind PPP pseudowires. It does **not**
configure interfaces, bridges or routes; `rtnetlink` tasks belong in a
separate crate.

## Requirements

- Linux. On other platforms the crate compiles but exposes no API, and the `l2tp`
  binary only reports that the platform is unsupported.
- Rust 1.89 or newer (required by the netlink dependencies).
- Linux kernel with L2TP Generic Netlink support (`l2tp` family). Ethernet
  pseudowires need `l2tp_eth`, PPP pseudowires `l2tp_ppp`, and IP
  encapsulation `l2tp_ip` or `l2tp_ip6`.
- Tokio runtime with its I/O driver enabled, or the `blocking` module, which
  brings its own.
- `CAP_NET_ADMIN` (or root) for every L2TP netlink command, including `get`
  and `list`; the kernel marks them all `GENL_UNS_ADMIN_PERM`. Subscribing to
  notifications needs no privilege.

## Installation

```toml
[dependencies]
l2tp = "0.4"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### Cargo features

- `serde`: `Serialize`/`Deserialize` for the configuration, information,
  event, identifier and statistics types. Endpoints are strings such as
  `192.0.2.1:1701` or `fe80::1%eth0`, cookies are hexadecimal strings, and
  interface names are strings, or byte arrays when they are not UTF-8.
- `cli`: builds the supplementary, testing-only `l2tp` command-line tool
  (implies `serde`).

No features are enabled by default, so library users do not pull in the CLI's
dependencies.

## Command-Line Tool

The `l2tp` CLI is a supplementary tool intended only for testing the library.
Its text and JSON output are for inspection; serialization losses, such as
omitted IPv6 UDP flow information, are expected. Use the Rust API for
applications that need complete configuration values.

The `l2tp` binary is behind the `cli` feature. Install it with:

```bash
cargo install --features cli l2tp
```

From a checkout, use `cargo run --features cli -- <args>`. Besides tunnel and
session management, `l2tp monitor` prints kernel notifications as they
happen, and sessions can be selected by `--ifname` instead of their
identifiers.

For UDP tunnels, omitting `--local` binds the IPv6 wildcard `::`; an IPv4
remote is then mapped to IPv6. Pass `--local 0.0.0.0` (or an IPv4 address,
optionally with a port) to create an IPv4 socket. An explicit IPv4 `--local`
is required when using an IPv4 remote with `--no-udp-csum`.

## Quick Start

### Managed UDP tunnel + Ethernet session

```rust,no_run
use l2tp::{
    Encapsulation, L2tpHandle, SessionConfig, SessionId, TunnelConfig, TunnelId,
    TunnelSocket, UdpEndpoint,
};
use std::net::{Ipv4Addr, SocketAddrV4};

#[tokio::main]
async fn main() -> l2tp::Result<()> {
    let handle = L2tpHandle::new().await?;

    let local = UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1701));
    let remote = UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 1701));

    let tunnel_cfg = TunnelConfig::new(
        TunnelId(1000),
        TunnelId(2000),
        Encapsulation::Udp {
            local,
            remote,
            udp_csum: false,
            udp_zero_csum6_tx: false,
            udp_zero_csum6_rx: false,
        },
    )?;

    // Managed socket: fd is passed via L2TP_ATTR_FD and owned by TunnelHandle.
    let socket = TunnelSocket::for_config(&tunnel_cfg, None)?;
    let tunnel = handle.create_tunnel(tunnel_cfg, socket).await?;

    let mut session_cfg =
        SessionConfig::eth(tunnel.tunnel_id(), SessionId(3000), SessionId(4000));
    // A unique name of your own; the kernel keeps it for the session's life.
    session_cfg.ifname = Some("l2tp-3000".parse()?);
    let session = handle.create_session(session_cfg).await?;
    // Address the device by index from here on; udev may rename it any time.
    let _ifindex = session.ifindex();

    let _tunnel_info = tunnel.get().await?;
    let _session_info = session.get().await?;

    Ok(())
}
```

### Managed IP-backed tunnel (IPv4 or IPv6)

```rust,no_run
use l2tp::{Encapsulation, IpEndpoint, L2tpHandle, TunnelConfig, TunnelId, TunnelSocket};
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> l2tp::Result<()> {
    let handle = L2tpHandle::new().await?;

    let local = IpEndpoint::V4(Ipv4Addr::new(192, 0, 2, 1));
    let remote = IpEndpoint::V4(Ipv4Addr::new(192, 0, 2, 2));

    let socket = TunnelSocket::ip(&local, &remote, None, TunnelId(5000), TunnelId(6000))?;
    let cfg = TunnelConfig::new(
        TunnelId(5000),
        TunnelId(6000),
        Encapsulation::Ip { local, remote },
    )?;

    let _tunnel = handle.create_tunnel(cfg, socket).await?;
    Ok(())
}
```

### Link-local IPv6 endpoints

The kernel refuses to bind or connect a link-local address without an
interface. Scope the endpoint with an interface name; it is resolved to the
interface index each time the socket binds, connects or reconnects.
If the interface is re-created under a new index, call `disconnect()` before
`reconnect_ip()` to clear the kernel's old interface binding. Reapply
`bind_to_device()` first if that binding is needed, since disconnect clears it.
The scopes of both endpoints and the `device` must name the same interface.

```rust,no_run
use l2tp::{
    Encapsulation, IpEndpoint, L2tpHandle, L2tpIfName, TunnelConfig, TunnelId,
    TunnelSocket,
};
use std::net::Ipv6Addr;

#[tokio::main]
async fn main() -> l2tp::Result<()> {
    let handle = L2tpHandle::new().await?;

    let eth0: L2tpIfName = "eth0".parse()?;
    let local =
        IpEndpoint::v6_scoped(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), eth0);
    // A link-local peer without a scope uses the local endpoint's interface.
    let remote = IpEndpoint::v6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));

    let cfg = TunnelConfig::new(
        TunnelId(7000),
        TunnelId(8000),
        Encapsulation::Ip { local, remote },
    )?;
    let socket = TunnelSocket::for_config(&cfg, None)?;

    let _tunnel = handle.create_tunnel(cfg, socket).await?;
    Ok(())
}
```

UDP endpoints carry the numeric scope ID of `SocketAddrV6`. Resolve the name
with `L2tpIfNameExt::index` right before creating or reconnecting the socket:

```rust,ignore
use l2tp::L2tpIfNameExt;

let scope_id = L2tpIfName::new("eth0")?.index()?;
let local = UdpEndpoint::V6(SocketAddrV6::new(link_local, 1701, 0, scope_id));
```

A link-local remote may omit the scope ID once the local endpoint, the
`device`, or an earlier scoped connect has pinned the socket to an interface.
Both socket types report a missing scope as `Error::ScopeRequired` before
the socket is created.

Unmanaged tunnels cannot use link-local endpoints, because the kernel creates
their socket without an interface scope; `create_unmanaged_tunnel` returns
`Error::UnmanagedLinkLocal` before contacting the kernel. Re-creating a tunnel
after its interface disappears is left to the application. L2TP notifications
do not report interface removal; detect link changes separately.

## Protocol Versions

`TunnelConfig::new` creates L2TPv3 tunnels. `with_version(L2tpVersion::V2)`
creates an L2TPv2 tunnel, whose sessions are PPP pseudowires with 16-bit
identifiers and UDP encapsulation. V2 with IP encapsulation is rejected with
`Error::V2IpEncapsulation`: the kernel accepts creation but its IP receive
path cannot find V2 sessions. The kernel ignores cookies and the L2-specific
sublayer for V2 sessions. Ethernet pseudowires need version 3.
`TunnelInfo::version` reports the version of an existing tunnel.

## PPP Pseudowires

A PPP session created through netlink becomes usable once a `PPPoL2TP`
socket is connected to it. `PppSocket::connect` attaches to the session and
yields the descriptor that carries PPP frames; PPP negotiation stays in user
space, for example in `pppd` with its `pppol2tp <fd>` option. `PppUnit`
creates a `pppN` interface and `PppUnit::connect_channel` connects the
channel to it for applications that implement PPP themselves; dropping the
returned `PppChannel` disconnects the channel again.

The unit and socket retain their creating network namespaces, including
container namespaces. Connecting objects from different namespaces returns
`Error::NamespaceMismatch`. Attaching from another thread namespace runs in
the owning namespace and requires permission to enter it; ordinary attachment
within the same namespace does not need `setns` privileges.

The kernel deletes the session when the last descriptor of its `PPPoL2TP`
socket is closed, without a netlink event, so the socket's lifetime is the
session's lifetime. Disable auto-delete on the session handle, or its
deletion reports `ENODEV`, the kernel's error for a missing tunnel or
session.

```rust,no_run
use l2tp::{L2tpHandle, L2tpVersion, PppSocket, SessionConfig, SessionId, TunnelId};

#[tokio::main]
async fn main() -> l2tp::Result<()> {
    let handle = L2tpHandle::new().await?;
    // The tunnel was created earlier, managed or unmanaged.
    let tunnel = handle.open_tunnel(TunnelId(1000)).await?;
    let session = handle
        .create_session(SessionConfig::ppp(tunnel.tunnel_id(), SessionId(1), SessionId(2)))
        .await?;
    let ppp = PppSocket::connect(
        L2tpVersion::V3,
        tunnel.tunnel_id(),
        TunnelId(2000),
        session.session_id(),
        SessionId(2),
    )?;
    let _channel = ppp.channel_index()?;
    Ok(())
}
```

## Events

The kernel announces tunnel and session creation, modification and deletion
through netlink commands on the `l2tp` multicast group. It announces nothing
for teardown it performs itself: a tunnel whose managed socket was closed,
the sessions removed with a deleted tunnel, or a PPP session whose
`PPPoL2TP` socket was released. Reconcile with `list_tunnels` and
`list_all_sessions` to catch those. `L2tpHandle::events` returns a `Stream`
of `L2tpEvent`; the blocking handle returns an iterator.

Some kernels, including Linux 6.8, broadcast these events into every network
namespace, including containers, without an origin-namespace identifier.
The crate cannot reliably distinguish those events: tunnel and session IDs
can be reused in different namespaces. Treat notifications as hints to
reconcile through `list_tunnels`, `list_all_sessions`, or other queries on
your handle. Do not apply a notification as a mutation of a local object.
This limitation also applies to plain `L2tpHandle::new()` inside a container;
no explicit namespace argument or netns ID is needed to encounter it.

```rust,no_run
use futures::StreamExt;
use l2tp::L2tpHandle;

#[tokio::main]
async fn main() -> l2tp::Result<()> {
    let handle = L2tpHandle::new().await?;
    let mut events = handle.events().await?;
    while let Some(event) = events.next().await {
        event?;
        // Query this handle's namespace, regardless of the event's origin.
        let tunnels = handle.list_tunnels().await?;
        let sessions = handle.list_all_sessions().await?;
        println!("local tunnels: {tunnels:?}; local sessions: {sessions:?}");
    }
    Ok(())
}
```

## Blocking API

`l2tp::blocking::L2tpHandle` mirrors the async handle with blocking methods.
It runs a dedicated thread with its own Tokio runtime, so it works from plain
threads, from `tokio::task::spawn_blocking`, and from code that already runs a
runtime of its own. Its handles hand their async counterparts back to the
worker thread on drop, so auto-delete keeps working.

```rust,no_run
use l2tp::{TunnelId, blocking::L2tpHandle};

fn main() -> l2tp::Result<()> {
    let handle = L2tpHandle::new()?;
    for tunnel in handle.list_tunnels()? {
        println!("{tunnel:?}");
    }
    let _stats = handle.tunnel_stats(TunnelId(1000))?;
    Ok(())
}
```

## Network Namespaces

Sockets belong to the network namespace of the thread that creates them.
`NetNs` opens a namespace file such as `/run/netns/<name>`, `NetNs::run`
executes a closure on a thread inside it, and `L2tpHandle::new_in` controls
the L2TP subsystem of that namespace. Entering a namespace needs
`CAP_SYS_ADMIN`.

`L2tpHandle::new()` retains the calling thread's actual namespace, including
an inherited container namespace, for future event connections. Opening an
event connection from a different namespace enters that original namespace;
opening it from the same namespace needs no additional privileges.
Handle and PPP object creation retain descriptors opened through
`/proc/thread-self/ns/net`, so that path must be accessible.
The kernel's cross-namespace multicast behavior described under
[Events](#events) still applies.

```rust,no_run
use l2tp::{L2tpHandle, NetNs, TunnelConfig, TunnelSocket};

async fn in_namespace(cfg: TunnelConfig) -> l2tp::Result<()> {
    let netns = NetNs::open("/run/netns/blue")?;
    let handle = L2tpHandle::new_in(&netns).await?;
    let socket_cfg = cfg.clone();
    let socket = netns.run(move || TunnelSocket::for_config(&socket_cfg, None))??;
    let _tunnel = handle.create_tunnel(cfg, socket).await?;
    Ok(())
}
```

## Interface Names

Interface names are `L2tpIfName`, the checked, `Copy` type of
`netlink-packet-l2tp` that this crate re-exports. It stores the kernel's
NUL-padded `char ifname[IFNAMSIZ]` buffer and applies the kernel's
`dev_valid_name()` rules: 1 to 15 bytes, not `.` or `..`, and no NUL, `/`,
`:` or whitespace. Construct one with `L2tpIfName::new`, `str::parse` or
`TryFrom`, read it back with `as_bytes`, `as_array`, `to_str`,
`to_string_lossy` or `Display`, and convert it with the `L2tpIfNameExt`
extension trait: `from_name` validates a string or bytes and reports a
rejected name as `Error::InvalidIfName`, `index` and `from_index`
map names to the kernel's interface indexes, and `as_os_str` yields an
`OsStr`. Names are byte strings and need not be UTF-8. The upstream
constructors return `DecodeError`, re-exported here as `l2tp::DecodeError`,
which converts into `Error::Netlink`. The CLI validates `--ifname` and
`--device` while parsing and accepts non-UTF-8 arguments.

A session's name is the one its interface had when the session was created;
the kernel does not follow renames. `SessionHandle::ifindex` identifies the
device for its whole life; see [Kernel Semantics Notes](#kernel-semantics-notes).

## Sockets

- `TunnelSocket::for_config` creates the socket a `TunnelConfig` describes;
  `TunnelSocket::udp` and `TunnelSocket::ip` are the lower-level
  constructors.
- `TunnelSocket::from_fd` adopts a bound and connected datagram socket
  prepared elsewhere, for example with `socket2` or through socket
  activation, and `TunnelConfig::for_socket` describes such a socket. The
  socket's addresses, bound device, link-local scope and peer connection ID
  are read back from the kernel. A descriptor that is not such a socket is
  closed together with the error.
- `set_tos`, `set_hop_limit`, `set_mark`, `set_pmtu_discovery` and
  `set_ipv6_dontfrag` cover the common options of tunnel traffic;
  `bind_to_device` applies `SO_BINDTODEVICE`, which needs `CAP_NET_RAW`.
- A `device` is not a scope. The kernel routes through the bound device by
  itself, so the socket never resolves it to an index; a device that
  disappears only matters to the kernel. A link-local scope, by contrast,
  is resolved to the interface index whenever a link-local address is
  bound or connected, and reconnecting to such an address fails with
  `ENODEV` while the scope's interface is gone. Other addresses need no
  scope and resolve none.
- `disconnect` issues `connect(AF_UNSPEC)`: the kernel forgets the peer,
  the source address it selected and `SO_BINDTODEVICE`, while an L2TP/IP
  socket's connection ID stays bound. Bind the device again if needed, then
  `reconnect_ip` or `reconnect_udp` to have the source address selected
  afresh, for example after the addresses of the underlying interface
  changed.
- `local_addr_udp`, `peer_addr_udp`, `local_addr_ip` and `peer_addr_ip`
  report the current addresses.
- The kernel delivers L2TP control messages on the tunnel socket.
  `TunnelSocket` implements `AsFd`, and `try_clone_fd` duplicates the
  descriptor so the control plane can wrap it in an async UDP socket.

## Kernel Semantics Notes

- `L2TP_ATTR_IFNAME` applies to sessions (`SESSION_CREATE`/session lookups), not tunnels.
  Tunnels do not create a netdevice. Sessions can be looked up, modified and
  deleted by interface name.
- **The session interface name is frozen at creation.** The kernel copies the
  `l2tpeth` device's name into the session once, right after registering the
  device, and never updates it. An interface renamed later, by `ip link`,
  udev or systemd-networkd, is still reported by `SessionInfo::ifname` and
  matched by the `*_by_ifname` methods under its original name, never its
  current one. Track these devices by interface index instead:
  `SessionHandle::ifindex` carries it, and rtnetlink addresses a device by
  index for everything including renames. Only L2TPv3 sessions are searched
  by name.
- L2TP netlink does not report the index, and a lookup by name after the
  fact can be defeated by udev or networkd renaming the new device at once.
  `create_session` therefore joins `RTNLGRP_LINK` before it sends
  `SESSION_CREATE`: the kernel broadcasts the device's registration as
  `RTM_NEWLINK` with change mask `~0` (renames use `0`) before it
  acknowledges the creation, so the notification naming the new interface,
  with its index, is already queued when the session exists. Only a lost
  notification falls back to a lookup by name, as the `open_*` methods
  always do. Request an explicit, unique `SessionConfig::ifname` rather than
  the kernel's `l2tpeth%d` pool, so no other device can hold the name while
  this one does.
- Tunnel deletion is acknowledged before the kernel tears the tunnel down on
  a work queue. `delete_tunnel` and `TunnelHandle::delete` wait until the
  tunnel is gone, so its identifier can be reused immediately afterwards. If
  it is still listed after about two seconds they return
  `Error::DeletionPending`; the deletion is not undone, so treat the tunnel
  as deleted (a repeated deletion fails with `ENODEV`).
- Generic netlink assigns the `l2tp` family identifier dynamically. A handle
  caches it and re-resolves once when the kernel answers `ENOENT` for a
  request, so it survives a reload of `l2tp_netlink`; an `Events` stream
  does not, so subscribe again after a module reload.
- Lookups of a missing tunnel or session fail with `ENODEV`.
- The kernel never records a peer port for IPv4 L2TP/IP sockets, so
  `getpeername` reports `ENOTCONN` for them. `TunnelSocket::peer_addr_ip`
  therefore reports the peer the socket connected to itself, which an IPv4
  L2TP/IP socket adopted with `from_fd` does not know: describe such a
  socket with `TunnelConfig::new` instead of `TunnelConfig::for_socket`.
- The kernel accepts the L2-specific sublayer type (`L2TP_ATTR_L2SPEC_TYPE`)
  when a session is created but never reports it, so `SessionInfo::l2spec_type`
  is `None` and the CLI shows `unknown`.
- `SessionConfig::eth`, `SessionConfig::ppp` and the CLI default the
  L2-specific sublayer to `L2SpecType::None`. The kernel and iproute2 default
  to `L2SpecType::Default`; set `l2spec_type` to `L2SpecType::Default` (CLI:
  `--l2spec default`) when matching a peer configured with that default.
  Both peers must use the same type for their session wire formats to match.
- The kernel reports the IPv4 UDP checksum setting (`L2TP_ATTR_UDP_CSUM`) only
  for IPv4 sockets. `TunnelInfo` therefore shows `udp_csum: false` for every
  IPv6 tunnel, even when its IPv4-mapped peer receives checksums.
- The kernel does not report IPv6 scope IDs or flow labels, so `TunnelInfo`
  UDP endpoints have them set to `0` and IP endpoints have no scope.
- Managed tunnels are fd-backed. When the managed tunnel socket is closed, the kernel
  tears down that tunnel and its sessions. Sockets are created with `SOCK_CLOEXEC`
  so child processes do not keep tunnels alive.
- The kernel cannot change tunnel parameters after creation, so there is no tunnel
  modify operation. Session parameters can be changed with `SessionHandle::modify`.
- The kernel's session dump ignores the tunnel filter; `list_sessions` filters the
  dump on the client side.

## Unmanaged Tunnels

For kernel-managed tunnels without `L2TP_ATTR_FD`:

```rust,ignore
let cfg = TunnelConfig::new(/* ... */)?;
let tunnel = handle.create_unmanaged_tunnel(cfg).await?;
```

## Common Operations

```rust,ignore
let tunnels = handle.list_tunnels().await?;
let sessions = handle.list_all_sessions().await?;

let tstats = handle.tunnel_stats(TunnelId(1000)).await?;
let sstats = handle.session_stats(TunnelId(1000), SessionId(3000)).await?;

// Existing objects, for example created by another process.
let tunnel = handle.open_tunnel(TunnelId(1000)).await?;
let session = handle.open_session_by_ifname(&"l2tpeth0".parse()?).await?;
```

## Handle Lifetime

- `TunnelHandle` and `SessionHandle` returned by the `create_*` methods
  default to `auto_delete = true`; those returned by the `open_*` methods
  default to `false`.
- Tunnel and session creation keeps ownership through the kernel acknowledgement
  even if the caller is cancelled. Successful creations that the caller no longer
  receives are cleaned up. Keep the Tokio runtime running until this work finishes.
- On drop, they spawn best-effort async delete calls onto the current Tokio runtime.
  These run after the drop returns, so they can race with re-creating the same ID.
- Prefer `tunnel.delete().await?` / `session.delete().await?`, which delete
  deterministically and report errors.
- Use `set_auto_delete(false)` if you want to avoid those best-effort netlink delete calls.
- For managed tunnels, dropping the handle still closes the owned tunnel socket fd,
  which causes the kernel to remove the tunnel/session datapath.

## Error Handling

Match kernel errors by kind without depending on `libc`:

```rust,ignore
match handle.create_unmanaged_tunnel(cfg).await {
    Err(e) if e.kind() == Some(std::io::ErrorKind::AlreadyExists) => { /* ID in use */ }
    other => { /* ... */ }
}
```

`Error::raw_os_error()` returns the raw errno when one is available. No
public function panics on its input; conditions such as a missing Tokio I/O
driver, an invalid interface name or an unsupported protocol version are
reported as errors.

## Logging

The crate logs netlink requests and failures through the `log` crate at
`debug` and `trace` level.

## Upgrading from 0.2

0.3.0 was never published; its changes ship in 0.4.0.

- The `l2tp` binary now requires `--features cli` (see above).
- `serde` derives on the statistics types now require the `serde` feature.
- Modules are private; import everything from the crate root (e.g. `l2tp::L2tpHandle`).
- `TunnelModify`, `TunnelHandle::modify` and `L2tpHandle::modify_tunnel` were removed:
  the kernel accepted these requests but did not apply their UDP checksum setting.
- `TunnelSocket::ip` takes `TunnelId`s for the tunnel and its peer instead of a `u32`.
- `delete_tunnel` and `TunnelHandle::delete` wait, for up to about two
  seconds, until the kernel has removed the tunnel. A tunnel still listed
  after that is `Error::DeletionPending`, which callers must treat as
  deleted: the acknowledged deletion completes on its own, and repeating it
  fails with `ENODEV`. Code that kept its tunnel state on any error from
  `delete_tunnel` would otherwise never remove it.
- `SessionInfo::ifname` and the `*_by_ifname` methods carry the
  creation-time name only; rename and otherwise address `l2tpeth` devices
  by `SessionHandle::ifindex`. See [Kernel Semantics Notes](#kernel-semantics-notes).
- Reconnecting an L2TP/IP socket resolves its link-local scope only when a
  link-local address is involved. A socket created with a `device` no longer
  needs that device to exist to reconnect to a global address, and
  `disconnect` forgets the device as the kernel does; call `bind_to_device`
  again before reconnecting if the binding is still wanted.
- `IpEndpoint::V6` is a struct variant with an `addr` and an optional
  interface `scope`; use `IpEndpoint::v6(addr)` or
  `IpEndpoint::v6_scoped(addr, ifname)`. Link-local endpoints without a scope
  are rejected with `Error::ScopeRequired` by `TunnelSocket::ip` and
  `TunnelSocket::udp`, and unmanaged tunnels reject link-local endpoints
  with `Error::UnmanagedLinkLocal`.
- Interface names are `L2tpIfName` from `netlink-packet-l2tp`; the crate's
  own `IfName` is gone, and `L2tpIfNameExt` adds the OS conversions.
- `TunnelInfo::proto_version` is `TunnelInfo::version`, an `L2tpVersion`.
- `SessionInfo` gained `peer_tunnel_id`, `cookie` and `peer_cookie`, and its
  `l2spec_type` is an `Option` that is `None` when the kernel does not report
  the sublayer type, which current kernels never do.
- `Cookie` is `Copy`, parses from hexadecimal, and is built with `TryFrom` or
  `From<[u8; 4]>`/`From<[u8; 8]>` instead of `try_from_bytes`.
- `L2tpHandle::new` returns `Error::Io` instead of panicking when the Tokio
  runtime has no I/O driver.
- `Error` is `#[non_exhaustive]`. `Error::Netlink` holds a message instead of a
  `netlink-packet-core` type and also reports invalid attribute values such as
  interface names. Malformed kernel replies are reported as
  `Error::UnexpectedReply` instead of a synthetic `KernelError`, and socket
  encapsulation mismatches as `Error::EncapsulationMismatch` instead of
  `Error::UnmanagedSocket`. `TunnelSocket::set_ipv6_dontfrag` errors are `Error::Io`.
- `PseudowireType` and `L2SpecType` are `#[non_exhaustive]` and have `Other(..)`
  variants for values this crate does not name.
- `TunnelInfo`, `SessionInfo`, `TunnelStats` and `SessionStats` are `#[non_exhaustive]`.

## Running Tests

Standard tests:

```bash
cargo test
```

Privileged tests (require root/CAP_NET_ADMIN and matching kernel modules):

```bash
cargo test --test privileged -- --ignored
```

## CLI tunnel lifetime

`l2tp tunnel create` creates an unmanaged, kernel-owned tunnel that survives
command exit. Remove it with `l2tp tunnel delete`. Checksum flags apply to the
kernel-created socket. The socket-only flags `--device` and `--ipv6-dontfrag`
are unsupported by persistent CLI tunnels and return an error; use the library's
managed tunnel API when those socket options are needed.

`--no-udp-csum` is rejected when the remote peer is IPv4-mapped on an IPv6
socket, including when an IPv4 `--remote` is automatically mapped to match an
IPv6 `--local`. Use IPv4 endpoints for both addresses, or the library's managed
tunnel API, to disable IPv4 checksums. Mapped tunnels with checksums enabled
remain supported.

Link-local addresses, with or without a `%ifname` zone suffix, are rejected
for the same reason: the kernel-created socket has no interface scope. Use the
library's managed tunnel API for link-local endpoints.

Automatically chosen tunnel IDs come from `getrandom(2)`; when that fails the
command reports the error instead of falling back to a predictable source.
Pass `--tunnel-id` to choose the ID yourself.

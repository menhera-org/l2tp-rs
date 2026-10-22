# l2tp-rs

High-level async L2TPv3 control API for Linux Generic Netlink.

This crate focuses on L2TP tunnel/session lifecycle and query operations only.
It does **not** configure interfaces/bridges/routes (`rtnetlink` tasks belong in a separate crate).

## Requirements

- Linux. On other platforms the crate compiles but exposes no API, and the `l2tp`
  binary only reports that the platform is unsupported.
- Rust 1.89 or newer (required by the netlink dependencies).
- Linux kernel with L2TP Generic Netlink support (`l2tp` family).
- Tokio runtime with its I/O driver enabled. `L2tpHandle::new` returns an
  error without one.
- `CAP_NET_ADMIN` (or root) for every L2TP netlink command, including `get`
  and `list`; the kernel marks them all `GENL_UNS_ADMIN_PERM`.

## Installation

```toml
[dependencies]
l2tp = "0.3"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### Cargo features

- `serde`: derives `Serialize`/`Deserialize` for `TunnelStats` and `SessionStats`.
- `cli`: builds the `l2tp` command-line tool (implies `serde`).

No features are enabled by default, so library users do not pull in the CLI's
dependencies.

## Command-Line Tool

The `l2tp` binary is behind the `cli` feature since 0.3. If you previously
installed it with `cargo install l2tp`, install it with:

```bash
cargo install --features cli l2tp
```

From a checkout, use `cargo run --features cli -- <args>`.

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

    // Managed socket: fd is passed via L2TP_ATTR_FD and owned by TunnelHandle.
    let socket = TunnelSocket::udp(&local, &remote, None)?;

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

    let tunnel = handle.create_tunnel(tunnel_cfg, socket).await?;

    let session_cfg = SessionConfig::eth(tunnel.tunnel_id(), SessionId(3000), SessionId(4000));
    let session = handle.create_session(session_cfg).await?;

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

    let socket = TunnelSocket::ip(&local, &remote, None, TunnelId(5000))?;
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
interface index each time the socket binds, connects or reconnects, so the
tunnel keeps working with an interface that was re-created under a new index.
The scopes of both endpoints and the `device` must name the same interface.

```rust,no_run
use l2tp::{
    Encapsulation, IfName, IpEndpoint, L2tpHandle, TunnelConfig, TunnelId,
    TunnelSocket,
};
use std::net::Ipv6Addr;

#[tokio::main]
async fn main() -> l2tp::Result<()> {
    let handle = L2tpHandle::new().await?;

    let eth0: IfName = "eth0".parse()?;
    let local =
        IpEndpoint::v6_scoped(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), eth0);
    // A link-local peer without a scope uses the local endpoint's interface.
    let remote = IpEndpoint::v6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));

    let socket = TunnelSocket::ip(&local, &remote, None, TunnelId(7000))?;
    let cfg = TunnelConfig::new(
        TunnelId(7000),
        TunnelId(8000),
        Encapsulation::Ip { local, remote },
    )?;

    let _tunnel = handle.create_tunnel(cfg, socket).await?;
    Ok(())
}
```

UDP endpoints carry the numeric scope ID of `SocketAddrV6`. Resolve the name
with `IfName::index()` right before creating or reconnecting the socket:

```rust,ignore
let scope_id = IfName::new("eth0")?.index()?;
let local = UdpEndpoint::V6(SocketAddrV6::new(link_local, 1701, 0, scope_id));
```

A link-local remote may omit the scope ID once the local endpoint, the
`device`, or an earlier scoped connect has pinned the socket to an interface.
Both socket types report a missing scope as `Error::ScopeRequired` before
the socket is created.

Unmanaged tunnels cannot use link-local endpoints, because the kernel creates
their socket without an interface scope; `create_unmanaged_tunnel` returns
`Error::UnmanagedLinkLocal` before contacting the kernel. Re-creating a tunnel
after its interface disappears is left to the application; this crate does
not watch rtnetlink link events.

## Interface Names

`IfName` is a checked, `Copy` value for Linux interface names, stored
NUL-padded like the kernel's `char ifname[IFNAMSIZ]`. `IfName::new`,
`str::parse` and the `TryFrom` conversions from `&str`, `String`, `&[u8]`,
`Vec<u8>`, `&OsStr`, `&CStr` and `[u8; IFNAMSIZ]` validate the name with the
kernel's `dev_valid_name()` rules: non-empty, at most `IFNAMSIZ - 1` bytes,
not `.` or `..`, and no NUL, `/`, `:` or whitespace. A rejected name yields
`Error::InvalidIfName` with an `IfNameError` that names the rule.

Names are byte strings and need not be UTF-8. Read one back with `as_bytes`,
`as_array`, `to_str` (`None` for a non-UTF-8 name), `to_string_lossy`,
`as_os_str`, `as_c_str`, `Display` (lossy) or the `From<IfName>` conversions
into `[u8; IFNAMSIZ]`, `Vec<u8>` and `OsString`. `IfName::index` and
`IfName::from_index` convert between names and the kernel's interface
indexes. Interface names appear in the public API only as `IfName`; the CLI
validates `--ifname` and `--device` while parsing and accepts non-UTF-8
arguments.

`netlink-packet-l2tp` 0.3 carries `L2TP_ATTR_IFNAME` as a `String`. Until a
release that carries the raw bytes is adopted, creating a session with a
non-UTF-8 interface name fails with `Error::Netlink`, and a session listing
that contains such a name fails to decode.

## Binding Managed Sockets to an Interface

Use `IfName` with managed sockets:

- At creation:
  - `TunnelSocket::udp(..., Some(&ifname))`
  - `TunnelSocket::ip(..., Some(&ifname), ...)`
- After creation:
  - `tunnel.socket().unwrap().bind_to_device(&ifname)?`

`SO_BINDTODEVICE` requires `CAP_NET_RAW`. A link-local scope only selects the
interface of a link-local address and needs no extra capability.

## Kernel Semantics Notes

- `L2TP_ATTR_IFNAME` applies to sessions (`SESSION_CREATE`/session lookups), not tunnels.
  Tunnels do not create a netdevice.
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
```

## Handle Lifetime

- `TunnelHandle` and `SessionHandle` default to `auto_delete = true`.
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

`Error::raw_os_error()` returns the raw errno when one is available.

## Upgrading from 0.2

- The `l2tp` binary now requires `--features cli` (see above).
- `serde` derives on the statistics types now require the `serde` feature.
- Modules are private; import everything from the crate root (e.g. `l2tp::L2tpHandle`).
- `TunnelModify`, `TunnelHandle::modify` and `L2tpHandle::modify_tunnel` were removed:
  the kernel accepted these requests but did not apply their UDP checksum setting.
- `TunnelSocket::ip` takes a `TunnelId` instead of a `u32`.
- `IpEndpoint::V6` is a struct variant with an `addr` and an optional
  interface `scope`; use `IpEndpoint::v6(addr)` or
  `IpEndpoint::v6_scoped(addr, ifname)`. Link-local endpoints without a scope
  are rejected with `Error::ScopeRequired` by `TunnelSocket::ip` and
  `TunnelSocket::udp`, and unmanaged tunnels reject link-local endpoints
  with `Error::UnmanagedLinkLocal`.
- `L2tpHandle::new` returns `Error::Io` instead of panicking when the Tokio
  runtime has no I/O driver.
- `IfName` is a `Copy` value holding the kernel's NUL-padded
  `[u8; IFNAMSIZ]` buffer, and names need not be UTF-8. `as_str` is replaced
  by `to_str`, `to_string_lossy` and `as_bytes`; `AsRef<str>` and
  `From<IfName> for String` by `AsRef<[u8]>`, `AsRef<OsStr>`, `AsRef<CStr>`
  and `From<IfName>` for `[u8; IFNAMSIZ]`, `Vec<u8>` and `OsString`.
- `Error::InvalidIfName` carries an `IfNameError` reason instead of the
  rejected string.
- `Error` is `#[non_exhaustive]`. `Error::Netlink` holds a message instead of a
  `netlink-packet-core` type. Malformed kernel replies are reported as
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

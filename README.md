# l2tp-rs

High-level async L2TPv3 control API for Linux Generic Netlink.

This crate focuses on L2TP tunnel/session lifecycle and query operations only.
It does **not** configure interfaces/bridges/routes (`rtnetlink` tasks belong in a separate crate).

## Requirements

- Linux. On other platforms the crate compiles but exposes no API, and the `l2tp`
  binary only reports that the platform is unsupported.
- Rust 1.89 or newer (required by the netlink dependencies).
- Linux kernel with L2TP Generic Netlink support (`l2tp` family).
- Tokio runtime.
- `CAP_NET_ADMIN` (or root) for most create/modify/delete operations.

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

## Binding Managed Sockets to an Interface

Use `IfName` with managed sockets:

- At creation:
  - `TunnelSocket::udp(..., Some(&ifname))`
  - `TunnelSocket::ip(..., Some(&ifname), ...)`
- After creation:
  - `tunnel.socket().unwrap().bind_to_device(&ifname)?`

`SO_BINDTODEVICE` requires `CAP_NET_RAW`.

## Kernel Semantics Notes

- `L2TP_ATTR_IFNAME` applies to sessions (`SESSION_CREATE`/session lookups), not tunnels.
  Tunnels do not create a netdevice.
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

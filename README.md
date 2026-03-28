# l2tp-rs

High-level async L2TPv3 control API for Linux Generic Netlink.

This crate focuses on L2TP tunnel/session lifecycle and query operations only.
It does **not** configure interfaces/bridges/routes (`rtnetlink` tasks belong in a separate crate).

## Requirements

- Linux kernel with L2TP Generic Netlink support (`l2tp` family).
- Tokio runtime.
- `CAP_NET_ADMIN` (or root) for most create/modify/delete operations.

## Installation

```toml
[dependencies]
l2tp = "0.2.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Quick Start

### Managed UDP tunnel + Ethernet session

```rust
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

```rust
use l2tp::{Encapsulation, IpEndpoint, L2tpHandle, TunnelConfig, TunnelId, TunnelSocket};
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> l2tp::Result<()> {
    let handle = L2tpHandle::new().await?;

    let local = IpEndpoint::V4(Ipv4Addr::new(192, 0, 2, 1));
    let remote = IpEndpoint::V4(Ipv4Addr::new(192, 0, 2, 2));

    let socket = TunnelSocket::ip(&local, &remote, None, 5000)?;
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

`SO_BINDTODEVICE` typically requires `CAP_NET_ADMIN`.

## Kernel Semantics Notes

- `L2TP_ATTR_IFNAME` applies to sessions (`SESSION_CREATE`/session lookups), not tunnels.
  Tunnels do not create a netdevice.
- Managed tunnels are fd-backed. When the managed tunnel socket is closed, the kernel
  tears down that tunnel and its sessions.

## Unmanaged Tunnels

For kernel-managed tunnels without `L2TP_ATTR_FD`:

```rust
let cfg = TunnelConfig::new(/* ... */)?;
let tunnel = handle.create_unmanaged_tunnel(cfg).await?;
```

## Common Operations

```rust
let tunnels = handle.list_tunnels().await?;
let sessions = handle.list_all_sessions().await?;

let tstats = handle.tunnel_stats(TunnelId(1000)).await?;
let sstats = handle.session_stats(TunnelId(1000), SessionId(3000)).await?;
```

## Handle Lifetime

- `TunnelHandle` and `SessionHandle` default to `auto_delete = true`.
- On drop, they spawn best-effort async delete calls.
- Use `set_auto_delete(false)` if you want to avoid those best-effort netlink delete calls.
- For managed tunnels, dropping the handle still closes the owned tunnel socket fd,
  which causes the kernel to remove the tunnel/session datapath.

## Running Tests

Standard tests:

```bash
cargo test
```

Privileged tests (require root/CAP_NET_ADMIN and matching kernel modules):

```bash
cargo test --test privileged -- --ignored
```

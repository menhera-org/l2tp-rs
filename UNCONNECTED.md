# Task: a bound, unconnected L2TP/IP tunnel socket

rs-l2tpd creates every tunnel *disconnected*: the socket is bound with
its connection id and the tunnel registered on it, and the peer is
connected later, when a route and a source exist (its spec T1, T6, K5).
The kernel supports this (`l2tp_tunnel_register` checks no socket state;
`l2tp_xmit_core` drops frames while `sk_state != TCP_ESTABLISHED`), and
`create_tunnel` with `L2TP_ATTR_FD` ignores the address attributes
(`l2tp_core.c`, `l2tp_tunnel_create`: `fd >= 0` takes `sockfd_lookup`).

The crate cannot express it: `TunnelSocket::ip` (`socket.rs:269-323`)
binds and connects in one constructor, and building the socket outside
the crate needs `sockaddr_l2tpip6`, which is unsafe code the daemon's
library forbids. `from_fd` (`:368`) already accepts an unconnected
socket, `disconnect` (`:597`) and `reconnect_ip` (`:718`) already do the
rest.

Release as **0.4.2**. Additive only.

## Add

```rust
impl TunnelSocket {
    /// Like [`ip`](Self::ip), but only binds: no peer is connected until
    /// [`reconnect_ip`](Self::reconnect_ip). The tunnel may be registered
    /// on it meanwhile; the kernel drops what its sessions send until the
    /// first connect. `peer_tunnel_id` is remembered for the reconnect.
    /// A link-local `local` needs a scope or a `device`, as for `ip`.
    pub fn ip_unconnected(
        local: &IpEndpoint,
        device: Option<&L2tpIfName>,
        tunnel_id: TunnelId,
        peer_tunnel_id: TunnelId,
    ) -> crate::Result<Self>;

    /// `SO_BINDTOIFINDEX`: binds by index, so a device that takes the name
    /// between a lookup and the bind cannot be bound to. Same privilege
    /// rule as `bind_to_device`: none on a socket without a binding,
    /// `CAP_NET_RAW` to replace one.
    pub fn bind_to_device_index(&self, index: u32) -> crate::Result<()>;
}
```

- `ip_unconnected`: the body of `ip` without the `connect` call and
  without `remote`; `scope_id` from `local` only; `Link { pinned:
  device.is_some() || local.is_link_local(), peer_v4: 0, connected:
  false, device }`.
- `bind_to_device_index`: `setsockopt(SOL_SOCKET, SO_BINDTOIFINDEX,
  &index)`; records `pinned = true` and `device = None` (the cache keeps
  names only; `bound_device` in `from_fd` reads the name back through
  `SO_BINDTODEVICE`, which the kernel answers for an index binding too).
- `TunnelConfig::for_socket` on an unconnected socket: `encapsulation()`
  must not fail on a missing peer; report the remote as the unspecified
  address of the family, and document that `create_tunnel` with a
  descriptor ignores the addresses.
- `peer_addr_ip` keeps reporting `ENOTCONN` until the first reconnect.

## Tests

- Unit: `ip_unconnected` then `local_addr_ip` reports the bound local
  address and `peer_addr_ip` fails `ENOTCONN`; `reconnect_ip` to
  `::1` then succeeds and `peer_addr_ip` reports it; `disconnect` returns
  to `ENOTCONN`.
- Privileged: register a tunnel and an Ethernet session on an
  unconnected socket, send a frame into the device, read `tx_dropped`
  rising on it; `reconnect_ip`, and the frame reaches the peer.
- Unit: `bind_to_device_index(lo index)`, then `from_fd` on a duplicate
  reports `lo` as the bound device.

## Out of scope

UDP sockets (`udp` also connects; rs-l2tpd uses IP encapsulation only).

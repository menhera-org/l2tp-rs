# l2tp 0.4.4: what rs-l2tpd needs

Instruction for the 0.4.4 release of this crate. It adds three things the
rs-l2tpd rewrite (`../rs-l2tpd`, phase 2) found missing. Today rs-l2tpd works
around each one; the workarounds are listed under "upstream needs" in
`../rs-l2tpd/docs/dependencies.md` and marked `shortcut:` in its
`src/kernel/linux/`. Each change below is an addition or a widening, so 0.4.4
stays a compatible patch release of 0.4.3.

## Rules

- **Compatibility:** change no existing signature, default or timeout
  behaviour. The existing blocking calls stay as they are; rs-l2tpd keeps its
  own five-second request deadline, so finite request deadlines are out of
  scope here.
- **Safety:** no new `unsafe` beyond what the socket code already needs, each
  block with a `SAFETY:` comment as today.
- **Dependencies:** no new crate. `Cargo.lock` may change only by this crate's
  own version.
- **Tests:** unit tests for the decoding and the accessors. Where the kernel
  is involved, extend the existing privileged tests under
  `src/handle/creation_tests.rs` (or their equivalent) and run them in a
  privileged container, as for 0.4.2 and 0.4.3.
- **Release:**
  - bump `version` to 0.4.4 in `Cargo.toml`;
  - add a `## 0.4.4 (date)` section to `CHANGELOG.md` with `### Added` and
    `### Changed` in the existing style;
  - update the README where it describes the affected API.
- **Publishing:** do not run `cargo publish` without the maintainer's go-ahead.
  When it is given, use `cargo publish --registry crates-io`.
- **Gates:** `cargo fmt --check`, `cargo clippy --all-targets --all-features
  -- -D warnings`, `cargo test --all-features`, and
  `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features` must all pass.

## 1. The identifiers of a `TunnelSocket`

**Need.** rs-l2tpd adopts tunnel sockets handed over by its previous instance
(systemd's descriptor store, or its own re-exec). It must check that each
descriptor carries the tunnel its name says. `TunnelSocket::from_fd` already
reads the bound connection ID back from the kernel and keeps it in the private
field `conn_id`. It keeps the peer's in `peer_conn_id`. Neither is public.
rs-l2tpd's library may not decode `sockaddr_l2tpip`/`sockaddr_l2tpip6` itself,
because it denies `unsafe`. So today it parses the field out of the
`#[derive(Debug)]` output of `TunnelSocket`, which breaks as soon as the
`Debug` form changes.

**Add:**

```rust
impl TunnelSocket {
    /// The connection ID an L2TP/IP socket is bound with (the local tunnel
    /// ID); `None` for a UDP socket.
    pub fn tunnel_id(&self) -> Option<TunnelId>;
    /// The peer tunnel ID used on reconnect: known for sockets created here
    /// and adopted IPv6 L2TP/IP sockets, `None` for an adopted IPv4 one until
    /// `from_fd_with_peer` supplies it, and for UDP.
    pub fn peer_tunnel_id(&self) -> Option<TunnelId>;
}
```

Both return the cached values; neither makes a syscall. Document that
`tunnel_id` is what `from_fd` read with `getsockname`, so it is the kernel's
value, not a cache of the caller's input.

**Tests:**
- every constructor (`ip`, `ip_unconnected`, `udp`, `udp_unconnected`,
  `from_fd`, `from_fd_with_peer`);
- an adopted IPv4 socket gives `peer_tunnel_id() == None` until
  `from_fd_with_peer`.

## 2. Cookies of every length the kernel accepts

**Need.** The kernel accepts a cookie of 0 to 8 bytes, any length in that
range, and reports what it stored:
- `net/l2tp/l2tp_netlink.c:584-602` in 6.8 refuses only `len > 8`;
- `734-736` echo the stored length.

`Cookie` holds only 0, 4 or 8 bytes. So `decode_session_info` (`netlink.rs`,
the `L2tpAttribute::Cookie` and `PeerCookie` arms) fails with
`InvalidCookieLength` for a session someone else created with, for example, a
2-byte cookie. This happens on a single query, and it also aborts a whole
session dump. rs-l2tpd must dump the namespace's sessions to verify a stored
name before deleting by it, and to check staging names. One foreign session
with an odd-length cookie would block both.

**Change:**
- `Cookie::try_from` and the hexadecimal parser accept any length from 0 to 8.
  Lengths above 8 keep failing with `InvalidCookieLength`, the kernel's own
  limit.
- Update the docs ("0, 4 or 8 bytes") and `len`'s doc. Say that RFC 3931 uses
  4 or 8 bytes and that the kernel takes anything up to 8.
- `Display`, `serde` and `as_bytes` follow the length as they do now; check
  that the serde forms round-trip odd lengths.
- Decoding a kernel report must never fail on a cookie the kernel can hold.

**Tests:**
- every length 0–9 through `TryFrom<&[u8]>`, the parser and serde (9 must
  fail);
- `decode_session_info` with 1-, 2- and 7-byte cookies;
- one live case: create a session with a 2-byte cookie, then `get_session`
  and `list_sessions` both succeed and report it.

Note for the CHANGELOG: this widens what is accepted on creation too. That is
deliberate, since the kernel accepts it; a caller that wants RFC lengths only
checks `len()` itself. rs-l2tpd's configuration keeps requiring 4 or 8 bytes.

## 3. A bounded event socket that does not need a runtime when opened

**Need.** rs-l2tpd opens its subscriptions on its reconciler thread and polls
them on a Tokio runtime on another thread. Two things make the current API
unusable for that:
- `L2tpHandle::events_bounded` needs a runtime when it is called and registers
  the descriptor with that runtime's reactor at once, through `AsyncFd`.
- Getting there needs an `L2tpHandle`, which needs a runtime and its own
  netlink-proto connection.

rs-l2tpd therefore resolves the family itself and reads the `l2tp` group on a
raw `netlink-sys` socket. That duplicates this crate's decoding (`Pending`,
`decode`), its sender check and its framing.

**Add** a runtime-free socket type that owns the subscribed descriptor and the
decoder. The caller decides where and when it is registered with an event
loop:

```rust
/// A socket joined to the `l2tp` multicast group, non-blocking, with no task
/// and no queue: notifications wait in its receive buffer (size it through
/// `AsFd`). Usable from any thread; register it with an event loop when and
/// where the caller likes.
pub struct EventSocket { /* netlink_sys::Socket + Pending */ }

impl EventSocket {
    /// Opens and subscribes a socket for a family the caller resolved
    /// itself (`CTRL_CMD_GETFAMILY`: the family ID and the `l2tp` group's
    /// ID), in the calling thread's network namespace. No request is sent.
    pub fn new(family_id: u16, group_id: u32) -> crate::Result<Self>;

    /// The next notification already received or receivable without
    /// blocking: `None` when the socket would block. Same semantics as
    /// `BoundedEvents`: non-kernel senders skipped, `ENOBUFS` reported as
    /// `Error::Io` ahead of the queued notifications, undecodable messages
    /// reported, the subscription continuing afterwards.
    pub fn try_next(&mut self) -> Option<crate::Result<L2tpEvent>>;
}

impl AsFd for EventSocket { /* the netlink socket */ }
impl AsRawFd for EventSocket { /* same */ }
```

Also add:
- **Constructors on both handles:** `L2tpHandle::event_socket()` (async) and
  `blocking::L2tpHandle::event_socket()`, which resolve the family through the
  handle and return an `EventSocket`. The existing crate-private
  `event_socket` returning `(Socket, u16)` can become the public one or back
  it.
- **`BoundedEvents::from_socket(EventSocket) -> crate::Result<BoundedEvents>`:**
  registers with the current runtime at the call, failing as `events_bounded`
  does without one.
- **Reuse:** `events_bounded`, `blocking::L2tpHandle::events_bounded` and
  `BoundedEventIter` are rebuilt on `EventSocket`, so there is one decoder.
  Their behaviour is unchanged.

Keep the existing guarantees and say them in the docs:
- the sender port is checked with `recvmsg`'s address, never the header;
- `NETLINK_NO_ENOBUFS` is never set;
- dropping the socket leaves the group;
- notifications are advisory and may come from another namespace before 7.3.

**Tests:**
- `try_next` on a socket with nothing queued gives `None` without blocking;
- the existing `Pending` unit tests run against `EventSocket`'s decoding path;
- a live case: create and delete a session with a handle, read the
  `SessionDeleted` with `try_next` from an `EventSocket` built with `new` from
  the handle's family and group IDs;
- `from_socket` inside and outside a runtime.

## When done

Report:
- the API as shipped;
- the gate output;
- the live tests run, with the kernel version they ran on;
- the commit, unpublished unless the maintainer said otherwise.

rs-l2tpd then pins 0.4.4 and removes its three workarounds:
- the `Debug` parsing in `src/kernel/linux/socket.rs`;
- the cookie limits on its kernel `SessionInfo`;
- the raw `l2tp` group socket in `src/kernel/linux/l2tp.rs`.

After that, `docs/dependencies.md` and `docs/architecture.md` are updated
there.

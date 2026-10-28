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

## 2. Foreign cookies of every length the kernel accepts, none produced

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

**The rule.** Permit foreign non-conforming lengths; never produce one.
- **Permit:** a cookie the kernel reports for a session someone else created
  may have any length from 0 to 8, and decoding it must succeed, so that
  queries and dumps work in a namespace that holds such a session.
- **Never produce:** this crate never creates a session with a cookie that RFC
  3931 does not allow, which means 0 (none), 4 or 8 bytes. That holds even when
  the caller passes in a cookie it took from a kernel report.

**Change:**
- **Constructors stay as they are:** `Cookie::none`, `TryFrom<&[u8]>`,
  `TryFrom<Vec<u8>>`, `From<[u8; 4]>`, `From<[u8; 8]>`, the hexadecimal parser
  and `serde` deserialisation keep accepting 0, 4 or 8 bytes only. Every other
  length fails with `InvalidCookieLength`, as today. No public way of building
  a `Cookie` yields another length.
- **Decoding widens:** add a crate-private constructor, for example
  `Cookie::from_kernel(&[u8]) -> crate::Result<Cookie>`, that accepts 0 to 8
  bytes and fails only above 8, the kernel's own limit. Use it in
  `decode_session_info` (`netlink.rs`, the `L2tpAttribute::Cookie` and
  `PeerCookie` arms) and wherever else a cookie is decoded from the kernel. So
  only `SessionInfo` and events can hold a non-conforming cookie.
- **Creation refuses:** `encode_session_create` (and so `create_session` on
  both handles) checks that `cookie` and `peer_cookie` are 0, 4 or 8 bytes, and
  fails with `InvalidCookieLength` before anything is sent otherwise. This
  closes the one path a reported cookie could take back to the kernel: copying
  a foreign `SessionInfo`'s cookies into a `SessionConfig`.
- **Inspection:** add `Cookie::is_rfc3931(&self) -> bool` (true for 0, 4 and 8
  bytes) so callers can tell a foreign non-conforming cookie apart.
  - `Display`, `as_bytes`, `len` and `serde` serialisation report the actual
    length.
  - Serialising a non-conforming cookie is allowed, since a report may be
    shown, but deserialising one back fails, like every public constructor.
    Document that asymmetry.
- **Docs:** say "0, 4 or 8 bytes when built here; a kernel report may carry
  any length up to 8 (`l2tp_netlink.c`), which this crate decodes but never
  sends" on `Cookie`, `SessionInfo` and `SessionConfig`.

**Tests:**
- every length 0–9 through `TryFrom<&[u8]>`, the parser and deserialisation:
  only 0, 4 and 8 succeed;
- `from_kernel` with lengths 0–9: 0–8 succeed, 9 fails;
- `decode_session_info` with 1-, 2- and 7-byte cookies succeeds and reports
  them with `is_rfc3931() == false`;
- `create_session` with a `SessionConfig` whose cookie came from such a
  report fails with `InvalidCookieLength`, and no request reaches the kernel
  (a unit test on `encode_session_create`);
- one live case: a session created with a 2-byte cookie by `ip l2tp add
  session ... cookie 0102` (outside this crate, as a foreign object). Then
  `get_session` and `list_sessions` both succeed and report it, and re-creating
  it from the reported `SessionInfo` is refused.

Note for the CHANGELOG, under `### Changed`: session queries and dumps no
longer fail on a session with a non-RFC cookie length, and session creation
now refuses one explicitly. Before this, creation could not receive one,
because no constructor produced it; the new check guards the decoded path.

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
- the cookie limits on its kernel `SessionInfo`, which will then hold the
  reported cookie as `l2tp` decodes it; a foreign non-conforming cookie can
  only make a session fail to match, never be created;
- the raw `l2tp` group socket in `src/kernel/linux/l2tp.rs`.

After that, `docs/dependencies.md` and `docs/architecture.md` are updated
there.

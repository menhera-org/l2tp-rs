# l2tp 0.5.0: public kernel decoding with distinct cookie types

Reviewed on 2026-10-29 against this crate at `1296ed6` and the released
`v0.4.3` API. This is a general-purpose Linux L2TP API; no changes to
downstream projects are part of this task.

## Rationale and corrections

Callers using their own generic-netlink sockets need the same decoding as
the crate's handles. `netlink-packet-l2tp` 0.4.0 rejects cookies other than
0, 4 or 8 bytes, while Linux accepts and reports lengths from 0 through 8.
See the cookie checks and session reporting in
[Linux l2tp_netlink.c](https://github.com/torvalds/linux/blob/master/net/l2tp/l2tp_netlink.c).

The existing internal `KernelMessage` parser already accommodates these
reports. Making it public does not relax emission: the upstream emitter
still validates RFC lengths and panics for a nonstandard cookie. Document
this explicitly instead of claiming decoded messages cannot be emitted.

Keep `Cookie` strictly RFC-conforming. Introduce a distinct `KernelCookie`
for reported values rather than exposing `Cookie::from_kernel`. Changing
the public `SessionInfo.cookie` and `peer_cookie` field types breaks
compatibility with v0.4.3, so release this work as 0.5.0, replacing the
unreleased 0.4.4 version.

## Implementation

- Export `pub struct KernelMessage(pub L2tpMessage)` at the crate root,
  retaining its existing `GenlFamily`, `Emitable` and
  `ParseableParametrized<[u8], GenlHeader>` implementations.
- Add and export `KernelCookie`, with private storage, checked construction
  from bytes accepting 0 through 8, byte/length accessors, hexadecimal
  display, and `is_rfc3931`. It is not an unrestricted byte container.
- Keep all `Cookie` construction and deserialization limited to 0, 4 or 8.
  Provide infallible conversion from `Cookie` to `KernelCookie` and checked
  conversion back, returning `Error::InvalidCookieLength` otherwise.
- Use `KernelCookie` for both reported cookie fields in `SessionInfo`,
  including queries, dumps and notifications. Session configuration stays
  typed as `Cookie`; remove the now-redundant creation-time length check.
- Preserve reported values in CLI output. With `serde`, both types use
  hexadecimal strings in human-readable formats and byte strings otherwise;
  `KernelCookie` must round-trip all allowed lengths.
- Update API docs, README, changelog and package/lockfile versions together.
  Explain the field-type migration and emission limitation. Avoid the old
  claim that every public cookie constructor accepts only RFC lengths.

## Additional 0.5.0 work

- Require Tokio 1.54.1 and replace deprecated `AsyncFd::new` with
  `AsyncFd::register`, documenting ownership safety and preserving error handling.
- Add explicit `HandleConfig { request_timeout: Option<Duration> }` arguments
  to both async and blocking handle constructors. `Default` selects 30 seconds;
  `None` disables timeouts. Apply the setting to family discovery and requests,
  including dumps and family refresh, and document timer-driver requirements.
- Timeouts report `Error::Io` with `TimedOut`. A mutation may have reached the
  kernel: do not claim rollback or retry it automatically. Creation retains
  its existing detached ACK/cleanup path so a timeout cannot close a managed
  descriptor before the kernel consumes it or delete someone else's object.
- Update all callers, docs and tests for the explicit configuration. Cover
  stalled replies, disabled timeouts and late creation acknowledgements.
- Review deprecated APIs and recorded compatibility deferrals. No other
  marked deferrals or open repository issues were found.

## Validation and completion

Keep coverage for strict cookie construction and kernel-length limits.
Test checked conversion in both directions, text/binary serde round trips,
and parsing a `GenlMessage<KernelMessage>` with a three-byte cookie from an
external integration test. Check both cookie attributes and rejection of
oversized or malformed data. Retain session/event decoding coverage.
Run formatting, tests, Clippy and documentation checks using musl on Linux.

Commit this corrected instruction before implementation, then delete it
when implementation is complete. Commit and push the completed work.

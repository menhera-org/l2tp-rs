# l2tp 0.4.4, addendum: the lenient decoder must be public

Checked on 2026-10-29 against commit `6f5b400` (0.4.4, unreleased) and the
rs-l2tpd phase 2 code (`../rs-l2tpd/src/kernel/linux/`). Items 1 and 3 of
the original instruction are complete and usable as shipped. Item 2 is
complete for this crate's own handles but does not reach rs-l2tpd, for one
reason:

rs-l2tpd sends its generic-netlink requests on its own socket (it needs a
five-second deadline, which the handles do not offer, and it must not need
a runtime), and decodes the replies with `netlink-packet-l2tp` 0.4.0's
`L2tpMessage::parse_with_param`. That parser refuses a cookie whose length
is not 0, 4 or 8 (`attribute.rs:760-770`, `validate_cookie_len`), so one
foreign session with a 2-byte cookie still fails rs-l2tpd's whole session
dump. 0.4.4 fixed exactly this in `netlink.rs:87-109` (`KernelMessage`,
which takes any cookie up to 8 bytes before falling back to the upstream
parser) and `types.rs:135` (`Cookie::from_kernel`), but both are
`pub(crate)`.

## Add, in 0.4.4

```rust
/// A message as the kernel sends it: like `L2tpMessage`, but a cookie of
/// any length up to 8 bytes is accepted (`l2tp_netlink.c` refuses only
/// longer ones), so a reply or notification describing a session created
/// elsewhere decodes. Emitting is unchanged.
pub struct KernelMessage(pub L2tpMessage);
// with its existing GenlFamily, Emitable and
// ParseableParametrized<[u8], GenlHeader> impls, re-exported from the crate
// root

impl Cookie {
    /// A cookie as the kernel reported it: 0 to 8 bytes, any length.
    /// Fails above 8. The only way to build a non-RFC-3931 length; see
    /// `is_rfc3931`.
    pub fn from_kernel(bytes: &[u8]) -> crate::Result<Self>;
}
```

Nothing else changes: `SessionInfo` keeps decoding through the same path,
creation keeps refusing a non-conforming cookie, every other constructor
keeps 0, 4 or 8.

Tests: the existing `KernelMessage` and `from_kernel` unit tests, plus one
that parses a `GenlMessage<KernelMessage>` from the bytes of a reply
carrying a 3-byte cookie and reads it back through `from_kernel`.

CHANGELOG, under `### Added` of 0.4.4: "`KernelMessage` and
`Cookie::from_kernel` are public, for callers that decode kernel replies
themselves."

rs-l2tpd then replaces `L2tpMessage::parse_with_param` with
`KernelMessage` in `src/kernel/linux/l2tp.rs` and stores the reported
cookie as `l2tp::Cookie` in its kernel `SessionInfo`.

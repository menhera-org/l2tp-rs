# Task: drop the `/proc` requirement

The crate must work on a host where `/proc` is not mounted or not
accessible (a chroot, a sandboxed daemon with `ProcSubset=`, an Android
app). Today `L2tpHandle::new`, `PppSocket::connect` and `PppUnit::new`
fail without it, because each opens `/proc/thread-self/ns/net`
(`netns.rs:33-35`) at creation. Nothing in the L2TP protocol needs that
file: the kernel places every socket in the namespace of the thread
that creates it, and that is all the crate ever relies on.

Release as **0.4.1**. No public item is removed.

## Where `/proc` is read today, and what for

| Site | Why | Replacement |
|---|---|---|
| `handle.rs:147` `NetNs::current()` in `connect` | Remember the namespace so that later sockets (the event connection at `:763`, `LinkMonitor` at `:290`, `index_by_name` at `:387`) can be opened in it from any thread | Remember a namespace *identity* (the cookie below) and, only when `/proc` happens to be readable, the descriptor as well |
| `netns.rs:51-61` `run_if_needed` → `same_as(&Self::current())` | Decide between running inline and `setns` on a helper thread; opens `/proc` on every call | Compare cookies: inline when the calling thread's cookie equals the handle's |
| `netns.rs:43-47` `same_as` (inode comparison) | Identity of two descriptors | Cookies; the function goes |
| `ppp.rs:131`, `:221` `NetNs::current()` | Identity for the `NamespaceMismatch` check at `:270` and the helper thread at `:278` | Cookies for the check; descriptor only when available |
| `socket.rs:1696` `/proc/net/if_inet6` | A test helper | Skip the test when the file is absent |

Already independent of `/proc` and unchanged: `socket::interface_index`
(`SIOCGIFINDEX` on the socket itself, `socket.rs:1221`),
`L2tpIfNameExt::index` (`if_nametoindex`, `types.rs:350`),
`LinkMonitor::registered_index`, every netlink request.

## The namespace identity: `SO_NETNS_COOKIE`

`getsockopt(fd, SOL_SOCKET, SO_NETNS_COOKIE)` returns a `u64` that is
unique per network namespace for the kernel's lifetime
(`net/core/sock.c:1981-1986` in 6.8; since Linux 5.14). `SOL_SOCKET`
options are answered by the socket layer for every socket family
(`net/socket.c:2369-2370`), so it works on netlink, L2TP/IP and
`PPPoL2TP` sockets alike. No file, no privilege.

```rust
// netns.rs
/// Identity of a network namespace, from `SO_NETNS_COOKIE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct NsId(u64);

impl NsId {
    /// The namespace `fd` (any socket) lives in. `None` before Linux 5.14
    /// (`ENOPROTOOPT`).
    pub(crate) fn of_socket(fd: BorrowedFd<'_>) -> io::Result<Option<NsId>>;
    /// The calling thread's namespace: the cookie of a throwaway
    /// `socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)`.
    pub(crate) fn of_thread() -> io::Result<Option<NsId>>;
}
```

Use `libc::SO_NETNS_COOKIE`: `libc` 0.2.191 defines it for every
architecture (71, `0x50` on SPARC).

## The namespace handle inside the crate

Replace the `NetNs` field of `L2tpInner`, `PppSocket` and `PppUnit` by
one private type:

```rust
// netns.rs
pub(crate) struct Owner {
    /// `None` on kernels without the cookie: identity unknown.
    id: Option<NsId>,
    /// `Some` only when a descriptor could be opened: `new_in` gave one,
    /// or `/proc` was readable at creation.
    fd: Option<NetNs>,
}

impl Owner {
    /// For `new()`-style creation on the calling thread: id from a scratch
    /// socket (or from `socket` when one is at hand), fd from
    /// `NetNs::current().ok()`.
    pub(crate) fn here(socket: Option<BorrowedFd<'_>>) -> io::Result<Self>;
    /// For `new_in(ns)`: keeps the descriptor; the id is read after the
    /// first socket is created inside it (`run`), so pass it back in.
    pub(crate) fn of(ns: NetNs) -> Self;

    /// Runs `f` where the owner's sockets live.
    pub(crate) fn run_in<T, F>(&self, f: F) -> io::Result<T>
    where F: FnOnce() -> T + Send + 'static, T: Send + 'static
    {
        match (self.id, NsId::of_thread()?) {
            // Same namespace, or no way to tell: the kernel decides.
            (Some(a), Some(b)) if a == b => Ok(f()),
            (None, _) | (_, None) => Ok(f()),
            (Some(_), Some(_)) => match &self.fd {
                Some(ns) => ns.run(f),
                None => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the handle's network namespace is not the calling \
                     thread's and no descriptor for it is held; create the \
                     handle with `new_in` or call from its namespace",
                )),
            },
        }
    }

    pub(crate) fn same_as(&self, other: &Owner) -> Option<bool> {
        Some(self.id? == other.id?)
    }
}
```

`run_in` replaces `NetNs::run_if_needed`; `same_as` on `NetNs` is
deleted. `NetNs::current()` stays public and still opens `/proc`; its
doc says so and names the one thing a descriptor is for: `setns`.

## Changes by file

1. **`netns.rs`**: add `NsId`, `Owner`; remove `same_as` and
   `run_if_needed`; keep `open`, `current`, `try_clone`, `run` and the
   `From`/`AsFd` impls.
2. **`handle.rs`**: `L2tpInner.netns: Owner`. In `connect`, open the
   genl connection first (inline for `new`, through `ns.run` for
   `new_in`), then build the owner from the connection's socket cookie
   (`connection.socket_mut().socket_mut().as_raw_fd()`), so the identity
   is the identity of the socket that was actually created. Replace the
   three `run_if_needed` calls (`open_connection`, `LinkMonitor::open`,
   `index_by_name`) by `run_in`. `Debug` prints the id.
3. **`link.rs`**: `LinkMonitor::open(&Owner)`.
4. **`blocking.rs`**: no change in logic; `start` keeps passing the
   optional `NetNs` through.
5. **`ppp.rs`**: `PppSocket.owner = Owner::here(Some(fd))` (the socket's
   own cookie). `PppUnit.owner = Owner::here(None)` (a `/dev/ppp`
   descriptor is not a socket; the scratch socket on the same thread
   gives the unit's namespace). `connect_channel`: `NamespaceMismatch`
   when `same_as` is `Some(false)`; otherwise `self.owner.run_in(..)`.
   When identities are unknown the kernel still refuses a foreign unit:
   `ppp_connect_channel` looks the unit up in the channel's own
   namespace (`drivers/net/ppp/ppp_generic.c:3502-3507`, `ENXIO`).
6. **Optional, same release**: `NetNs::current()` falls back, when the
   `/proc` open fails, to `ioctl(pidfd_open(getpid()), PIDFD_GET_NET_NAMESPACE)`
   (`_IO(0xFF, 4)`, Linux 6.11+, `include/uapi/linux/pidfd.h:105-110` in
   v7.0). Define the two constants locally; on `ENOTTY`/`EINVAL` return
   the original `/proc` error.
7. **README**: in *Network Namespaces*, replace "Handle and PPP object
   creation retain descriptors opened through `/proc/thread-self/ns/net`,
   so that path must be accessible" by: `/proc` is not required. A
   handle remembers which namespace its sockets live in by their kernel
   cookie; when `/proc` is readable it also keeps a descriptor, so that
   later sockets can be opened from a thread in another namespace. Without
   it, open event connections from a thread in the handle's namespace, or
   create the handle with `new_in`. Add to *Requirements*: nothing of
   the filesystem but `/dev/ppp` for PPP units.
8. **CHANGELOG** 0.4.1, *Fixed*: `L2tpHandle::new`, `PppSocket::connect`
   and `PppUnit::new` no longer need `/proc`; namespace identity comes
   from `SO_NETNS_COOKIE`.

## Tests

- `netns.rs`: two sockets on one thread have equal cookies; a cookie
  read on a non-socket descriptor fails; `Owner::here` on a thread
  equals `Owner::here` on another thread of the same process;
  `run_in` runs inline on the calling thread when ids match (keep the
  thread-id assertion of `current_namespace_executes_inline_without_setns`).
- `handle.rs`: `new_in_the_current_namespace_needs_no_setns_privileges`
  compares owners by `same_as` instead of `NetNs::same_as`.
- `tests/privileged.rs`, new, `--ignored`: **works without procfs**. Spawn
  the test binary again under `unshare -m` (needs `CAP_SYS_ADMIN`, which
  the privileged suite has) with a tmpfs mounted over `/proc`, and in the
  child: `L2tpHandle::new`, `list_tunnels`, a managed IP tunnel with one
  Ethernet session, `session.ifindex()` is `Some`, `events()` opens, drop
  everything. The child reports through its exit status. Skip with a
  message when `unshare` is unavailable.
- `tests/privileged.rs`: a `new_in` test that opens a second namespace
  (`unshare -n` child or `/run/netns`) still passes: `run_in` takes the
  descriptor path there.
- The `/proc/net/if_inet6` helper: `return None` when the file cannot be
  read, which its callers already treat as "no link-local interface".

## Kernel references to cite in comments

- `SO_NETNS_COOKIE`: `net/core/sock.c` (`sk_getsockopt`, `case SO_NETNS_COOKIE`), 5.14+.
- `SOL_SOCKET` handled for every family: `net/socket.c` (`do_sock_getsockopt`).
- Sockets inherit the creating thread's namespace: `net/socket.c` (`sock_create` → `current->nsproxy->net_ns`).
- `setns` needs a descriptor: `kernel/nsproxy.c` (`SYSCALL_DEFINE2(setns)`).
- `PPPIOCCONNECT` finds the unit in the channel's namespace: `drivers/net/ppp/ppp_generic.c` (`ppp_connect_channel`).
- `PIDFD_GET_NET_NAMESPACE`: `include/uapi/linux/pidfd.h`, 6.11+.

## Out of scope

Cross-namespace multicast of L2TP events, the `events` stream's
unbounded channel, and anything about tunnel sockets: none of them
touches `/proc`.

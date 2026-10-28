// SPDX-License-Identifier: MIT

use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

/// `_IO(0xFF, 4)` of `include/uapi/linux/pidfd.h`; `_IOC_NONE` is 1 at bit
/// 29 on MIPS, PowerPC and SPARC and 0 elsewhere.
#[cfg(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "sparc",
    target_arch = "sparc64",
))]
const PIDFD_GET_NET_NAMESPACE: libc::Ioctl = (1 << 29 | 0xFF04) as _;
#[cfg(not(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "sparc",
    target_arch = "sparc64",
)))]
const PIDFD_GET_NET_NAMESPACE: libc::Ioctl = 0xFF04 as _;

/// Identity of a network namespace, from `SO_NETNS_COOKIE`: unique per
/// namespace for the kernel's lifetime (`sk_getsockopt` in
/// `net/core/sock.c`, Linux 5.14+).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct NsId(u64);

impl NsId {
    /// The namespace `fd` (any socket) lives in. `None` before Linux 5.14
    /// (`ENOPROTOOPT`). `SOL_SOCKET` options are answered for every family
    /// (`do_sock_getsockopt` in `net/socket.c`).
    pub(crate) fn of_socket(fd: BorrowedFd<'_>) -> io::Result<Option<NsId>> {
        let mut cookie: u64 = 0;
        let mut len = size_of::<u64>() as libc::socklen_t;
        // SAFETY: the kernel writes at most `len` bytes through the pointer.
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NETNS_COOKIE,
                (&raw mut cookie).cast(),
                &mut len,
            )
        };
        if rc == -1 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::ENOPROTOOPT) => Ok(None),
                _ => Err(err),
            };
        }
        Ok(Some(NsId(cookie)))
    }

    /// The calling thread's namespace: the cookie of a throwaway socket,
    /// which the kernel creates there (`sock_create` in `net/socket.c`).
    pub(crate) fn of_thread() -> io::Result<Option<NsId>> {
        // SAFETY: plain socket creation; the descriptor is owned exactly once.
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly created descriptor.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        Self::of_socket(socket.as_fd())
    }
}

/// The network namespace that a handle's or PPP object's sockets live in.
#[derive(Debug)]
pub(crate) struct Owner {
    /// `None` on kernels without the cookie: identity unknown.
    id: Option<NsId>,
    /// `Some` only when a descriptor could be opened: `new_in` gave one, or
    /// `NetNs::current` worked at creation. Only `setns` needs it
    /// (`kernel/nsproxy.c`).
    fd: Option<NetNs>,
}

impl Owner {
    /// The calling thread's namespace, identified by `socket` when one is
    /// at hand.
    pub(crate) fn here(socket: Option<BorrowedFd<'_>>) -> io::Result<Self> {
        let id = match socket {
            Some(socket) => NsId::of_socket(socket)?,
            None => NsId::of_thread()?,
        };
        Ok(Self {
            id,
            fd: NetNs::current().ok(),
        })
    }

    /// The namespace `ns`; its identity is learned from the first socket
    /// created inside it, through [`identify`](Self::identify).
    pub(crate) fn of(ns: NetNs) -> Self {
        Self {
            id: None,
            fd: Some(ns),
        }
    }

    /// Records the identity of the namespace `socket` was created in.
    pub(crate) fn identify(
        &mut self,
        socket: BorrowedFd<'_>,
    ) -> io::Result<()> {
        self.id = NsId::of_socket(socket)?;
        Ok(())
    }

    /// Runs `f` where the owner's sockets live: inline when that is the
    /// calling thread's namespace, which needs no privilege, otherwise on a
    /// temporary thread through [`NetNs::run`].
    pub(crate) fn run_in<T, F>(&self, f: F) -> io::Result<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        match (self.id, NsId::of_thread()?) {
            (Some(a), Some(b)) if a == b => Ok(f()),
            (Some(_), Some(_)) => match &self.fd {
                Some(ns) => ns.run(f),
                None => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the handle's network namespace is not the calling \
                     thread's and no descriptor for it is held; create the \
                     handle with `new_in` or call from its namespace",
                )),
            },
            // Identity unknown: a held descriptor still decides; without
            // one the kernel does, in the calling thread's namespace.
            _ => match &self.fd {
                Some(ns) if !ns.is_current() => ns.run(f),
                _ => Ok(f()),
            },
        }
    }

    /// Whether both live in one namespace; `None` when unknown.
    pub(crate) fn same_as(&self, other: &Owner) -> Option<bool> {
        Some(self.id? == other.id?)
    }

    #[cfg(test)]
    pub(crate) fn with_id(id: u64) -> Self {
        Self {
            id: Some(NsId(id)),
            fd: None,
        }
    }
}

/// An open network namespace, such as `/run/netns/<name>` or
/// `/proc/<pid>/ns/net`.
///
/// Netlink and tunnel sockets belong to the network namespace of the thread
/// that creates them. [`NetNs::run`] executes a closure on a short-lived
/// thread that has entered this namespace with `setns(2)`, which needs
/// `CAP_SYS_ADMIN`; the calling thread is never moved. Use it to create
/// [`TunnelSocket`](crate::TunnelSocket)s in the namespace, and
/// [`L2tpHandle::new_in`](crate::L2tpHandle::new_in) to control the L2TP
/// subsystem of the namespace.
#[derive(Debug)]
pub struct NetNs(OwnedFd);

impl NetNs {
    /// Opens the namespace file at `path`.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self(File::open(path)?.into()))
    }

    /// Opens the network namespace of the calling thread.
    ///
    /// This opens `/proc/thread-self/ns/net`; on Linux 6.11 and later it
    /// falls back to `PIDFD_GET_NET_NAMESPACE` on a pidfd of the calling
    /// thread when `/proc` is unavailable. A descriptor is needed only to
    /// enter the namespace with `setns(2)`, as [`run`](Self::run) does; the
    /// rest of the crate does not need one.
    pub fn current() -> io::Result<Self> {
        Self::open("/proc/thread-self/ns/net")
            .or_else(|err| Self::from_pidfd().ok_or(err))
    }

    /// `ioctl(pidfd_open(gettid(), PIDFD_THREAD), PIDFD_GET_NET_NAMESPACE)`
    /// (`include/uapi/linux/pidfd.h`, Linux 6.11+).
    fn from_pidfd() -> Option<Self> {
        // `PIDFD_THREAD` is `O_EXCL` (Linux 6.9+): the thread, not the
        // thread-group leader whose namespace may differ.
        // SAFETY: plain syscalls; the descriptors are owned exactly once.
        let pidfd = unsafe {
            libc::syscall(
                libc::SYS_pidfd_open,
                libc::gettid(),
                libc::O_EXCL as libc::c_uint,
            )
        };
        if pidfd < 0 {
            return None;
        }
        // SAFETY: `pidfd` is a freshly created descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
        // SAFETY: the ioctl takes no argument and returns a new descriptor.
        let ns =
            unsafe { libc::ioctl(pidfd.as_raw_fd(), PIDFD_GET_NET_NAMESPACE) };
        // SAFETY: as above.
        (ns >= 0).then(|| Self(unsafe { OwnedFd::from_raw_fd(ns) }))
    }

    /// Whether this is the calling thread's namespace, by inode; `false`
    /// when that cannot be told.
    fn is_current(&self) -> bool {
        let (Ok(current), Ok(this)) = (Self::current(), self.0.try_clone())
        else {
            return false;
        };
        match (
            File::from(current.0).metadata(),
            File::from(this).metadata(),
        ) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }

    /// Duplicates the namespace descriptor.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }

    /// Runs `f` on a new thread inside this namespace and returns its result.
    ///
    /// The error is the thread creation or `setns(2)` failure; `EPERM` means
    /// the caller lacks `CAP_SYS_ADMIN` over the namespace.
    pub fn run<T, F>(&self, f: F) -> io::Result<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let ns = self.try_clone()?;
        let thread = std::thread::Builder::new()
            .name("l2tp-netns".to_string())
            .spawn(move || {
                // SAFETY: `ns` is an open namespace descriptor; `setns` only
                // affects this thread.
                let rc =
                    unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) };
                if rc == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(f())
            })?;
        thread
            .join()
            .map_err(|_| io::Error::other("the netns thread panicked"))?
    }
}

impl From<OwnedFd> for NetNs {
    fn from(fd: OwnedFd) -> Self {
        Self(fd)
    }
}

impl From<File> for NetNs {
    fn from(file: File) -> Self {
        Self(file.into())
    }
}

impl From<NetNs> for OwnedFd {
    fn from(netns: NetNs) -> Self {
        netns.0
    }
}

impl AsFd for NetNs {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for NetNs {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_in_the_current_namespace_needs_cap_sys_admin() {
        let netns = NetNs::current().unwrap();
        match netns.run(|| 40 + 2) {
            Ok(value) => assert_eq!(value, 42),
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}")
            }
        }
        assert!(netns.try_clone().is_ok());
    }

    #[test]
    fn sockets_of_one_thread_share_a_cookie() {
        let first = NsId::of_thread().unwrap();
        assert!(first.is_some(), "SO_NETNS_COOKIE needs Linux 5.14");
        assert_eq!(first, NsId::of_thread().unwrap());
    }

    #[test]
    fn cookies_of_non_sockets_are_errors() {
        let file = File::open("/dev/null").unwrap();
        let err = NsId::of_socket(file.as_fd()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTSOCK));
    }

    #[test]
    fn threads_of_one_process_share_an_owner() {
        let here = Owner::here(None).unwrap();
        let there = std::thread::spawn(|| Owner::here(None).unwrap())
            .join()
            .unwrap();
        assert_eq!(here.same_as(&there), Some(true));
        assert_eq!(here.same_as(&Owner::with_id(0)), Some(false));
    }

    #[test]
    fn current_namespace_executes_inline_without_setns() {
        let owner = Owner::here(None).unwrap();
        let caller = std::thread::current().id();
        let actual = owner.run_in(|| std::thread::current().id()).unwrap();
        assert_eq!(actual, caller);
        // A descriptor of the current namespace, before its identity is
        // known, is recognized as well.
        let owner = Owner::of(NetNs::current().unwrap());
        let actual = owner.run_in(|| std::thread::current().id()).unwrap();
        assert_eq!(actual, caller);
    }

    #[test]
    fn foreign_namespaces_without_a_descriptor_are_unsupported() {
        let err = Owner::with_id(0).run_in(|| ()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn pidfd_fallback_names_the_current_namespace() {
        // Linux 6.11+ only; older kernels have nothing to compare.
        let Some(ns) = NetNs::from_pidfd() else {
            return;
        };
        assert!(ns.is_current());
    }

    #[test]
    fn missing_namespace_files_are_reported() {
        assert!(NetNs::open("/run/netns/l2tp-no-such-ns").is_err());
    }
}

// SPDX-License-Identifier: MIT

use std::{
    fs::File,
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    path::Path,
};

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
    pub fn current() -> io::Result<Self> {
        Self::open("/proc/thread-self/ns/net")
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
    fn missing_namespace_files_are_reported() {
        assert!(NetNs::open("/run/netns/l2tp-no-such-ns").is_err());
    }
}

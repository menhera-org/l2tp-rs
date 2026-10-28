// SPDX-License-Identifier: MIT

use crate::{
    Cookie, L2SpecType, L2tpIfName, PseudowireType, SessionId, SessionStats,
    TunnelId,
};

/// Parameters for creating an L2TP session.
///
/// With the `serde` feature every field except the identifiers and the
/// pseudowire type has a default.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SessionConfig {
    /// Parent tunnel identifier.
    pub tunnel_id: TunnelId,
    /// Local session identifier.
    pub session_id: SessionId,
    /// Peer session identifier.
    pub peer_session_id: SessionId,
    /// Session pseudowire type.
    ///
    /// Ethernet pseudowires need an L2TPv3 tunnel and the `l2tp_eth` module.
    /// PPP pseudowires need the `l2tp_ppp` module and a
    /// [`PppSocket`](crate::PppSocket) for their data plane.
    pub pseudowire_type: PseudowireType,
    /// Session L2-specific header type. Ignored by the kernel for L2TPv2.
    #[cfg_attr(feature = "serde", serde(default))]
    pub l2spec_type: L2SpecType,
    /// Local session cookie. Ignored by the kernel for L2TPv2.
    ///
    /// 0, 4 or 8 bytes when built here; a kernel report may carry any length
    /// up to 8 (`l2tp_netlink.c`), which this crate decodes but never sends:
    /// creating a session with a cookie copied from a [`SessionInfo`] that
    /// fails [`Cookie::is_rfc3931`] is refused with
    /// [`Error::InvalidCookieLength`](crate::Error::InvalidCookieLength)
    /// before any request is sent.
    #[cfg_attr(feature = "serde", serde(default))]
    pub cookie: Cookie,
    /// Peer session cookie. Ignored by the kernel for L2TPv2. Restricted
    /// like [`cookie`](Self::cookie).
    #[cfg_attr(feature = "serde", serde(default))]
    pub peer_cookie: Cookie,
    /// Enable receive sequence checking.
    #[cfg_attr(feature = "serde", serde(default))]
    pub recv_seq: bool,
    /// Enable transmit sequence numbers.
    #[cfg_attr(feature = "serde", serde(default))]
    pub send_seq: bool,
    /// Enable LNS mode.
    #[cfg_attr(feature = "serde", serde(default))]
    pub lns_mode: bool,
    /// Receive timeout in milliseconds.
    #[cfg_attr(feature = "serde", serde(default))]
    pub recv_timeout_ms: Option<u64>,
    /// Optional interface name for `SESSION_CREATE`.
    ///
    /// For Ethernet pseudowires, this names the `l2tpeth*` netdevice created
    /// by the kernel. Tunnel objects do not have an `ifname`. The kernel
    /// records this name for the session's lifetime; see
    /// [`SessionInfo::ifname`] before renaming the device. Give each session
    /// a unique explicit name, so no other device can hold it while the
    /// session exists.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "crate::types::ifname_serde")
    )]
    pub ifname: Option<L2tpIfName>,
}

impl SessionConfig {
    /// Creates a basic Ethernet pseudowire session configuration.
    pub fn eth(
        tunnel_id: TunnelId,
        session_id: SessionId,
        peer_session_id: SessionId,
    ) -> Self {
        Self::with_pseudowire(
            tunnel_id,
            session_id,
            peer_session_id,
            PseudowireType::Eth,
        )
    }

    /// Creates a basic PPP pseudowire session configuration.
    ///
    /// Attach a [`PppSocket`](crate::PppSocket) to the created session for
    /// its data plane.
    pub fn ppp(
        tunnel_id: TunnelId,
        session_id: SessionId,
        peer_session_id: SessionId,
    ) -> Self {
        Self::with_pseudowire(
            tunnel_id,
            session_id,
            peer_session_id,
            PseudowireType::Ppp,
        )
    }

    fn with_pseudowire(
        tunnel_id: TunnelId,
        session_id: SessionId,
        peer_session_id: SessionId,
        pseudowire_type: PseudowireType,
    ) -> Self {
        Self {
            tunnel_id,
            session_id,
            peer_session_id,
            pseudowire_type,
            l2spec_type: L2SpecType::None,
            cookie: Cookie::none(),
            peer_cookie: Cookie::none(),
            recv_seq: false,
            send_seq: false,
            lns_mode: false,
            recv_timeout_ms: None,
            ifname: None,
        }
    }
}

/// Runtime information returned by the kernel for a session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct SessionInfo {
    /// Parent tunnel identifier.
    pub tunnel_id: TunnelId,
    /// Peer tunnel identifier of the parent tunnel.
    pub peer_tunnel_id: TunnelId,
    /// Local session identifier.
    pub session_id: SessionId,
    /// Peer session identifier.
    pub peer_session_id: SessionId,
    /// Session pseudowire type.
    pub pseudowire_type: PseudowireType,
    /// Session L2-specific sublayer type, when the kernel reports it.
    ///
    /// Linux accepts `L2TP_ATTR_L2SPEC_TYPE` on creation but omits it from
    /// session replies, so this is `None` on current kernels and the value
    /// given at creation cannot be read back.
    pub l2spec_type: Option<L2SpecType>,
    /// Local session cookie; empty when none is set.
    ///
    /// 0, 4 or 8 bytes when built here; a kernel report may carry any length
    /// up to 8 (`l2tp_netlink.c`), which this crate decodes but never sends.
    /// [`Cookie::is_rfc3931`] tells a session created elsewhere with another
    /// length.
    pub cookie: Cookie,
    /// Peer session cookie; empty when none is set. Reported like
    /// [`cookie`](Self::cookie).
    pub peer_cookie: Cookie,
    /// Receive sequence checking state.
    pub recv_seq: bool,
    /// Transmit sequence number state.
    pub send_seq: bool,
    /// LNS mode state.
    pub lns_mode: bool,
    /// Receive timeout in milliseconds.
    pub recv_timeout_ms: Option<u64>,
    /// The session interface name as recorded when the session was created.
    ///
    /// The kernel copies the `l2tpeth` device's name into the session once,
    /// right after creating the device, and never updates it: an interface
    /// renamed afterwards with rtnetlink keeps being reported, and matched
    /// by the `*_by_ifname` lookups, under this original name. Applications
    /// that rename these interfaces, or run where udev or networkd rename
    /// them, must track the device by its interface index:
    /// [`SessionHandle::ifindex`] captures it from the kernel's registration
    /// broadcast when the session is created. A lookup of this name with
    /// [`L2tpIfNameExt::index`](crate::L2tpIfNameExt::index) is only
    /// correct while the interface still bears it, and the kernel does not
    /// report the index itself. Request an explicit, unique name in
    /// [`SessionConfig::ifname`] rather than relying on the kernel's
    /// `l2tpeth%d` pool, so that no other device can hold the name while
    /// this one does.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "crate::types::ifname_serde")
    )]
    pub ifname: Option<L2tpIfName>,
    /// Whether IPsec offload/protection is in use.
    pub using_ipsec: bool,
}

/// Mutable session parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct SessionModify {
    /// Optional receive sequence toggle.
    pub recv_seq: Option<bool>,
    /// Optional send sequence toggle.
    pub send_seq: Option<bool>,
    /// Optional LNS mode toggle.
    pub lns_mode: Option<bool>,
    /// Optional receive timeout update in milliseconds.
    pub recv_timeout_ms: Option<u64>,
}

impl SessionModify {
    /// Returns `true` when no parameter would be changed.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Handle for managing a session lifecycle.
#[derive(Debug)]
pub struct SessionHandle {
    pub(crate) tunnel_id: TunnelId,
    pub(crate) session_id: SessionId,
    pub(crate) ifname: Option<L2tpIfName>,
    pub(crate) ifindex: Option<u32>,
    pub(crate) auto_delete: bool,
    pub(crate) handle: crate::handle::L2tpHandle,
}

impl SessionHandle {
    /// Returns the parent tunnel identifier.
    pub fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    /// Returns this handle's session identifier.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the interface name the session was created with, if one was
    /// assigned.
    ///
    /// This is the name the kernel recorded at creation, which a later
    /// rename does not change; see [`SessionInfo::ifname`]. Use
    /// [`ifindex`](Self::ifindex) to follow the device through renames.
    pub fn ifname(&self) -> Option<&L2tpIfName> {
        self.ifname.as_ref()
    }

    /// Returns the interface index of the session's `l2tpeth` device.
    ///
    /// The index identifies the device for its whole life, while
    /// [`ifname`](Self::ifname) is only its name at creation; address the
    /// device by this index in rtnetlink, including to rename it.
    ///
    /// For a session created by
    /// [`L2tpHandle::create_session`](crate::L2tpHandle::create_session)
    /// the index comes from the kernel's `RTM_NEWLINK` registration
    /// broadcast, which a listener joined before the request had received
    /// by the time the kernel acknowledged it, so a rename by udev or
    /// networkd right after creation cannot make it name another device.
    /// Only if that notification was lost, or the listener could not be
    /// opened, is the index looked up by name. For a handle from the
    /// `open_*` methods the index is always looked up by name when the
    /// handle is opened, which is correct unless the interface has been
    /// renamed in between. `None` when the session has no interface or the
    /// index could not be determined.
    pub fn ifindex(&self) -> Option<u32> {
        self.ifindex
    }

    /// Returns whether the session is deleted when the handle is dropped.
    pub fn auto_delete(&self) -> bool {
        self.auto_delete
    }

    /// Enables or disables best-effort session deletion on drop.
    ///
    /// The deletion runs on a task spawned onto the current Tokio runtime
    /// after the handle is dropped, so it can race with creating a new session
    /// that reuses this ID; use [`SessionHandle::delete`] to delete
    /// deterministically. Without a Tokio runtime, nothing is deleted.
    pub fn set_auto_delete(&mut self, v: bool) {
        self.auto_delete = v;
    }

    /// Fetches current session information from the kernel.
    pub async fn get(&self) -> crate::Result<SessionInfo> {
        self.handle
            .get_session(self.tunnel_id, self.session_id)
            .await
    }

    /// Fetches session statistics from the kernel.
    pub async fn stats(&self) -> crate::Result<SessionStats> {
        self.handle
            .session_stats(self.tunnel_id, self.session_id)
            .await
    }

    /// Applies mutable session parameters.
    pub async fn modify(&self, params: SessionModify) -> crate::Result<()> {
        self.handle
            .modify_session(self.tunnel_id, self.session_id, params)
            .await
    }

    /// Deletes the session and waits for the kernel to acknowledge it.
    /// Once polled inside a Tokio runtime, deletion continues even if the
    /// caller cancels this future.
    pub async fn delete(mut self) -> crate::Result<()> {
        crate::handle::run_cleanup(async move {
            // Once the delete is sent, a failure must not queue another one.
            self.auto_delete = false;
            self.handle
                .delete_session(self.tunnel_id, self.session_id)
                .await?;
            drop(self);
            Ok(())
        })
        .await
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        if !self.auto_delete {
            return;
        }

        let handle = self.handle.clone();
        let tunnel_id = self.tunnel_id;
        let session_id = self.session_id;

        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = handle.delete_session(tunnel_id, session_id).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_eth_constructor_sets_expected_defaults() {
        let config =
            SessionConfig::eth(TunnelId(1), SessionId(2), SessionId(3));

        assert_eq!(config.tunnel_id, TunnelId(1));
        assert_eq!(config.session_id, SessionId(2));
        assert_eq!(config.peer_session_id, SessionId(3));
        assert_eq!(config.pseudowire_type, PseudowireType::Eth);
        assert_eq!(config.l2spec_type, L2SpecType::None);
        assert!(config.cookie.as_bytes().is_empty());
        assert!(config.peer_cookie.as_bytes().is_empty());
        assert!(!config.recv_seq);
        assert!(!config.send_seq);
        assert!(!config.lns_mode);
        assert_eq!(config.recv_timeout_ms, None);
        assert_eq!(config.ifname, None);

        let ppp = SessionConfig::ppp(TunnelId(1), SessionId(2), SessionId(3));
        assert_eq!(ppp.pseudowire_type, PseudowireType::Ppp);
    }

    #[test]
    fn session_modify_is_empty_only_without_changes() {
        assert!(SessionModify::default().is_empty());
        assert!(
            !SessionModify {
                lns_mode: Some(false),
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn session_config_deserializes_with_defaults() {
        let config: SessionConfig = serde_json::from_str(
            r#"{"tunnel_id": 1, "session_id": 2, "peer_session_id": 3,
                "pseudowire_type": "Eth", "cookie": "deadbeef",
                "ifname": "l2tpeth0"}"#,
        )
        .unwrap();
        assert_eq!(config.cookie.to_string(), "deadbeef");
        assert_eq!(config.ifname.unwrap().to_str().unwrap(), "l2tpeth0");
        assert!(!config.recv_seq);

        // Names also arrive as byte sequences, bounded by the kernel buffer.
        let bytes: SessionConfig = serde_json::from_str(
            r#"{"tunnel_id": 1, "session_id": 2, "peer_session_id": 3,
                "pseudowire_type": "Eth", "ifname": [101, 116, 104, 255]}"#,
        )
        .unwrap();
        assert_eq!(bytes.ifname.unwrap().as_bytes(), b"eth\xff");
        let overlong = serde_json::from_str::<SessionConfig>(
            r#"{"tunnel_id": 1, "session_id": 2, "peer_session_id": 3,
                "pseudowire_type": "Eth",
                "ifname": [97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                           97, 97, 97, 97, 97]}"#,
        )
        .unwrap_err();
        assert!(
            overlong.to_string().contains("invalid length"),
            "{overlong}"
        );
        let modify: SessionModify =
            serde_json::from_str(r#"{"send_seq": true}"#).unwrap();
        assert_eq!(modify.send_seq, Some(true));
        assert_eq!(modify.recv_seq, None);
    }
}

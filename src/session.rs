use crate::{Cookie, IfName, L2SpecType, PseudowireType, SessionId, SessionStats, TunnelId};

/// Parameters for creating an L2TP session.
pub struct SessionConfig {
    /// Parent tunnel identifier.
    pub tunnel_id: TunnelId,
    /// Local session identifier.
    pub session_id: SessionId,
    /// Peer session identifier.
    pub peer_session_id: SessionId,
    /// Session pseudowire type.
    pub pseudowire_type: PseudowireType,
    /// Session L2-specific header type.
    pub l2spec_type: L2SpecType,
    /// Local session cookie.
    pub cookie: Cookie,
    /// Peer session cookie.
    pub peer_cookie: Cookie,
    /// Enable receive sequence checking.
    pub recv_seq: bool,
    /// Enable transmit sequence numbers.
    pub send_seq: bool,
    /// Enable LNS mode.
    pub lns_mode: bool,
    /// Receive timeout in milliseconds.
    pub recv_timeout_ms: Option<u64>,
    /// Optional interface name for session netdevice creation.
    pub ifname: Option<IfName>,
}

impl SessionConfig {
    /// Creates a basic Ethernet pseudowire session configuration.
    pub fn eth(tunnel_id: TunnelId, session_id: SessionId, peer_session_id: SessionId) -> Self {
        Self {
            tunnel_id,
            session_id,
            peer_session_id,
            pseudowire_type: PseudowireType::Eth,
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
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Parent tunnel identifier.
    pub tunnel_id: TunnelId,
    /// Local session identifier.
    pub session_id: SessionId,
    /// Peer session identifier.
    pub peer_session_id: SessionId,
    /// Session pseudowire type.
    pub pseudowire_type: PseudowireType,
    /// Session L2-specific header type.
    pub l2spec_type: L2SpecType,
    /// Receive sequence checking state.
    pub recv_seq: bool,
    /// Transmit sequence number state.
    pub send_seq: bool,
    /// LNS mode state.
    pub lns_mode: bool,
    /// Receive timeout in milliseconds.
    pub recv_timeout_ms: Option<u64>,
    /// Kernel-assigned or requested session interface name.
    pub ifname: Option<IfName>,
    /// Whether IPsec offload/protection is in use.
    pub using_ipsec: bool,
}

/// Mutable session parameters.
#[derive(Debug, Clone, Default)]
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

/// Handle for managing a session lifecycle.
pub struct SessionHandle {
    pub(crate) tunnel_id: TunnelId,
    pub(crate) session_id: SessionId,
    pub(crate) ifname: Option<IfName>,
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

    /// Returns the interface name, if one was assigned.
    pub fn ifname(&self) -> Option<&IfName> {
        self.ifname.as_ref()
    }

    /// Enables or disables best-effort session deletion on drop.
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
        let config = SessionConfig::eth(TunnelId(1), SessionId(2), SessionId(3));

        assert_eq!(config.tunnel_id, TunnelId(1));
        assert_eq!(config.session_id, SessionId(2));
        assert_eq!(config.peer_session_id, SessionId(3));
        assert_eq!(config.pseudowire_type, PseudowireType::Eth);
        assert_eq!(config.l2spec_type, L2SpecType::None);
        assert_eq!(config.cookie.as_bytes(), &[]);
        assert_eq!(config.peer_cookie.as_bytes(), &[]);
        assert!(!config.recv_seq);
        assert!(!config.send_seq);
        assert!(!config.lns_mode);
        assert_eq!(config.recv_timeout_ms, None);
        assert_eq!(config.ifname, None);
    }
}

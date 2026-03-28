use crate::{Cookie, IfName, L2SpecType, PseudowireType, SessionId, SessionStats, TunnelId};

pub struct SessionConfig {
    pub tunnel_id: TunnelId,
    pub session_id: SessionId,
    pub peer_session_id: SessionId,
    pub pseudowire_type: PseudowireType,
    pub l2spec_type: L2SpecType,
    pub cookie: Cookie,
    pub peer_cookie: Cookie,
    pub recv_seq: bool,
    pub send_seq: bool,
    pub lns_mode: bool,
    pub recv_timeout_ms: Option<u64>,
    pub ifname: Option<IfName>,
}

impl SessionConfig {
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

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub tunnel_id: TunnelId,
    pub session_id: SessionId,
    pub peer_session_id: SessionId,
    pub pseudowire_type: PseudowireType,
    pub l2spec_type: L2SpecType,
    pub recv_seq: bool,
    pub send_seq: bool,
    pub lns_mode: bool,
    pub recv_timeout_ms: Option<u64>,
    pub ifname: Option<IfName>,
    pub using_ipsec: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SessionModify {
    pub recv_seq: Option<bool>,
    pub send_seq: Option<bool>,
    pub lns_mode: Option<bool>,
    pub recv_timeout_ms: Option<u64>,
}

pub struct SessionHandle {
    pub(crate) tunnel_id: TunnelId,
    pub(crate) session_id: SessionId,
    pub(crate) ifname: Option<IfName>,
    pub(crate) auto_delete: bool,
    pub(crate) handle: crate::handle::L2tpHandle,
}

impl SessionHandle {
    pub fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn ifname(&self) -> Option<&IfName> {
        self.ifname.as_ref()
    }

    pub fn set_auto_delete(&mut self, v: bool) {
        self.auto_delete = v;
    }

    pub async fn get(&self) -> crate::Result<SessionInfo> {
        self.handle
            .get_session(self.tunnel_id, self.session_id)
            .await
    }

    pub async fn stats(&self) -> crate::Result<SessionStats> {
        self.handle
            .session_stats(self.tunnel_id, self.session_id)
            .await
    }

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

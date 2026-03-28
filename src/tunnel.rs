use crate::{Encapsulation, IfName, TunnelId, TunnelSocket, TunnelStats};

pub struct TunnelConfig {
    pub tunnel_id: TunnelId,
    pub peer_tunnel_id: TunnelId,
    pub encapsulation: Encapsulation,
    pub ifname: Option<IfName>,
}

impl TunnelConfig {
    pub fn new(
        tunnel_id: TunnelId,
        peer_tunnel_id: TunnelId,
        encapsulation: Encapsulation,
        ifname: Option<IfName>,
    ) -> crate::Result<Self> {
        match &encapsulation {
            Encapsulation::Udp { local, remote, .. } => {
                if local.ip_version() != remote.ip_version() {
                    return Err(crate::Error::AddressFamilyMismatch);
                }
            }
            Encapsulation::Ip { local, remote } => {
                if local.ip_version() != remote.ip_version() {
                    return Err(crate::Error::AddressFamilyMismatch);
                }
            }
        }

        Ok(Self {
            tunnel_id,
            peer_tunnel_id,
            encapsulation,
            ifname,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub tunnel_id: TunnelId,
    pub peer_tunnel_id: TunnelId,
    pub proto_version: u8,
    pub encapsulation: Encapsulation,
    pub ifname: Option<IfName>,
    pub using_ipsec: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TunnelModify {
    pub udp_csum: Option<bool>,
}

pub struct TunnelHandle {
    pub(crate) tunnel_id: TunnelId,
    pub(crate) socket: Option<TunnelSocket>,
    pub(crate) auto_delete: bool,
    pub(crate) handle: crate::handle::L2tpHandle,
}

impl TunnelHandle {
    pub fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    pub fn socket(&self) -> Option<&TunnelSocket> {
        self.socket.as_ref()
    }

    pub fn socket_mut(&mut self) -> Option<&mut TunnelSocket> {
        self.socket.as_mut()
    }

    pub fn set_auto_delete(&mut self, v: bool) {
        self.auto_delete = v;
    }

    pub async fn get(&self) -> crate::Result<TunnelInfo> {
        self.handle.get_tunnel(self.tunnel_id).await
    }

    pub async fn stats(&self) -> crate::Result<TunnelStats> {
        self.handle.tunnel_stats(self.tunnel_id).await
    }

    pub async fn modify(&self, params: TunnelModify) -> crate::Result<()> {
        self.handle.modify_tunnel(self.tunnel_id, params).await
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        if !self.auto_delete {
            return;
        }

        let handle = self.handle.clone();
        let tunnel_id = self.tunnel_id;

        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = handle.delete_tunnel(tunnel_id).await;
            });
        }
    }
}

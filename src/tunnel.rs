use crate::{Encapsulation, IpEndpoint, TunnelId, TunnelSocket, TunnelStats, UdpEndpoint};

/// Parameters for creating an L2TP tunnel.
pub struct TunnelConfig {
    pub(crate) tunnel_id: TunnelId,
    pub(crate) peer_tunnel_id: TunnelId,
    pub(crate) encapsulation: Encapsulation,
}

impl TunnelConfig {
    /// Creates a tunnel configuration and validates endpoint address families.
    pub fn new(
        tunnel_id: TunnelId,
        peer_tunnel_id: TunnelId,
        encapsulation: Encapsulation,
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
        })
    }
}

/// Runtime information returned by the kernel for a tunnel.
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    /// Local tunnel identifier.
    pub tunnel_id: TunnelId,
    /// Peer tunnel identifier.
    pub peer_tunnel_id: TunnelId,
    /// L2TP protocol version.
    pub proto_version: u8,
    /// Active encapsulation settings.
    pub encapsulation: Encapsulation,
    /// Whether IPsec offload/protection is in use.
    pub using_ipsec: bool,
}

/// Mutable tunnel parameters.
#[derive(Debug, Clone, Default)]
pub struct TunnelModify {
    /// Optional UDP checksum enable/disable update.
    pub udp_csum: Option<bool>,
}

/// Handle for managing a tunnel lifecycle.
pub struct TunnelHandle {
    pub(crate) tunnel_id: TunnelId,
    pub(crate) socket: Option<TunnelSocket>,
    pub(crate) auto_delete: bool,
    pub(crate) handle: crate::handle::L2tpHandle,
}

impl TunnelHandle {
    /// Returns this handle's tunnel identifier.
    pub fn tunnel_id(&self) -> TunnelId {
        self.tunnel_id
    }

    /// Returns the managed socket, if the tunnel was created as managed.
    pub fn socket(&self) -> Option<&TunnelSocket> {
        self.socket.as_ref()
    }

    /// Returns a mutable managed socket reference, if present.
    pub fn socket_mut(&mut self) -> Option<&mut TunnelSocket> {
        self.socket.as_mut()
    }

    /// Enables or disables best-effort netlink `TUNNEL_DELETE` on drop.
    ///
    /// Note: for managed tunnels, dropping the handle also drops the managed
    /// socket fd, and the kernel closes the tunnel when that fd is closed even
    /// if `auto_delete` is disabled.
    pub fn set_auto_delete(&mut self, v: bool) {
        self.auto_delete = v;
    }

    /// Fetches current tunnel information from the kernel.
    pub async fn get(&self) -> crate::Result<TunnelInfo> {
        self.handle.get_tunnel(self.tunnel_id).await
    }

    /// Fetches tunnel statistics from the kernel.
    pub async fn stats(&self) -> crate::Result<TunnelStats> {
        self.handle.tunnel_stats(self.tunnel_id).await
    }

    /// Applies mutable tunnel parameters.
    pub async fn modify(&self, params: TunnelModify) -> crate::Result<()> {
        self.handle.modify_tunnel(self.tunnel_id, params).await
    }

    /// Reconnects a managed UDP tunnel socket to a new remote endpoint.
    pub fn reconnect_udp(&self, new_remote: &UdpEndpoint) -> crate::Result<()> {
        let socket = self.socket.as_ref().ok_or(crate::Error::UnmanagedSocket)?;
        socket.reconnect_udp(new_remote)
    }

    /// Reconnects a managed IP tunnel socket to a new remote endpoint.
    pub fn reconnect_ip(&self, new_remote: &IpEndpoint) -> crate::Result<()> {
        let socket = self.socket.as_ref().ok_or(crate::Error::UnmanagedSocket)?;
        socket.reconnect_ip(new_remote)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IpEndpoint, UdpEndpoint};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn tunnel_config_new_accepts_matching_udp_families() {
        let config = TunnelConfig::new(
            TunnelId(10),
            TunnelId(20),
            Encapsulation::Udp {
                local: UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10000)),
                remote: UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10001)),
                udp_csum: true,
                udp_zero_csum6_tx: false,
                udp_zero_csum6_rx: false,
            },
        )
        .unwrap();

        assert_eq!(config.tunnel_id, TunnelId(10));
        assert_eq!(config.peer_tunnel_id, TunnelId(20));
    }

    #[test]
    fn tunnel_config_new_rejects_mismatched_udp_families() {
        let err = match TunnelConfig::new(
            TunnelId(1),
            TunnelId(2),
            Encapsulation::Udp {
                local: UdpEndpoint::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1701)),
                remote: UdpEndpoint::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1701, 0, 0)),
                udp_csum: false,
                udp_zero_csum6_tx: false,
                udp_zero_csum6_rx: false,
            },
        ) {
            Ok(_) => panic!("expected address family mismatch"),
            Err(e) => e,
        };

        assert!(matches!(err, crate::Error::AddressFamilyMismatch));
    }

    #[test]
    fn tunnel_config_new_rejects_mismatched_ip_families() {
        let err = match TunnelConfig::new(
            TunnelId(1),
            TunnelId(2),
            Encapsulation::Ip {
                local: IpEndpoint::V4(Ipv4Addr::LOCALHOST),
                remote: IpEndpoint::V6(Ipv6Addr::LOCALHOST),
            },
        ) {
            Ok(_) => panic!("expected address family mismatch"),
            Err(e) => e,
        };

        assert!(matches!(err, crate::Error::AddressFamilyMismatch));
    }
}

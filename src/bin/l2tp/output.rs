use l2tp::{
    Encapsulation, IpEndpoint, L2SpecType, PseudowireType, SessionInfo, SessionStats, TunnelInfo,
    TunnelStats, UdpEndpoint,
};
use serde::Serialize;

use super::OutputFmt;

pub struct Output {
    fmt: OutputFmt,
}

impl Output {
    pub fn new(fmt: OutputFmt) -> Self {
        Self { fmt }
    }

    pub fn success(&self, msg: &str) {
        match self.fmt {
            OutputFmt::Text => println!("{msg}"),
            OutputFmt::Json => {
                let v = StatusJson {
                    status: "ok",
                    message: msg,
                };
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
        }
    }

    pub fn error(&self, msg: &str) {
        match self.fmt {
            OutputFmt::Text => eprintln!("error: {msg}"),
            OutputFmt::Json => {
                let v = StatusJson {
                    status: "error",
                    message: msg,
                };
                eprintln!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
        }
    }

    pub fn tunnel_info(&self, info: &TunnelInfo) {
        match self.fmt {
            OutputFmt::Text => print_tunnel_text(info),
            OutputFmt::Json => {
                let v = tunnel_to_json(info);
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
        }
    }

    pub fn tunnel_list(&self, tunnels: &[TunnelInfo]) {
        match self.fmt {
            OutputFmt::Text => {
                if tunnels.is_empty() {
                    println!("no tunnels");
                    return;
                }
                for (i, tunnel) in tunnels.iter().enumerate() {
                    if i != 0 {
                        println!();
                    }
                    print_tunnel_text(tunnel);
                }
            }
            OutputFmt::Json => {
                let v: Vec<TunnelInfoJson> = tunnels.iter().map(tunnel_to_json).collect();
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
        }
    }

    pub fn tunnel_stats(&self, tunnel_id: u32, stats: &TunnelStats) {
        match self.fmt {
            OutputFmt::Text => {
                println!("tunnel {tunnel_id} stats");
                println!(
                    "  tx: packets={} bytes={} errors={}",
                    stats.tx_packets, stats.tx_bytes, stats.tx_errors
                );
                println!(
                    "  rx: packets={} bytes={} errors={}",
                    stats.rx_packets, stats.rx_bytes, stats.rx_errors
                );
            }
            OutputFmt::Json => {
                let v = TunnelStatsJson { tunnel_id, stats };
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
        }
    }

    pub fn session_info(&self, info: &SessionInfo) {
        match self.fmt {
            OutputFmt::Text => print_session_text(info),
            OutputFmt::Json => {
                let v = session_to_json(info);
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
        }
    }

    pub fn session_list(&self, sessions: &[SessionInfo]) {
        match self.fmt {
            OutputFmt::Text => {
                if sessions.is_empty() {
                    println!("no sessions");
                    return;
                }
                for (i, session) in sessions.iter().enumerate() {
                    if i != 0 {
                        println!();
                    }
                    print_session_text(session);
                }
            }
            OutputFmt::Json => {
                let v: Vec<SessionInfoJson> = sessions.iter().map(session_to_json).collect();
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
        }
    }

    pub fn session_stats(&self, tunnel_id: u32, session_id: u32, stats: &SessionStats) {
        match self.fmt {
            OutputFmt::Text => {
                println!("session {session_id} in tunnel {tunnel_id} stats");
                println!(
                    "  tx: packets={} bytes={} errors={}",
                    stats.tx_packets, stats.tx_bytes, stats.tx_errors
                );
                println!(
                    "  rx: packets={} bytes={} errors={}",
                    stats.rx_packets, stats.rx_bytes, stats.rx_errors
                );
                println!(
                    "  rx-extra: seq_discards={} oos_packets={} cookie_discards={} invalid={}",
                    stats.rx_seq_discards,
                    stats.rx_oos_packets,
                    stats.rx_cookie_discards,
                    stats.rx_invalid
                );
            }
            OutputFmt::Json => {
                let v = SessionStatsJson {
                    tunnel_id,
                    session_id,
                    stats,
                };
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
        }
    }
}

#[derive(Serialize)]
struct StatusJson<'a> {
    status: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct TunnelInfoJson {
    tunnel_id: u32,
    peer_tunnel_id: u32,
    proto_version: u8,
    encap: String,
    local: String,
    remote: String,
    udp_csum: Option<bool>,
    udp_zero_csum6_tx: Option<bool>,
    udp_zero_csum6_rx: Option<bool>,
    using_ipsec: bool,
}

#[derive(Serialize)]
struct SessionInfoJson {
    tunnel_id: u32,
    session_id: u32,
    peer_session_id: u32,
    pseudowire_type: String,
    l2spec_type: String,
    recv_seq: bool,
    send_seq: bool,
    lns_mode: bool,
    recv_timeout_ms: Option<u64>,
    ifname: Option<String>,
    using_ipsec: bool,
}

#[derive(Serialize)]
struct TunnelStatsJson<'a> {
    tunnel_id: u32,
    stats: &'a TunnelStats,
}

#[derive(Serialize)]
struct SessionStatsJson<'a> {
    tunnel_id: u32,
    session_id: u32,
    stats: &'a SessionStats,
}

fn print_tunnel_text(info: &TunnelInfo) {
    println!(
        "tunnel {}  peer {}  proto v{}",
        info.tunnel_id.0, info.peer_tunnel_id.0, info.proto_version
    );
    match &info.encapsulation {
        Encapsulation::Udp {
            local,
            remote,
            udp_csum,
            udp_zero_csum6_tx,
            udp_zero_csum6_rx,
        } => {
            println!(
                "  encap: udp  local: {}  remote: {}",
                fmt_udp(local),
                fmt_udp(remote)
            );
            println!(
                "  udp_csum: {}  zero_csum6_tx: {}  zero_csum6_rx: {}",
                udp_csum, udp_zero_csum6_tx, udp_zero_csum6_rx
            );
        }
        Encapsulation::Ip { local, remote } => {
            println!(
                "  encap: ip  local: {}  remote: {}",
                fmt_ip(local),
                fmt_ip(remote)
            );
        }
    }
    println!("  using_ipsec: {}", info.using_ipsec);
}

fn print_session_text(info: &SessionInfo) {
    println!(
        "session {}  tunnel {}  peer {}",
        info.session_id.0, info.tunnel_id.0, info.peer_session_id.0
    );
    println!(
        "  pw_type: {}  l2spec: {}",
        fmt_pw_type(info.pseudowire_type),
        fmt_l2spec(info.l2spec_type)
    );
    println!(
        "  recv_seq: {}  send_seq: {}  lns_mode: {}",
        info.recv_seq, info.send_seq, info.lns_mode
    );
    if let Some(timeout) = info.recv_timeout_ms {
        println!("  recv_timeout_ms: {timeout}");
    } else {
        println!("  recv_timeout_ms: none");
    }
    if let Some(ifname) = &info.ifname {
        println!("  ifname: {}", ifname.as_str());
    } else {
        println!("  ifname: none");
    }
    println!("  using_ipsec: {}", info.using_ipsec);
}

fn tunnel_to_json(info: &TunnelInfo) -> TunnelInfoJson {
    match &info.encapsulation {
        Encapsulation::Udp {
            local,
            remote,
            udp_csum,
            udp_zero_csum6_tx,
            udp_zero_csum6_rx,
        } => TunnelInfoJson {
            tunnel_id: info.tunnel_id.0,
            peer_tunnel_id: info.peer_tunnel_id.0,
            proto_version: info.proto_version,
            encap: "udp".to_string(),
            local: fmt_udp(local),
            remote: fmt_udp(remote),
            udp_csum: Some(*udp_csum),
            udp_zero_csum6_tx: Some(*udp_zero_csum6_tx),
            udp_zero_csum6_rx: Some(*udp_zero_csum6_rx),
            using_ipsec: info.using_ipsec,
        },
        Encapsulation::Ip { local, remote } => TunnelInfoJson {
            tunnel_id: info.tunnel_id.0,
            peer_tunnel_id: info.peer_tunnel_id.0,
            proto_version: info.proto_version,
            encap: "ip".to_string(),
            local: fmt_ip(local),
            remote: fmt_ip(remote),
            udp_csum: None,
            udp_zero_csum6_tx: None,
            udp_zero_csum6_rx: None,
            using_ipsec: info.using_ipsec,
        },
    }
}

fn session_to_json(info: &SessionInfo) -> SessionInfoJson {
    SessionInfoJson {
        tunnel_id: info.tunnel_id.0,
        session_id: info.session_id.0,
        peer_session_id: info.peer_session_id.0,
        pseudowire_type: fmt_pw_type(info.pseudowire_type).to_string(),
        l2spec_type: fmt_l2spec(info.l2spec_type).to_string(),
        recv_seq: info.recv_seq,
        send_seq: info.send_seq,
        lns_mode: info.lns_mode,
        recv_timeout_ms: info.recv_timeout_ms,
        ifname: info.ifname.as_ref().map(|v| v.as_str().to_string()),
        using_ipsec: info.using_ipsec,
    }
}

fn fmt_udp(ep: &UdpEndpoint) -> String {
    match ep {
        UdpEndpoint::V4(addr) => format!("{}:{}", addr.ip(), addr.port()),
        UdpEndpoint::V6(addr) => format!("[{}]:{}", addr.ip(), addr.port()),
    }
}

fn fmt_ip(ep: &IpEndpoint) -> String {
    match ep {
        IpEndpoint::V4(addr) => addr.to_string(),
        IpEndpoint::V6(addr) => addr.to_string(),
    }
}

fn fmt_pw_type(v: PseudowireType) -> &'static str {
    match v {
        PseudowireType::Eth => "eth",
        PseudowireType::EthVlan => "eth-vlan",
        PseudowireType::Ppp => "ppp",
        PseudowireType::PppAc => "ppp-ac",
        PseudowireType::Ip => "ip",
        PseudowireType::None => "none",
    }
}

fn fmt_l2spec(v: L2SpecType) -> &'static str {
    match v {
        L2SpecType::None => "none",
        L2SpecType::Default => "default",
    }
}

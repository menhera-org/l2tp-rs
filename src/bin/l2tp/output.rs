// SPDX-License-Identifier: MIT

use l2tp::{
    Encapsulation, IpEndpoint, L2SpecType, L2tpEvent, PseudowireType,
    SessionInfo, SessionStats, TunnelInfo, TunnelStats, UdpEndpoint,
};
use serde::Serialize;

use crate::cli::OutputFmt;

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
            OutputFmt::Json => print_json(&StatusJson {
                status: "ok",
                message: msg,
            }),
        }
    }

    pub fn error(&self, msg: &str) {
        match self.fmt {
            OutputFmt::Text => eprintln!("error: {msg}"),
            OutputFmt::Json => match serde_json::to_string_pretty(&StatusJson {
                status: "error",
                message: msg,
            }) {
                Ok(json) => eprintln!("{json}"),
                Err(_) => eprintln!("error: {msg}"),
            },
        }
    }

    pub fn tunnel_info(&self, info: &TunnelInfo) {
        match self.fmt {
            OutputFmt::Text => print_tunnel_text(info),
            OutputFmt::Json => print_json(&tunnel_to_json(info)),
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
                let v: Vec<TunnelInfoJson> =
                    tunnels.iter().map(tunnel_to_json).collect();
                print_json(&v);
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
                print_json(&TunnelStatsJson { tunnel_id, stats })
            }
        }
    }

    pub fn session_info(&self, info: &SessionInfo) {
        match self.fmt {
            OutputFmt::Text => print_session_text(info),
            OutputFmt::Json => print_json(&session_to_json(info)),
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
                let v: Vec<SessionInfoJson> =
                    sessions.iter().map(session_to_json).collect();
                print_json(&v);
            }
        }
    }

    pub fn session_stats(&self, info: &SessionInfo, stats: &SessionStats) {
        match self.fmt {
            OutputFmt::Text => {
                println!(
                    "session {} in tunnel {} stats",
                    info.session_id, info.tunnel_id
                );
                println!(
                    "  tx: packets={} bytes={} errors={}",
                    stats.tx_packets, stats.tx_bytes, stats.tx_errors
                );
                println!(
                    "  rx: packets={} bytes={} errors={}",
                    stats.rx_packets, stats.rx_bytes, stats.rx_errors
                );
                println!(
                    "  rx-extra: seq_discards={} oos_packets={} \
                     cookie_discards={} invalid={}",
                    stats.rx_seq_discards,
                    stats.rx_oos_packets,
                    stats.rx_cookie_discards,
                    stats.rx_invalid
                );
            }
            OutputFmt::Json => print_json(&SessionStatsJson {
                tunnel_id: info.tunnel_id.0,
                session_id: info.session_id.0,
                stats,
            }),
        }
    }

    pub fn event(&self, event: &L2tpEvent) {
        let (name, tunnel, session) = match event {
            L2tpEvent::TunnelCreated(info) => {
                ("tunnel_created", Some(info), None)
            }
            L2tpEvent::TunnelModified(info) => {
                ("tunnel_modified", Some(info), None)
            }
            L2tpEvent::TunnelDeleted(info) => {
                ("tunnel_deleted", Some(info), None)
            }
            L2tpEvent::SessionCreated(info) => {
                ("session_created", None, Some(info))
            }
            L2tpEvent::SessionModified(info) => {
                ("session_modified", None, Some(info))
            }
            L2tpEvent::SessionDeleted(info) => {
                ("session_deleted", None, Some(info))
            }
            _ => ("unknown", None, None),
        };
        match self.fmt {
            OutputFmt::Text => {
                println!("event: {}", name.replace('_', " "));
                if let Some(info) = tunnel {
                    print_tunnel_text(info);
                }
                if let Some(info) = session {
                    print_session_text(info);
                }
                println!();
            }
            OutputFmt::Json => match serde_json::to_string(&EventJson {
                event: name,
                tunnel: tunnel.map(tunnel_to_json),
                session: session.map(session_to_json),
            }) {
                Ok(json) => println!("{json}"),
                Err(err) => eprintln!("error: cannot encode event: {err}"),
            },
        }
    }
}

fn print_json(value: &impl Serialize) {
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{json}"),
        Err(err) => eprintln!("error: cannot encode output: {err}"),
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
    peer_tunnel_id: u32,
    session_id: u32,
    peer_session_id: u32,
    pseudowire_type: String,
    l2spec_type: Option<String>,
    cookie: String,
    peer_cookie: String,
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

#[derive(Serialize)]
struct EventJson {
    event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tunnel: Option<TunnelInfoJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<SessionInfoJson>,
}

fn print_tunnel_text(info: &TunnelInfo) {
    println!(
        "tunnel {}  peer {}  proto v{}",
        info.tunnel_id, info.peer_tunnel_id, info.version
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
        "session {}  tunnel {}  peer {}  peer-tunnel {}",
        info.session_id,
        info.tunnel_id,
        info.peer_session_id,
        info.peer_tunnel_id
    );
    println!(
        "  pw_type: {}  l2spec: {}",
        fmt_pw_type(info.pseudowire_type),
        info.l2spec_type
            .map_or_else(|| "unknown".to_string(), fmt_l2spec)
    );
    println!(
        "  cookie: {}  peer_cookie: {}",
        fmt_cookie(&info.cookie),
        fmt_cookie(&info.peer_cookie)
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
        println!("  ifname: {ifname}");
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
            proto_version: info.version.number(),
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
            proto_version: info.version.number(),
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
        peer_tunnel_id: info.peer_tunnel_id.0,
        session_id: info.session_id.0,
        peer_session_id: info.peer_session_id.0,
        pseudowire_type: fmt_pw_type(info.pseudowire_type),
        l2spec_type: info.l2spec_type.map(fmt_l2spec),
        cookie: info.cookie.to_string(),
        peer_cookie: info.peer_cookie.to_string(),
        recv_seq: info.recv_seq,
        send_seq: info.send_seq,
        lns_mode: info.lns_mode,
        recv_timeout_ms: info.recv_timeout_ms,
        // JSON is UTF-8, so a non-UTF-8 name is shown lossily.
        ifname: info.ifname.map(|v| v.to_string_lossy().into_owned()),
        using_ipsec: info.using_ipsec,
    }
}

fn fmt_cookie(cookie: &l2tp::Cookie) -> String {
    if cookie.is_empty() {
        "none".to_string()
    } else {
        cookie.to_string()
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
        IpEndpoint::V6 { addr, scope: None } => addr.to_string(),
        IpEndpoint::V6 {
            addr,
            scope: Some(scope),
        } => format!("{addr}%{scope}"),
    }
}

fn fmt_pw_type(v: PseudowireType) -> String {
    match v {
        PseudowireType::Eth => "eth".to_string(),
        PseudowireType::EthVlan => "eth-vlan".to_string(),
        PseudowireType::Ppp => "ppp".to_string(),
        PseudowireType::PppAc => "ppp-ac".to_string(),
        PseudowireType::Ip => "ip".to_string(),
        PseudowireType::None => "none".to_string(),
        PseudowireType::Other(raw) => raw.to_string(),
        other => format!("{other:?}"),
    }
}

fn fmt_l2spec(v: L2SpecType) -> String {
    match v {
        L2SpecType::None => "none".to_string(),
        L2SpecType::Default => "default".to_string(),
        L2SpecType::Other(raw) => raw.to_string(),
        other => format!("{other:?}"),
    }
}

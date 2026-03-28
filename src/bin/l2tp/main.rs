mod output;

use clap::{Parser, Subcommand, ValueEnum};
use l2tp::{
    Cookie, Encapsulation, IfName, IpEndpoint, L2SpecType, L2tpHandle, PseudowireType,
    SessionConfig, SessionId, SessionInfo, SessionModify, TunnelConfig, TunnelId, TunnelModify,
    TunnelSocket, UdpEndpoint,
};
use output::Output;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFmt {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum EncapArg {
    Udp,
    Ip,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PwTypeArg {
    Eth,
    EthVlan,
    Ppp,
    PppAc,
    Ip,
    None,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum L2SpecArg {
    None,
    Default,
}

#[derive(Parser)]
#[command(name = "l2tp")]
struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = OutputFmt::Text)]
    output: OutputFmt,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Tunnel(TunnelArgs),
    Session(SessionArgs),
}

#[derive(Parser)]
struct TunnelArgs {
    #[command(subcommand)]
    cmd: TunnelCmd,
}

#[derive(Subcommand)]
enum TunnelCmd {
    Create(TunnelCreateArgs),
    Delete(TunnelDeleteArgs),
    Change(TunnelChangeArgs),
    Show(TunnelShowArgs),
    List(TunnelListArgs),
    Stats(TunnelStatsArgs),
}

#[derive(Parser)]
struct TunnelCreateArgs {
    #[arg(long)]
    peer_tunnel_id: u32,

    #[arg(long)]
    tunnel_id: Option<u32>,

    #[arg(long, value_enum, default_value_t = EncapArg::Udp)]
    encap: EncapArg,

    #[arg(long)]
    local: Option<String>,

    #[arg(long)]
    remote: String,

    #[arg(long)]
    device: Option<String>,

    #[arg(long)]
    no_udp_csum: bool,

    #[arg(long)]
    udp_zero_csum6_tx: bool,

    #[arg(long)]
    udp_zero_csum6_rx: bool,

    #[arg(long)]
    ipv6_dontfrag: bool,
}

#[derive(Parser)]
struct TunnelDeleteArgs {
    #[arg(long)]
    tunnel_id: u32,
}

#[derive(Parser)]
struct TunnelChangeArgs {
    #[arg(long)]
    tunnel_id: u32,

    #[arg(long, conflicts_with = "no_udp_csum")]
    udp_csum: bool,

    #[arg(long, conflicts_with = "udp_csum")]
    no_udp_csum: bool,
}

#[derive(Parser)]
struct TunnelShowArgs {
    #[arg(long)]
    tunnel_id: u32,
}

#[derive(Parser)]
struct TunnelListArgs {}

#[derive(Parser)]
struct TunnelStatsArgs {
    #[arg(long)]
    tunnel_id: u32,
}

#[derive(Parser)]
struct SessionArgs {
    #[command(subcommand)]
    cmd: SessionCmd,
}

#[derive(Subcommand)]
enum SessionCmd {
    Create(SessionCreateArgs),
    Delete(SessionDeleteArgs),
    Change(SessionChangeArgs),
    Show(SessionShowArgs),
    List(SessionListArgs),
    Stats(SessionStatsArgs),
}

#[derive(Parser)]
struct SessionCreateArgs {
    #[arg(long)]
    tunnel_id: u32,

    #[arg(long)]
    session_id: u32,

    #[arg(long)]
    peer_session_id: u32,

    #[arg(long, value_enum, default_value_t = PwTypeArg::Eth)]
    pw_type: PwTypeArg,

    #[arg(long, value_enum, default_value_t = L2SpecArg::None)]
    l2spec: L2SpecArg,

    #[arg(long)]
    cookie: Option<String>,

    #[arg(long)]
    peer_cookie: Option<String>,

    #[arg(long)]
    recv_seq: bool,

    #[arg(long)]
    send_seq: bool,

    #[arg(long)]
    lns_mode: bool,

    #[arg(long)]
    recv_timeout_ms: Option<u64>,

    #[arg(long)]
    ifname: Option<String>,
}

#[derive(Parser)]
struct SessionDeleteArgs {
    #[arg(long)]
    tunnel_id: u32,

    #[arg(long)]
    session_id: u32,
}

#[derive(Parser)]
struct SessionChangeArgs {
    #[arg(long)]
    tunnel_id: u32,

    #[arg(long)]
    session_id: u32,

    #[arg(long, conflicts_with = "no_recv_seq")]
    recv_seq: bool,

    #[arg(long, conflicts_with = "recv_seq")]
    no_recv_seq: bool,

    #[arg(long, conflicts_with = "no_send_seq")]
    send_seq: bool,

    #[arg(long, conflicts_with = "send_seq")]
    no_send_seq: bool,

    #[arg(long, conflicts_with = "no_lns_mode")]
    lns_mode: bool,

    #[arg(long, conflicts_with = "lns_mode")]
    no_lns_mode: bool,

    #[arg(long)]
    recv_timeout_ms: Option<u64>,
}

#[derive(Parser)]
struct SessionShowArgs {
    #[arg(long)]
    tunnel_id: u32,

    #[arg(long)]
    session_id: u32,
}

#[derive(Parser)]
struct SessionListArgs {
    #[arg(long, conflicts_with = "all")]
    tunnel_id: Option<u32>,

    #[arg(long, conflicts_with = "tunnel_id")]
    all: bool,
}

#[derive(Parser)]
struct SessionStatsArgs {
    #[arg(long)]
    tunnel_id: u32,

    #[arg(long)]
    session_id: u32,
}

fn parse_udp_addr(s: &str) -> Result<UdpEndpoint, String> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(match sa {
            SocketAddr::V4(v4) => UdpEndpoint::V4(v4),
            SocketAddr::V6(v6) => UdpEndpoint::V6(v6),
        });
    }

    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(v4) => UdpEndpoint::V4(std::net::SocketAddrV4::new(v4, 0)),
            IpAddr::V6(v6) => UdpEndpoint::V6(SocketAddrV6::new(v6, 0, 0, 0)),
        });
    }

    Err(format!("invalid address '{s}'"))
}

fn resolve_udp_endpoints(
    local_str: Option<&str>,
    remote_str: &str,
) -> l2tp::Result<(UdpEndpoint, UdpEndpoint)> {
    let local = parse_udp_addr(local_str.unwrap_or("::")).map_err(l2tp::Error::InvalidIfName)?;
    let remote = parse_udp_addr(remote_str).map_err(l2tp::Error::InvalidIfName)?;

    if remote_str.parse::<SocketAddr>().is_err() {
        return Err(l2tp::Error::InvalidIfName(format!(
            "remote address must include port: '{remote_str}'"
        )));
    }

    match (&local, remote) {
        (UdpEndpoint::V6(_), UdpEndpoint::V4(v4)) => {
            let mapped = UdpEndpoint::V6(SocketAddrV6::new(
                v4.ip().to_ipv6_mapped(),
                v4.port(),
                0,
                0,
            ));
            Ok((local, mapped))
        }
        (_, remote) if local.ip_version() == remote.ip_version() => Ok((local, remote)),
        _ => Err(l2tp::Error::InvalidIfName(
            "remote address family does not match local; use [::ffff:x.x.x.x]:port for IPv4 remote with IPv6 local".to_string(),
        )),
    }
}

fn parse_ip_addr(s: &str) -> Result<IpEndpoint, String> {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => Ok(IpEndpoint::V4(v4)),
        Ok(IpAddr::V6(v6)) => Ok(IpEndpoint::V6(v6)),
        Err(_) => Err(format!("invalid address '{s}'")),
    }
}

fn parse_hex_cookie(s: &str, field: &str) -> l2tp::Result<Cookie> {
    if s.is_empty() {
        return Ok(Cookie::none());
    }
    if !s.len().is_multiple_of(2) {
        return Err(l2tp::Error::InvalidIfName(format!(
            "invalid {field}: odd-length hex string"
        )));
    }

    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let pair = &s[i..i + 2];
        let v = u8::from_str_radix(pair, 16)
            .map_err(|_| l2tp::Error::InvalidIfName(format!("invalid {field}: non-hex value")))?;
        out.push(v);
        i += 2;
    }
    Cookie::try_from_bytes(out)
}

fn flag_pair(on: bool, off: bool) -> Option<bool> {
    if on {
        Some(true)
    } else if off {
        Some(false)
    } else {
        None
    }
}

async fn run_tunnel(cmd: TunnelCmd, handle: &L2tpHandle, out: &Output) -> l2tp::Result<()> {
    match cmd {
        TunnelCmd::Create(args) => tunnel_create(args, handle, out).await,
        TunnelCmd::Delete(args) => {
            handle.delete_tunnel(TunnelId(args.tunnel_id)).await?;
            out.success(&format!("deleted tunnel {}", args.tunnel_id));
            Ok(())
        }
        TunnelCmd::Change(args) => tunnel_change(args, handle, out).await,
        TunnelCmd::Show(args) => {
            let info = handle.get_tunnel(TunnelId(args.tunnel_id)).await?;
            out.tunnel_info(&info);
            Ok(())
        }
        TunnelCmd::List(_) => {
            let tunnels = handle.list_tunnels().await?;
            out.tunnel_list(&tunnels);
            Ok(())
        }
        TunnelCmd::Stats(args) => {
            let stats = handle.tunnel_stats(TunnelId(args.tunnel_id)).await?;
            out.tunnel_stats(args.tunnel_id, &stats);
            Ok(())
        }
    }
}

async fn run_session(cmd: SessionCmd, handle: &L2tpHandle, out: &Output) -> l2tp::Result<()> {
    match cmd {
        SessionCmd::Create(args) => session_create(args, handle, out).await,
        SessionCmd::Delete(args) => {
            handle
                .delete_session(TunnelId(args.tunnel_id), SessionId(args.session_id))
                .await?;
            out.success(&format!(
                "deleted session {} in tunnel {}",
                args.session_id, args.tunnel_id
            ));
            Ok(())
        }
        SessionCmd::Change(args) => session_change(args, handle, out).await,
        SessionCmd::Show(args) => {
            let info = handle
                .get_session(TunnelId(args.tunnel_id), SessionId(args.session_id))
                .await?;
            out.session_info(&info);
            Ok(())
        }
        SessionCmd::List(args) => {
            let sessions: Vec<SessionInfo> = if args.all || args.tunnel_id.is_none() {
                handle.list_all_sessions().await?
            } else {
                handle
                    .list_sessions(TunnelId(args.tunnel_id.unwrap_or_default()))
                    .await?
            };
            out.session_list(&sessions);
            Ok(())
        }
        SessionCmd::Stats(args) => {
            let stats = handle
                .session_stats(TunnelId(args.tunnel_id), SessionId(args.session_id))
                .await?;
            out.session_stats(args.tunnel_id, args.session_id, &stats);
            Ok(())
        }
    }
}

async fn tunnel_create(
    args: TunnelCreateArgs,
    handle: &L2tpHandle,
    out: &Output,
) -> l2tp::Result<()> {
    let device = args.device.as_deref().map(IfName::new).transpose()?;

    let encapsulation = match args.encap {
        EncapArg::Udp => {
            let (local, remote) = resolve_udp_endpoints(args.local.as_deref(), &args.remote)?;
            Encapsulation::Udp {
                local,
                remote,
                udp_csum: !args.no_udp_csum,
                udp_zero_csum6_tx: args.udp_zero_csum6_tx,
                udp_zero_csum6_rx: args.udp_zero_csum6_rx,
            }
        }
        EncapArg::Ip => {
            let local_s = args.local.as_deref().ok_or_else(|| {
                l2tp::Error::InvalidIfName("--local is required for --encap ip".to_string())
            })?;
            let local = parse_ip_addr(local_s).map_err(l2tp::Error::InvalidIfName)?;
            let remote = parse_ip_addr(&args.remote).map_err(l2tp::Error::InvalidIfName)?;
            if local.ip_version() != remote.ip_version() {
                return Err(l2tp::Error::AddressFamilyMismatch);
            }
            Encapsulation::Ip { local, remote }
        }
    };

    let attempts = if args.tunnel_id.is_some() { 1 } else { 32 };
    for attempt in 0..attempts {
        let tunnel_id = TunnelId(match args.tunnel_id {
            Some(v) => v,
            None => random_tunnel_id(attempt as u32),
        });
        let peer_tunnel_id = TunnelId(args.peer_tunnel_id);
        let config = TunnelConfig::new(tunnel_id, peer_tunnel_id, encapsulation.clone())?;

        let socket = match &encapsulation {
            Encapsulation::Udp { local, remote, .. } => {
                TunnelSocket::udp(local, remote, device.as_ref())?
            }
            Encapsulation::Ip { local, remote } => {
                TunnelSocket::ip(local, remote, device.as_ref(), tunnel_id.0)?
            }
        };
        if args.ipv6_dontfrag {
            socket.set_ipv6_dontfrag(true)?;
        }

        match handle.create_tunnel(config, socket).await {
            Ok(mut tunnel) => {
                tunnel.set_auto_delete(false);
                out.success(&format!("created tunnel {}", tunnel_id.0));
                return Ok(());
            }
            Err(l2tp::Error::KernelError { code, .. })
                if args.tunnel_id.is_none() && code == libc::EEXIST =>
            {
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Err(l2tp::Error::KernelError {
        code: libc::EEXIST,
        message: "failed to allocate unique tunnel id after 32 attempts".to_string(),
    })
}

async fn tunnel_change(
    args: TunnelChangeArgs,
    handle: &L2tpHandle,
    out: &Output,
) -> l2tp::Result<()> {
    let tunnel_id = TunnelId(args.tunnel_id);

    let udp_csum = flag_pair(args.udp_csum, args.no_udp_csum);
    if udp_csum.is_none() {
        out.success("no tunnel changes requested");
        return Ok(());
    }

    handle
        .modify_tunnel(tunnel_id, TunnelModify { udp_csum })
        .await?;
    out.success(&format!("updated tunnel {}", args.tunnel_id));
    Ok(())
}

async fn session_create(
    args: SessionCreateArgs,
    handle: &L2tpHandle,
    out: &Output,
) -> l2tp::Result<()> {
    let cookie = parse_hex_cookie(args.cookie.as_deref().unwrap_or(""), "cookie")?;
    let peer_cookie = parse_hex_cookie(args.peer_cookie.as_deref().unwrap_or(""), "peer-cookie")?;
    let ifname = args.ifname.as_deref().map(IfName::new).transpose()?;

    let config = SessionConfig {
        tunnel_id: TunnelId(args.tunnel_id),
        session_id: SessionId(args.session_id),
        peer_session_id: SessionId(args.peer_session_id),
        pseudowire_type: map_pw(args.pw_type),
        l2spec_type: map_l2spec(args.l2spec),
        cookie,
        peer_cookie,
        recv_seq: args.recv_seq,
        send_seq: args.send_seq,
        lns_mode: args.lns_mode,
        recv_timeout_ms: args.recv_timeout_ms,
        ifname,
    };

    let mut session = handle.create_session(config).await?;
    session.set_auto_delete(false);
    out.success(&format!(
        "created session {} in tunnel {}",
        args.session_id, args.tunnel_id
    ));
    Ok(())
}

async fn session_change(
    args: SessionChangeArgs,
    handle: &L2tpHandle,
    out: &Output,
) -> l2tp::Result<()> {
    let modify = SessionModify {
        recv_seq: flag_pair(args.recv_seq, args.no_recv_seq),
        send_seq: flag_pair(args.send_seq, args.no_send_seq),
        lns_mode: flag_pair(args.lns_mode, args.no_lns_mode),
        recv_timeout_ms: args.recv_timeout_ms,
    };

    if modify.recv_seq.is_none()
        && modify.send_seq.is_none()
        && modify.lns_mode.is_none()
        && modify.recv_timeout_ms.is_none()
    {
        out.success("no session changes requested");
        return Ok(());
    }

    handle
        .modify_session(TunnelId(args.tunnel_id), SessionId(args.session_id), modify)
        .await?;
    out.success(&format!(
        "updated session {} in tunnel {}",
        args.session_id, args.tunnel_id
    ));
    Ok(())
}

fn random_tunnel_id(attempt: u32) -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos() as u64;
    let pid = std::process::id() as u64;
    let mixed = now ^ (pid << 32) ^ (attempt as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let span = u32::MAX - 999_999;
    1_000_000 + ((mixed as u32) % span)
}

fn map_pw(v: PwTypeArg) -> PseudowireType {
    match v {
        PwTypeArg::Eth => PseudowireType::Eth,
        PwTypeArg::EthVlan => PseudowireType::EthVlan,
        PwTypeArg::Ppp => PseudowireType::Ppp,
        PwTypeArg::PppAc => PseudowireType::PppAc,
        PwTypeArg::Ip => PseudowireType::Ip,
        PwTypeArg::None => PseudowireType::None,
    }
}

fn map_l2spec(v: L2SpecArg) -> L2SpecType {
    match v {
        L2SpecArg::None => L2SpecType::None,
        L2SpecArg::Default => L2SpecType::Default,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let out = Output::new(cli.output);

    let handle = match L2tpHandle::new().await {
        Ok(v) => v,
        Err(e) => {
            out.error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };

    let result = match cli.cmd {
        Cmd::Tunnel(args) => run_tunnel(args.cmd, &handle, &out).await,
        Cmd::Session(args) => run_session(args.cmd, &handle, &out).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            out.error(&e.to_string());
            ExitCode::FAILURE
        }
    }
}

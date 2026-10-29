// SPDX-License-Identifier: MIT

use std::{
    ffi::OsString,
    fmt, io,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    os::unix::ffi::OsStrExt,
    process::ExitCode,
    time::Duration,
};

use clap::{
    Args, Parser, Subcommand, ValueEnum,
    builder::{OsStringValueParser, TryMapValueParser, TypedValueParser},
};
use futures::StreamExt;
use l2tp::{
    Cookie, Encapsulation, HandleConfig, IpEndpoint, L2SpecType, L2tpHandle,
    L2tpIfName, L2tpIfNameExt, L2tpVersion, PseudowireType, SessionConfig,
    SessionId, SessionInfo, SessionModify, TunnelConfig, TunnelId, UdpEndpoint,
};

use crate::output::Output;

/// Errors reported by the command-line tool.
#[derive(Debug)]
enum CliError {
    /// Invalid command-line input.
    Usage(String),
    /// Library or kernel failure.
    L2tp(l2tp::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg) => msg.fmt(f),
            Self::L2tp(err) => err.fmt(f),
        }
    }
}

impl From<l2tp::Error> for CliError {
    fn from(err: l2tp::Error) -> Self {
        Self::L2tp(err)
    }
}

type CliResult<T> = Result<T, CliError>;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum OutputFmt {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum EncapArg {
    Udp,
    Ip,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum VersionArg {
    #[value(name = "2")]
    V2,
    #[value(name = "3")]
    V3,
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

type IfNameParser = TryMapValueParser<
    OsStringValueParser,
    fn(OsString) -> Result<L2tpIfName, l2tp::Error>,
>;

// Interface names are byte strings, so parse them from the raw argument.
fn parse_ifname(arg: OsString) -> Result<L2tpIfName, l2tp::Error> {
    L2tpIfName::from_name(arg.as_bytes())
}

fn ifname_parser() -> IfNameParser {
    OsStringValueParser::new().try_map(parse_ifname)
}

/// Supplementary L2TP tool for testing only.
///
/// Serialized output is for inspection and may be lossy.
#[derive(Parser)]
#[command(name = "l2tp")]
struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = OutputFmt::Text)]
    output: OutputFmt,

    /// Request timeout in seconds; 0 disables it. Does not limit monitor idle
    /// time.
    #[arg(long, global = true, default_value_t = 30)]
    request_timeout: u64,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Tunnel(TunnelArgs),
    Session(SessionArgs),
    /// Print kernel L2TP notifications as they happen.
    Monitor(MonitorArgs),
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

    /// L2TP protocol version; Ethernet sessions need version 3.
    #[arg(long, value_enum, default_value_t = VersionArg::V3)]
    proto_version: VersionArg,

    #[arg(long)]
    local: Option<String>,

    #[arg(long)]
    remote: String,

    #[arg(long, value_parser = ifname_parser())]
    device: Option<L2tpIfName>,

    /// Disable IPv4 UDP checksums; requires IPv4 endpoints (not mapped IPv6).
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

    /// Local cookie as 8 or 16 hexadecimal digits.
    #[arg(long, default_value_t = Cookie::none())]
    cookie: Cookie,

    /// Peer cookie as 8 or 16 hexadecimal digits.
    #[arg(long, default_value_t = Cookie::none())]
    peer_cookie: Cookie,

    #[arg(long)]
    recv_seq: bool,

    #[arg(long)]
    send_seq: bool,

    #[arg(long)]
    lns_mode: bool,

    #[arg(long)]
    recv_timeout_ms: Option<u64>,

    /// Interface name, validated with the kernel's rules while parsing.
    #[arg(long, value_parser = ifname_parser())]
    ifname: Option<L2tpIfName>,
}

/// Selects a session by its identifiers or by its interface name.
#[derive(Args)]
struct SessionRefArgs {
    /// Tunnel of the session; use with --session-id.
    #[arg(long, requires = "session_id", conflicts_with = "ifname")]
    tunnel_id: Option<u32>,

    /// Session identifier; use with --tunnel-id.
    #[arg(long, requires = "tunnel_id", conflicts_with = "ifname")]
    session_id: Option<u32>,

    /// Interface name of an Ethernet pseudowire session, instead of the
    /// identifiers.
    #[arg(
        long,
        value_parser = ifname_parser(),
        conflicts_with_all = ["tunnel_id", "session_id"]
    )]
    ifname: Option<L2tpIfName>,
}

// Preserve the original selector in mutations: looking up IDs first can
// target a replacement session when another controller reuses those IDs.
#[derive(Clone, Copy)]
enum SessionRef {
    Ids(TunnelId, SessionId),
    IfName(L2tpIfName),
}

impl fmt::Display for SessionRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ids(tunnel_id, session_id) => {
                write!(f, "session {session_id} in tunnel {tunnel_id}")
            }
            Self::IfName(ifname) => {
                // Names can contain terminal controls or invalid UTF-8.
                write!(f, "session on interface {:?}", ifname.as_os_str())
            }
        }
    }
}

impl SessionRefArgs {
    fn resolve(&self) -> CliResult<SessionRef> {
        match (self.tunnel_id, self.session_id, self.ifname) {
            (Some(tunnel_id), Some(session_id), None) => {
                Ok(SessionRef::Ids(TunnelId(tunnel_id), SessionId(session_id)))
            }
            (None, None, Some(ifname)) => Ok(SessionRef::IfName(ifname)),
            _ => Err(CliError::Usage(
                "select the session with --tunnel-id and --session-id, or \
                 with --ifname"
                    .to_string(),
            )),
        }
    }
}

#[derive(Parser)]
struct SessionDeleteArgs {
    #[command(flatten)]
    session: SessionRefArgs,
}

#[derive(Parser)]
struct SessionChangeArgs {
    #[command(flatten)]
    session: SessionRefArgs,

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
    #[command(flatten)]
    session: SessionRefArgs,
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
    #[command(flatten)]
    session: SessionRefArgs,
}

#[derive(Parser)]
struct MonitorArgs {}

// Persistent CLI tunnels use a kernel-created socket, which has no interface
// scope, so `%ifname` zone suffixes cannot be honoured.
fn reject_scoped_addr(s: &str) -> Result<(), String> {
    if s.contains('%') {
        return Err(format!(
            "interface-scoped address '{s}' is unsupported for persistent CLI \
             tunnels, because the kernel creates their socket without an \
             interface scope; use the library's managed tunnel API for \
             link-local addresses"
        ));
    }
    Ok(())
}

fn parse_udp_addr(s: &str) -> Result<UdpEndpoint, String> {
    reject_scoped_addr(s)?;
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(UdpEndpoint::from(sa));
    }

    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(match ip {
            IpAddr::V4(v4) => {
                UdpEndpoint::V4(std::net::SocketAddrV4::new(v4, 0))
            }
            IpAddr::V6(v6) => UdpEndpoint::V6(SocketAddrV6::new(v6, 0, 0, 0)),
        });
    }

    Err(format!("invalid address '{s}'"))
}

fn resolve_udp_endpoints(
    local_str: Option<&str>,
    remote_str: &str,
) -> CliResult<(UdpEndpoint, UdpEndpoint)> {
    let local =
        parse_udp_addr(local_str.unwrap_or("::")).map_err(CliError::Usage)?;
    let remote = parse_udp_addr(remote_str).map_err(CliError::Usage)?;

    if remote_str.parse::<SocketAddr>().is_err() {
        return Err(CliError::Usage(format!(
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
        (_, remote) if local.ip_version() == remote.ip_version() => {
            Ok((local, remote))
        }
        _ => Err(CliError::Usage(
            "remote address family does not match local; use \
             [::ffff:x.x.x.x]:port for IPv4 remote with IPv6 local"
                .to_string(),
        )),
    }
}

fn parse_ip_addr(s: &str) -> Result<IpEndpoint, String> {
    reject_scoped_addr(s)?;
    s.parse::<IpAddr>()
        .map(IpEndpoint::from)
        .map_err(|_| format!("invalid address '{s}'"))
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

async fn run_tunnel(
    cmd: TunnelCmd,
    handle: &L2tpHandle,
    out: &Output,
) -> CliResult<()> {
    match cmd {
        TunnelCmd::Create(args) => tunnel_create(args, handle, out).await,
        TunnelCmd::Delete(args) => {
            handle.delete_tunnel(TunnelId(args.tunnel_id)).await?;
            out.success(&format!("deleted tunnel {}", args.tunnel_id));
            Ok(())
        }
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

async fn get_session(
    handle: &L2tpHandle,
    session: SessionRef,
) -> CliResult<SessionInfo> {
    Ok(match session {
        SessionRef::Ids(tunnel_id, session_id) => {
            handle.get_session(tunnel_id, session_id).await?
        }
        SessionRef::IfName(ifname) => {
            handle.get_session_by_ifname(&ifname).await?
        }
    })
}

async fn run_session(
    cmd: SessionCmd,
    handle: &L2tpHandle,
    out: &Output,
) -> CliResult<()> {
    match cmd {
        SessionCmd::Create(args) => session_create(args, handle, out).await,
        SessionCmd::Delete(args) => {
            let session = args.session.resolve()?;
            match session {
                SessionRef::Ids(tunnel_id, session_id) => {
                    handle.delete_session(tunnel_id, session_id).await?;
                }
                SessionRef::IfName(ifname) => {
                    handle.delete_session_by_ifname(&ifname).await?;
                }
            }
            out.success(&format!("deleted {session}"));
            Ok(())
        }
        SessionCmd::Change(args) => session_change(args, handle, out).await,
        SessionCmd::Show(args) => {
            let info = get_session(handle, args.session.resolve()?).await?;
            out.session_info(&info);
            Ok(())
        }
        SessionCmd::List(args) => {
            let sessions: Vec<SessionInfo> = match args.tunnel_id {
                Some(tunnel_id) => {
                    handle.list_sessions(TunnelId(tunnel_id)).await?
                }
                None => handle.list_all_sessions().await?,
            };
            out.session_list(&sessions);
            Ok(())
        }
        SessionCmd::Stats(args) => {
            let info = get_session(handle, args.session.resolve()?).await?;
            let stats = handle
                .session_stats(info.tunnel_id, info.session_id)
                .await?;
            out.session_stats(&info, &stats);
            Ok(())
        }
    }
}

async fn run_monitor(handle: &L2tpHandle, out: &Output) -> CliResult<()> {
    let mut events = handle.events().await?;
    while let Some(event) = events.next().await {
        match event {
            Ok(event) => out.event(&event),
            Err(err) => out.error(&format!("cannot decode event: {err}")),
        }
    }
    Ok(())
}

fn validate_persistent_tunnel_options(
    args: &TunnelCreateArgs,
) -> CliResult<()> {
    if args.device.is_some() || args.ipv6_dontfrag {
        return Err(CliError::Usage(
            "--device and --ipv6-dontfrag require an owned socket and are not \
             supported for persistent CLI tunnels; use the library's managed \
             tunnel API"
                .to_string(),
        ));
    }
    Ok(())
}

async fn tunnel_create(
    args: TunnelCreateArgs,
    handle: &L2tpHandle,
    out: &Output,
) -> CliResult<()> {
    validate_persistent_tunnel_options(&args)?;

    let encapsulation = match args.encap {
        EncapArg::Udp => {
            let (local, remote) =
                resolve_udp_endpoints(args.local.as_deref(), &args.remote)?;
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
                CliError::Usage(
                    "--local is required for --encap ip".to_string(),
                )
            })?;
            let local = parse_ip_addr(local_s).map_err(CliError::Usage)?;
            let remote =
                parse_ip_addr(&args.remote).map_err(CliError::Usage)?;
            if local.ip_version() != remote.ip_version() {
                return Err(l2tp::Error::AddressFamilyMismatch.into());
            }
            Encapsulation::Ip { local, remote }
        }
    };
    let version = match args.proto_version {
        VersionArg::V2 => L2tpVersion::V2,
        VersionArg::V3 => L2tpVersion::V3,
    };

    let attempts = if args.tunnel_id.is_some() { 1 } else { 32 };
    for _ in 0..attempts {
        let tunnel_id = TunnelId(match args.tunnel_id {
            Some(v) => v,
            None => random_tunnel_id(version).map_err(|e| {
                CliError::L2tp(
                    io::Error::new(
                        e.kind(),
                        format!("cannot choose a random tunnel id: {e}"),
                    )
                    .into(),
                )
            })?,
        });
        let peer_tunnel_id = TunnelId(args.peer_tunnel_id);
        let config = TunnelConfig::new(
            tunnel_id,
            peer_tunnel_id,
            encapsulation.clone(),
        )?
        .with_version(version);

        match handle.create_unmanaged_tunnel(config).await {
            Ok(mut tunnel) => {
                tunnel.set_auto_delete(false);
                out.success(&format!("created tunnel {tunnel_id}"));
                return Ok(());
            }
            Err(e)
                if args.tunnel_id.is_none()
                    && e.kind() == Some(io::ErrorKind::AlreadyExists) =>
            {
                continue;
            }
            Err(l2tp::Error::UnmanagedUdpChecksum) => {
                return Err(CliError::Usage(
                    "--no-udp-csum is unsupported for IPv4-mapped peers on \
                     persistent IPv6 tunnels; use IPv4 --local and --remote \
                     endpoints or the library's managed tunnel API"
                        .to_string(),
                ));
            }
            Err(l2tp::Error::UnmanagedLinkLocal) => {
                return Err(CliError::Usage(
                    "link-local addresses are unsupported for persistent CLI \
                     tunnels, because the kernel creates their socket without \
                     an interface scope; use the library's managed tunnel API"
                        .to_string(),
                ));
            }
            Err(e) => return Err(e.into()),
        }
    }

    Err(CliError::Usage(
        "failed to allocate unique tunnel id after 32 attempts".to_string(),
    ))
}

async fn session_create(
    args: SessionCreateArgs,
    handle: &L2tpHandle,
    out: &Output,
) -> CliResult<()> {
    let config = SessionConfig {
        tunnel_id: TunnelId(args.tunnel_id),
        session_id: SessionId(args.session_id),
        peer_session_id: SessionId(args.peer_session_id),
        pseudowire_type: map_pw(args.pw_type),
        l2spec_type: map_l2spec(args.l2spec),
        cookie: args.cookie,
        peer_cookie: args.peer_cookie,
        recv_seq: args.recv_seq,
        send_seq: args.send_seq,
        lns_mode: args.lns_mode,
        recv_timeout_ms: args.recv_timeout_ms,
        ifname: args.ifname,
    };

    let mut session = handle.create_session(config).await?;
    session.set_auto_delete(false);
    let device = match session.ifindex() {
        Some(index) => format!(" with interface index {index}"),
        None => String::new(),
    };
    out.success(&format!(
        "created session {} in tunnel {}{device}",
        args.session_id, args.tunnel_id
    ));
    Ok(())
}

async fn session_change(
    args: SessionChangeArgs,
    handle: &L2tpHandle,
    out: &Output,
) -> CliResult<()> {
    let session = args.session.resolve()?;
    let modify = SessionModify {
        recv_seq: flag_pair(args.recv_seq, args.no_recv_seq),
        send_seq: flag_pair(args.send_seq, args.no_send_seq),
        lns_mode: flag_pair(args.lns_mode, args.no_lns_mode),
        recv_timeout_ms: args.recv_timeout_ms,
    };

    if modify.is_empty() {
        out.success("no session changes requested");
        return Ok(());
    }

    match session {
        SessionRef::Ids(tunnel_id, session_id) => {
            handle.modify_session(tunnel_id, session_id, modify).await?;
        }
        SessionRef::IfName(ifname) => {
            handle.modify_session_by_ifname(&ifname, modify).await?;
        }
    }
    out.success(&format!("updated {session}"));
    Ok(())
}

// L2TPv3 relies on identifiers an off-path attacker cannot guess, so take them
// from the kernel's random number generator. getrandom(2) needs no /dev node
// and blocks until the generator is seeded; there is no weaker fallback.
// L2TPv2 identifiers are 16-bit on the wire, so they stay within 1..=65535.
fn random_tunnel_id(version: L2tpVersion) -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    let mut filled = 0;
    while filled < bytes.len() {
        let rest = &mut bytes[filled..];
        // SAFETY: `rest` is a valid, writable buffer of `rest.len()` bytes.
        let n =
            unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        match usize::try_from(n) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "getrandom returned no bytes",
                ));
            }
            Ok(n) => filled += n,
            Err(_) => {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }
    let random = u32::from_ne_bytes(bytes);
    Ok(match version {
        L2tpVersion::V2 => 1 + random % u32::from(u16::MAX),
        _ => 1_000_000 + random % (u32::MAX - 999_999),
    })
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
pub(crate) async fn main() -> ExitCode {
    let cli = Cli::parse();
    let out = Output::new(cli.output);

    let config = HandleConfig::default().with_request_timeout(
        (cli.request_timeout != 0)
            .then(|| Duration::from_secs(cli.request_timeout)),
    );
    let handle = match L2tpHandle::new(config).await {
        Ok(v) => v,
        Err(e) => {
            out.error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };

    let result = match cli.cmd {
        Cmd::Tunnel(args) => run_tunnel(args.cmd, &handle, &out).await,
        Cmd::Session(args) => run_session(args.cmd, &handle, &out).await,
        Cmd::Monitor(_) => run_monitor(&handle, &out).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            out.error(&e.to_string());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_tunnel_create(argv: &[&str]) -> TunnelCreateArgs {
        let Cli {
            cmd:
                Cmd::Tunnel(TunnelArgs {
                    cmd: TunnelCmd::Create(args),
                }),
            ..
        } = Cli::try_parse_from(argv).unwrap()
        else {
            panic!("expected tunnel create");
        };
        args
    }

    fn parse_session_create<I, T>(argv: I) -> SessionCreateArgs
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let Cli {
            cmd:
                Cmd::Session(SessionArgs {
                    cmd: SessionCmd::Create(args),
                }),
            ..
        } = Cli::try_parse_from(argv).unwrap()
        else {
            panic!("expected session create");
        };
        args
    }

    #[test]
    fn request_timeout_is_explicitly_configurable_and_disablable() {
        assert_eq!(
            Cli::try_parse_from(["l2tp", "tunnel", "list"])
                .unwrap()
                .request_timeout,
            30
        );
        for value in ["0", "5"] {
            assert_eq!(
                Cli::try_parse_from([
                    "l2tp",
                    "tunnel",
                    "list",
                    "--request-timeout",
                    value
                ])
                .unwrap()
                .request_timeout,
                value.parse::<u64>().unwrap()
            );
        }
    }

    #[test]
    fn persistent_tunnel_options_reject_socket_only_flags() {
        for extra in [vec![], vec!["--device", "lo"], vec!["--ipv6-dontfrag"]] {
            let mut argv = vec![
                "l2tp",
                "tunnel",
                "create",
                "--peer-tunnel-id",
                "2",
                "--remote",
                "127.0.0.1:1701",
            ];
            argv.extend(&extra);
            let args = parse_tunnel_create(&argv);
            let result = validate_persistent_tunnel_options(&args);
            if extra.is_empty() {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(CliError::Usage(_))));
            }
        }
    }

    #[test]
    fn protocol_version_defaults_to_three() {
        let args = parse_tunnel_create(&[
            "l2tp",
            "tunnel",
            "create",
            "--peer-tunnel-id",
            "2",
            "--remote",
            "127.0.0.1:1701",
        ]);
        assert!(matches!(args.proto_version, VersionArg::V3));
        let args = parse_tunnel_create(&[
            "l2tp",
            "tunnel",
            "create",
            "--peer-tunnel-id",
            "2",
            "--remote",
            "127.0.0.1:1701",
            "--proto-version",
            "2",
        ]);
        assert!(matches!(args.proto_version, VersionArg::V2));
        assert!(
            Cli::try_parse_from([
                "l2tp",
                "tunnel",
                "create",
                "--peer-tunnel-id",
                "2",
                "--remote",
                "127.0.0.1:1701",
                "--proto-version",
                "4",
            ])
            .is_err()
        );
    }

    #[tokio::test]
    async fn persistent_mapped_tunnel_rejects_disabled_udp_checksum() {
        let handle = L2tpHandle::new(Default::default()).await.unwrap();
        let out = Output::new(OutputFmt::Text);
        for (local, remote) in [
            (Some("[::]:1701"), "127.0.0.1:1702"),
            (Some("[::]:1701"), "[::ffff:127.0.0.1]:1702"),
            (Some("[::ffff:127.0.0.1]:1701"), "[::ffff:127.0.0.2]:1702"),
            (None, "[::ffff:127.0.0.1]:1702"),
        ] {
            let mut argv = vec![
                "l2tp",
                "tunnel",
                "create",
                "--peer-tunnel-id",
                "2",
                "--remote",
                remote,
                "--no-udp-csum",
            ];
            if let Some(local) = local {
                argv.extend(["--local", local]);
            }
            let args = parse_tunnel_create(&argv);
            // The unsupported setting must fail before any netlink request,
            // without requiring L2TP support or CAP_NET_ADMIN.
            let err = tunnel_create(args, &handle, &out).await.unwrap_err();
            assert!(matches!(err, CliError::Usage(_)));
            assert!(err.to_string().contains("--no-udp-csum"));
            assert!(err.to_string().contains("IPv4-mapped"));
        }
    }

    #[tokio::test]
    async fn persistent_tunnels_reject_link_local_addresses() {
        let handle = L2tpHandle::new(Default::default()).await.unwrap();
        let out = Output::new(OutputFmt::Text);
        for (encap, local, remote, expected) in [
            // Zone suffixes are rejected while parsing.
            ("ip", "fe80::1%eth0", "fe80::2", "interface-scoped"),
            (
                "udp",
                "[::]:1701",
                "[fe80::2%eth0]:1701",
                "interface-scoped",
            ),
            // Plain link-local addresses fail before any netlink request.
            ("ip", "fe80::1", "fe80::2", "link-local"),
            ("udp", "[::]:1701", "[fe80::2]:1701", "link-local"),
        ] {
            let args = parse_tunnel_create(&[
                "l2tp",
                "tunnel",
                "create",
                "--peer-tunnel-id",
                "2",
                "--encap",
                encap,
                "--local",
                local,
                "--remote",
                remote,
            ]);
            let err = tunnel_create(args, &handle, &out).await.unwrap_err();
            assert!(matches!(err, CliError::Usage(_)), "{err}");
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    #[test]
    fn interface_name_arguments_are_validated_while_parsing() {
        let base = [
            "l2tp",
            "session",
            "create",
            "--tunnel-id",
            "1",
            "--session-id",
            "2",
            "--peer-session-id",
            "3",
            "--ifname",
        ];
        let err = Cli::try_parse_from(base.iter().chain(["eth:0"].iter()))
            .err()
            .expect("an invalid name must be rejected");
        assert!(err.to_string().contains("invalid interface name"), "{err}");
        let args = parse_session_create(base.iter().chain(["l2tpeth0"].iter()));
        assert_eq!(args.ifname.unwrap().to_str().unwrap(), "l2tpeth0");

        // Names are byte strings, so arguments need not be UTF-8.
        let raw =
            std::os::unix::ffi::OsStringExt::from_vec(b"eth\xff0".to_vec());
        let argv: Vec<OsString> = base
            .iter()
            .map(OsString::from)
            .chain(std::iter::once(raw))
            .collect();
        let args = parse_session_create(argv);
        assert_eq!(args.ifname.unwrap().as_bytes(), b"eth\xff0");

        let err = Cli::try_parse_from([
            "l2tp",
            "tunnel",
            "create",
            "--peer-tunnel-id",
            "2",
            "--remote",
            "127.0.0.1:1701",
            "--device",
            "a b",
        ])
        .err()
        .expect("an invalid device must be rejected");
        assert!(err.to_string().contains("invalid interface name"), "{err}");
    }

    #[test]
    fn cookies_are_parsed_as_hex_while_parsing() {
        let base = [
            "l2tp",
            "session",
            "create",
            "--tunnel-id",
            "1",
            "--session-id",
            "2",
            "--peer-session-id",
            "3",
        ];
        let args = parse_session_create(base);
        assert!(args.cookie.is_empty());
        let args = parse_session_create(base.iter().copied().chain([
            "--cookie",
            "deadbeef",
            "--peer-cookie",
            "",
        ]));
        assert_eq!(args.cookie.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert!(args.peer_cookie.is_empty());
        // Multi-byte characters, sign characters and odd lengths are errors.
        for bad in ["aéb", "éé", "+1+2+3+4", "abc", "zzzzzzzz", "abcdef"] {
            let err = Cli::try_parse_from(
                base.iter().copied().chain(["--cookie", bad]),
            )
            .err()
            .expect("an invalid cookie must be rejected");
            assert!(err.to_string().contains("cookie"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn session_selectors_need_ids_or_an_interface_name() {
        let parse = |argv: &[&str]| -> CliResult<SessionRef> {
            let Cli {
                cmd:
                    Cmd::Session(SessionArgs {
                        cmd: SessionCmd::Show(args),
                    }),
                ..
            } = Cli::try_parse_from(argv)
                .map_err(|e| CliError::Usage(e.to_string()))?
            else {
                panic!("expected session show");
            };
            args.session.resolve()
        };
        assert!(matches!(
            parse(&[
                "l2tp",
                "session",
                "show",
                "--tunnel-id",
                "1",
                "--session-id",
                "2"
            ]),
            Ok(SessionRef::Ids(TunnelId(1), SessionId(2)))
        ));
        assert!(matches!(
            parse(&["l2tp", "session", "show", "--ifname", "l2tpeth0"]),
            Ok(SessionRef::IfName(name)) if name.as_bytes() == b"l2tpeth0"
        ));
        assert!(parse(&["l2tp", "session", "show"]).is_err());
        assert!(
            parse(&["l2tp", "session", "show", "--tunnel-id", "1"]).is_err()
        );
        assert!(
            parse(&[
                "l2tp",
                "session",
                "show",
                "--tunnel-id",
                "1",
                "--session-id",
                "2",
                "--ifname",
                "l2tpeth0"
            ])
            .is_err()
        );
    }

    #[test]
    fn session_name_status_messages_escape_terminal_controls() {
        for raw in [
            &b"\x1b[2Jeth0"[..],
            &b"\x1b]52;;YQ==\x07"[..],
            &b"eth\x9b0"[..],
            &b"eth\xff0"[..],
        ] {
            let session = SessionRef::IfName(L2tpIfName::new(raw).unwrap());
            let message = format!("deleted {session}");
            assert!(!message.chars().any(char::is_control), "{message:?}");
            assert!(!message.contains('\u{fffd}'), "{message:?}");
            assert!(message.contains('\\'), "{message:?}");
        }
    }

    #[test]
    fn random_tunnel_ids_stay_in_range_and_vary() {
        let ids: Vec<u32> = (0..32)
            .map(|_| random_tunnel_id(L2tpVersion::V3).unwrap())
            .collect();
        assert!(ids.iter().all(|&id| id >= 1_000_000));
        assert!(ids.windows(2).any(|w| w[0] != w[1]));

        // L2TPv2 identifiers must fit 16 bits for the PPPoL2TP socket.
        let ids: Vec<u32> = (0..32)
            .map(|_| random_tunnel_id(L2tpVersion::V2).unwrap())
            .collect();
        assert!(
            ids.iter()
                .all(|&id| (1..=u32::from(u16::MAX)).contains(&id))
        );
        assert!(ids.windows(2).any(|w| w[0] != w[1]));
    }
}

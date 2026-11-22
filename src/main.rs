mod cli;
mod client;
mod daemon;
mod discovery;
mod doctor;
mod hashcache;
mod hosts;
mod identity;
mod protocol;
mod pull;
mod server;
mod sync;
mod ui;
mod verbose;

use crate::cli::{Cli, Command};
use crate::protocol::{DeviceInfo, Peer, DEFAULT_PORT, PROTOCOL_VERSION};
use anyhow::{bail, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use std::collections::HashMap;
use std::io::IsTerminal;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Everything a running zapsend instance needs: identity, HTTP server, discovery.
struct Stack {
    me: DeviceInfo,
    registry: discovery::Registry,
    /// `None` when we skip networking (sending straight to an --ip target).
    sock: Option<Arc<tokio::net::UdpSocket>>,
    /// The same state the HTTPS server runs on; the web UI reads it directly.
    state: Arc<server::AppState>,
}

/// Identity only — no listeners. Used by `send --ip`, which does not need to
/// be discoverable itself and therefore never fights another instance for a port.
pub(crate) fn local_only(alias: &str, port: u16) -> Result<Stack> {
    let (_, me) = identity::load_or_create(alias, port)?;
    let registry = discovery::new_registry();
    let state = Arc::new(server::AppState {
        me: me.clone(),
        registry: registry.clone(),
        download_dir: PathBuf::from("./zapsend-received"),
        sessions: Mutex::new(HashMap::new()),
        pin: server::PinState::new(None),
        ask: false,
        share: None,
        downloads: Mutex::new(HashMap::new()),
    });
    Ok(Stack {
        me,
        registry,
        sock: None,
        state,
    })
}

/// How badly a command needs the HTTPS API server.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiServer {
    /// `receive`: a receiver that cannot listen is useless, so a busy port is
    /// fatal instead of a half-working instance.
    Required,
    /// `discover` and `send --to`: peers only answer an announcement by calling
    /// `POST /register` back on the announced port. Losing that listener makes
    /// the scan blind, but a port already held by another instance must not
    /// kill the command — so take any free port and announce that one.
    Want,
}

/// Full stack: HTTPS API server + multicast discovery.
///
/// `plain` serves plain HTTP with no TLS instead. Only `receive --plain`
/// passes true: a receiver on a private network whose link is already
/// encrypted (Tailscale, WireGuard). The sender side always keeps TLS for
/// its own listener — plain only ever describes the peer.
pub(crate) async fn start(
    alias: &str,
    port: u16,
    download_dir: PathBuf,
    // Directory to offer through the Download API, if any.
    share: Option<PathBuf>,
    pin: Option<String>,
    ask: bool,
    api: ApiServer,
    plain: bool,
) -> Result<Stack> {
    let (tls, mut me) = if plain {
        (None, identity::plain_info(alias, port))
    } else {
        let (identity, info) = identity::load_or_create(alias, port)?;
        let tls = RustlsConfig::from_pem(
            identity.cert_pem.into_bytes(),
            identity.key_pem.into_bytes(),
        )
        .await
        .context("building TLS config")?;
        (Some(tls), info)
    };
    let registry = discovery::new_registry();

    // Bind before spawning so a taken port fails loudly here instead of
    // silently leaving a receiver that claims to listen but never does.
    let listener = match std::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))) {
        Ok(l) => Some(l),
        Err(e) if api == ApiServer::Required => {
            return Err(anyhow::Error::new(e).context(format!(
                "cannot bind the API server to :{port} — another instance already holds it"
            )));
        }
        Err(_) => {
            let l = std::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 0)))?;
            let actual = l.local_addr()?.port();
            eprintln!("! port :{port} is in use — announcing :{actual} instead");
            me.port = actual;
            Some(l)
        }
    };

    // Peers decide whether to call the Download API from this flag, so it has to
    // match reality: `--share` turns the API on, and nothing else does.
    if share.is_some() {
        me.download = true;
    }
    // This receiver can always resume a half-finished upload.
    me.zapsend_resume = true;

    let state = Arc::new(server::AppState {
        me: me.clone(),
        registry: registry.clone(),
        download_dir,
        sessions: Mutex::new(HashMap::new()),
        pin: server::PinState::new(pin),
        ask,
        share,
        downloads: Mutex::new(HashMap::new()),
    });
    let app = server::router(state.clone());

    if let Some(listener) = listener {
        listener.set_nonblocking(true)?;
        if plain {
            // No TLS at all: the same router, the same PIN checks, served
            // over plain HTTP. Only reachable on a private network — the
            // caller (`receive --plain`) is what opts into this.
            tokio::spawn(async move {
                if let Err(e) = axum_server::from_tcp(listener)
                    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                {
                    eprintln!("! API server stopped: {e}");
                }
            });
        } else {
            let tls = tls.expect("TLS config is built whenever plain is false");
            tokio::spawn(async move {
                if let Err(e) = axum_server::from_tcp_rustls(listener, tls)
                    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                {
                    eprintln!("! API server stopped: {e}");
                }
            });
        }
    }

    let sock = Arc::new(discovery::bind_multicast()?);
    tokio::spawn(discovery::listen(
        sock.clone(),
        registry.clone(),
        me.clone(),
    ));

    Ok(Stack {
        me,
        registry,
        sock: Some(sock),
        state,
    })
}

#[tokio::main]
async fn main() {
    // A failed run still has to be readable by a script: the verdict lives in
    // the exit code, and `--json` puts the reason on stderr as one object so
    // stdout stays a pure result channel.
    if let Err(e) = run().await {
        if json_mode() {
            eprintln!(
                "{}",
                serde_json::json!({"ok": false, "error": format!("{e:#}")})
            );
        } else {
            eprintln!("error: {e:#}");
        }
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    // rustls 0.23 refuses to guess a crypto backend when more than one is
    // compiled in (axum-server and reqwest pull different defaults).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    verbose::set(cli.verbose);
    // `--json` is per invocation, but an agent driving several commands should
    // not have to remember it every time. `ZAPSEND_JSON=1` sets it once for the
    // whole session. Auto-detecting a pipe was considered and rejected: it would
    // silently rewrite the output of every existing script that reads ours.
    let json_env = std::env::var("ZAPSEND_JSON")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    JSON_MODE.store(cli.json || json_env, std::sync::atomic::Ordering::Relaxed);
    let alias = cli.alias.clone();
    let port = cli.port;

    match cli.command {
        Command::Trust {
            name,
            ip,
            fingerprint,
            pin,
            plain,
        } => trust(&name, &ip, fingerprint, pin, plain).await,
        Command::Hosts => print_hosts(),
        Command::Forget { name } => forget(&name),
        Command::Discover { wait } => discover(&alias, port, wait).await,
        Command::Send {
            files,
            to,
            ip,
            fingerprint,
            tofu,
            pin,
            scan,
            retry,
            plain,
        } => {
            send(
                &alias,
                port,
                files,
                to,
                ip,
                fingerprint,
                tofu,
                pin,
                scan,
                retry,
                plain,
            )
            .await
        }
        Command::Receive {
            dir,
            pin,
            ask,
            share,
            plain,
        } => receive(&alias, port, dir, share, pin, ask, plain).await,
        Command::Pull {
            to,
            ip,
            fingerprint,
            tofu,
            pin,
            dir,
            file,
            scan,
            retry,
            plain,
        } => {
            pull::run(
                &alias,
                port,
                pull::Options {
                    to,
                    ip,
                    fingerprint,
                    tofu,
                    pin,
                    dir,
                    file,
                    scan,
                    retry,
                    plain,
                },
            )
            .await
        }
        Command::Sync {
            dir,
            to,
            ip,
            fingerprint,
            tofu,
            pin,
            dry_run,
            replace,
            retries,
            plain,
        } => {
            sync::run(
                &alias,
                port,
                sync::Options {
                    dir,
                    to,
                    ip,
                    fingerprint,
                    tofu,
                    pin,
                    dry_run,
                    replace,
                    retries,
                    plain,
                },
            )
            .await
        }
        Command::Doctor {
            to,
            ip,
            scan,
            dir,
            plain,
        } => doctor::run(&alias, port, doctor::Options { to, ip, scan, dir, plain }).await,
        Command::Daemon {
            dir,
            to,
            ip,
            fingerprint,
            tofu,
            pin,
            interval,
            settle,
            keep,
            scan,
            plain,
        } => {
            daemon::run(
                &alias,
                port,
                daemon::Options {
                    dir,
                    to,
                    ip,
                    fingerprint,
                    tofu,
                    pin,
                    interval,
                    settle,
                    keep,
                    scan,
                    plain,
                },
            )
            .await
        }
        Command::Ui {
            dir,
            pin,
            ui_port,
            no_open,
        } => ui::run(&alias, port, dir, pin, ui_port, no_open).await,
    }
}

/// Announce ourselves for `secs` seconds, then return everything we heard.
pub(crate) async fn scan(stack: &Stack, secs: u64) -> Vec<Peer> {
    let Some(sock) = stack.sock.as_ref() else {
        return Vec::new();
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        let _ = discovery::announce(sock, &stack.me).await;
        tokio::time::sleep(Duration::from_millis(800)).await;
    }

    // Multicast is the happy path; the /24 sweep is what saves a tethered
    // laptop, a guest network or an AP with client isolation.
    if stack.registry.lock().unwrap().is_empty() {
        if let Err(e) = discovery::sweep(&stack.registry, &stack.me, false).await {
            eprintln!("! subnet sweep failed: {e}");
        }
    }

    let mut peers = {
        let reg = stack.registry.lock().unwrap();
        reg.values().cloned().collect::<Vec<_>>()
    };
    peers.sort_by(|a, b| a.info.alias.cmp(&b.info.alias));
    peers
}

fn print_peers(peers: &[Peer]) {
    if peers.is_empty() {
        println!("no devices found.");
        println!();
        println!("troubleshooting:");
        println!("  · is LocalSend open on the other device?");
        println!("  · is the network blocking multicast? (common on guest wifi)");
        println!("  · try the fallback:  zapsend send <file> --ip <address>");
        return;
    }

    println!(
        "{:<24} {:<20} {:<10} FINGERPRINT",
        "ALIAS", "ADDRESS", "TYPE"
    );
    for p in peers {
        println!(
            "{:<24} {:<20} {:<10} {}…",
            truncate(&p.info.alias, 24),
            format!("{}:{}", p.ip, p.info.port),
            p.info.device_type.as_deref().unwrap_or("?"),
            identity::short_fingerprint(&p.info.fingerprint),
        );
    }
}

/// Printed once on startup. Plain ASCII, so it survives every terminal and
/// every code page Windows can throw at it.
/// Output mode is a process-wide fact, not a parameter worth threading through
/// every command: `--json` means "stdout is JSON, stderr is for humans".
/// ponytail: a global, because the alternative is a flag on six functions and
/// every call site, for something that cannot change mid-run.
static JSON_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn json_mode() -> bool {
    JSON_MODE.load(std::sync::atomic::Ordering::Relaxed)
}

fn banner() {
    use std::io::IsTerminal;

    if json_mode() {
        return;
    }

    // Colour only when a human is looking; pipes and logs get plain text.
    let plain = !std::io::stdout().is_terminal() || std::env::var_os("NO_COLOR").is_some();
    let (bold_white, bold_green, green, dim, reset) = if plain {
        ("", "", "", "", "")
    } else {
        (
            "\x1b[1;3;38;2;248;250;252m",
            "\x1b[1;3;38;2;32;232;137m",
            "\x1b[1;38;2;32;232;137m",
            "\x1b[2m",
            "\x1b[0m",
        )
    };

    println!(
        "  {green}⇄{reset}  {bold_white}Zap{bold_green}Send{reset} {dim}{}{reset}",
        env!("CARGO_PKG_VERSION")
    );
    println!("     {dim}headless file transfer, LocalSend protocol{reset}");
    println!();
}

pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

async fn discover(alias: &str, port: u16, wait: u64) -> Result<()> {
    let stack = start(
        alias,
        port,
        PathBuf::from("./zapsend-received"),
        None,
        None,
        false,
        ApiServer::Want,
        false,
    )
    .await?;
    eprintln!("scanning for {wait}s…");
    let peers = scan(&stack, wait).await;
    if json_mode() {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "discover",
                "devices": peers.iter().map(|p| serde_json::json!({
                    "alias": p.info.alias,
                    "ip": p.ip.to_string(),
                    "port": p.info.port,
                    "protocol": p.info.protocol,
                    "fingerprint": p.info.fingerprint,
                    "deviceType": p.info.device_type,
                    "download": p.info.download,
                })).collect::<Vec<_>>(),
            })
        );
    } else {
        print_peers(&peers);
    }
    Ok(())
}

/// Turn the command-line arguments into one upload per file, walking folders.
///
/// A folder keeps its own name as a prefix (`holiday/img.jpg`), so the receiver
/// rebuilds the tree instead of dumping a hundred loose files. Empty folders
/// carry no files and are therefore not recreated — the protocol has no way to
/// express a directory on its own.
pub(crate) fn collect_uploads(paths: &[PathBuf]) -> Result<Vec<client::Upload>> {
    let mut out = Vec::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .with_context(|| format!("invalid name: {}", path.display()))?
            .to_string();
        if path.is_dir() {
            walk_dir(path, &name, &mut out)?;
        } else {
            out.push(client::Upload {
                path: path.clone(),
                name,
                replace: false,
            });
        }
    }
    if out.is_empty() {
        bail!("nothing to send");
    }
    Ok(out)
}

fn walk_dir(dir: &Path, prefix: &str, out: &mut Vec<client::Upload>) -> Result<()> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read folder {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let remote = format!("{prefix}/{name}");
        if path.is_dir() {
            walk_dir(&path, &remote, out)?;
        } else {
            out.push(client::Upload {
                path,
                name: remote,
                replace: false,
            });
        }
    }
    Ok(())
}

/// Resolve a `--ip` target into a peer whose certificate we can pin, or refuse.
///
/// `--ip` skips discovery, so there is no announcement to pin against. The
/// three ways through, in order:
/// * `--fingerprint` — pin exactly that certificate.
/// * a fingerprint saved earlier under this address (by `trust` under a name,
///   or by an earlier `--tofu` under the address itself).
/// * `--tofu` — trust on first sight: take the fingerprint the peer announces
///   over /info and save it under the address, so the next command verifies
///   against it. Only on a network you trust.
/// A peer that serves plain HTTP has no certificate to pin. On the trust-on-
/// first-sight path that is refused, not reported: `--tofu` is about the
/// certificate, not the transport, and a cleartext answer must not carry the
/// PIN and the files without the caller saying so. `--plain` is the explicit
/// form of that: the caller already knows the peer is plain (a `receive
/// --plain` receiver on a private network), so no fingerprint is asked for,
/// saved, or checked. It contradicts `--fingerprint`.
pub(crate) async fn resolve_ip_peer(
    raw: &str,
    fingerprint: Option<&str>,
    tofu: bool,
    verb: &str,
    plain: bool,
) -> Result<Peer> {
    let (addr, target_port) = parse_target(raw)?;
    if plain && fingerprint.is_some() {
        bail!("--plain and --fingerprint contradict each other: a plain-HTTP peer has no certificate to pin");
    }
    if plain {
        // Nothing to verify and nothing to save: a plain peer announces no
        // fingerprint, and the caller already decided this address is plain.
        // The caller fetches /info next and learns resume/download from it.
        return Ok(Peer {
            info: DeviceInfo {
                zapsend_resume: false,
                alias: raw.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                device_model: None,
                device_type: None,
                fingerprint: String::new(),
                port: target_port,
                protocol: "http".to_string(),
                download: false,
            },
            ip: addr,
        });
    }
    let key = hosts::address_key(addr, target_port);
    let mut peer = Peer {
        info: DeviceInfo {
            zapsend_resume: false,
            alias: raw.to_string(),
            version: PROTOCOL_VERSION.to_string(),
            device_model: None,
            device_type: None,
            fingerprint: String::new(),
            port: target_port,
            protocol: "https".to_string(),
            download: false,
        },
        ip: addr,
    };
    if let Some(given) = fingerprint {
        if given.len() != 64 || !given.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("a fingerprint is 64 hex characters, got {}", given.len());
        }
        peer.info.fingerprint = given.to_ascii_lowercase();
        return Ok(peer);
    }
    if let Some(known) = hosts::peer(&key).await? {
        return Ok(known);
    }
    if !tofu {
        bail!("{}", unverified_ip_refusal(addr, target_port, verb));
    }
    // Trust on first sight: ask who is there over an unverified connection,
    // take the fingerprint it announces, and save it before any file moves.
    let info = client::fetch_info(&peer).await.with_context(|| {
        format!("cannot reach {raw}: pass --fingerprint to save it without a check")
    })?;
    if info.protocol.eq_ignore_ascii_case("http") {
        // Trust on first sight is about the certificate, not the transport:
        // a cleartext answer must not carry the PIN and the files without
        // the caller saying so with --plain.
        bail!("{raw} serves plain HTTP. Pass --plain to send to it (private network only, never on the open internet)");
    }
    if info.fingerprint.len() != 64 {
        bail!("{raw} did not announce a fingerprint, nothing to pin — pass --fingerprint to save one without a check");
    }
    let stored = info.fingerprint.to_ascii_lowercase();
    hosts::remember(&key, &addr.to_string(), target_port, Some(stored.clone()), None)?;
    eprintln!(
        "! trusting {raw} on first sight — fingerprint {} saved; compare it with what the machine prints when it starts",
        identity::short_fingerprint(&stored)
    );
    peer.info.fingerprint = stored;
    peer.info.zapsend_resume = info.zapsend_resume;
    peer.info.download = info.download;
    peer.info.protocol = info.protocol;
    if !info.alias.is_empty() {
        peer.info.alias = info.alias;
    }
    Ok(peer)
}

/// The error for a `--ip` target nobody has verified yet. It has to name the
/// fix, not just the problem: a user who typed `--ip` on a trusted home
/// network is one command away from a verified connection, and the error
/// should be that command.
fn unverified_ip_refusal(addr: IpAddr, port: u16, verb: &str) -> String {
    format!(
        "refusing to {verb} {addr}:{port} without a verified certificate fingerprint.

The peer's certificate cannot be checked against anything you have seen before, so a machine on this network could pretend to be it. Fix it one of these ways:
  zapsend trust NAME --ip {addr}:{port}   # remember it once, then use --to NAME
  add --fingerprint <64 hex chars from `zapsend discover`>
  add --tofu   # trust on first sight, save the fingerprint for next time"
    )
}

/// Refuse to use a peer whose certificate cannot be pinned, unless it serves
/// plain HTTP — then there is no certificate at all, and the warning says
/// so. Discovery and `trust` always supply a fingerprint; an empty one here
/// means a hand-edited hosts entry, or a `--ip` that slipped past
/// `resolve_ip_peer`.
pub(crate) fn require_verified(peer: &Peer, fix: &str) -> Result<()> {
    if !peer.info.fingerprint.is_empty() {
        return Ok(());
    }
    if peer.info.protocol.eq_ignore_ascii_case("http") {
        eprintln!(
            "! {} serves plain HTTP — there is no certificate to pin, traffic is unencrypted",
            peer.info.alias
        );
        return Ok(());
    }
    bail!(
        "refusing to talk to {} ({}:{}) without a verified certificate fingerprint.

The peer's certificate cannot be checked against anything you have seen before, so a machine on this network could pretend to be it.
{fix}",
        peer.info.alias,
        peer.ip,
        peer.info.port
    )
}

/// Accept `1.2.3.4` or `1.2.3.4:53400`.
pub(crate) fn parse_target(raw: &str) -> Result<(IpAddr, u16)> {
    match raw.rsplit_once(':') {
        Some((ip, port)) => {
            let addr = ip
                .trim_matches(|c| c == '[' || c == ']')
                .parse()
                .with_context(|| format!("invalid IP in {raw}"))?;
            let port = port
                .parse()
                .with_context(|| format!("invalid port in {raw}"))?;
            Ok((addr, port))
        }
        None => Ok((
            raw.parse().with_context(|| format!("invalid IP {raw}"))?,
            DEFAULT_PORT,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn send(
    alias: &str,
    port: u16,
    files: Vec<PathBuf>,
    to: Option<String>,
    ip: Option<String>,
    fingerprint: Option<String>,
    tofu: bool,
    pin: Option<String>,
    scan_secs: u64,
    retries: u32,
    plain: bool,
) -> Result<()> {
    // `--to a,b,c` (or `--to all`, every trusted host) fans the same files out to
    // a list. Resolving each name from the hosts file is the fleet case; a scan
    // per name would need a human to pick between answers, which is the opposite
    // of unattended.
    if let Some(list) = to.as_deref().filter(|t| t.contains(',') || *t == "all") {
        let names: Vec<String> = if list == "all" {
            hosts::load()?.keys().cloned().collect()
        } else {
            list.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        };
        if names.is_empty() {
            bail!("nothing to send to: the hosts file is empty (`zapsend trust NAME --ip ADDR`)");
        }
        if list != "all" && names.len() < 2 {
            bail!("--to {list:?} needs at least two names");
        }
        return fan_out(alias, port, files, &names, pin, retries).await;
    }

    // Straight-to-address sends need neither a server nor discovery, so they
    // work even while another instance owns the port.
    let (stack, peer) = match ip {
        Some(raw) => {
            let stack = local_only(alias, port)?;
            let mut peer =
                resolve_ip_peer(&raw, fingerprint.as_deref(), tofu, "send files to", plain).await?;
            // Ask who is actually there before sending: that is how we learn
            // whether it can resume a broken upload, and which scheme it serves.
            // A peer that does not answer /info is not a reason to give up.
            if let Ok(info) = client::fetch_info(&peer).await {
                peer.info.zapsend_resume = info.zapsend_resume;
                peer.info.download = info.download;
                peer.info.protocol = info.protocol;
                // The port is *not* taken from the answer: the address we just
                // reached is the only one proven to work. A peer that announces
                // a different port would otherwise send us somewhere we never
                // verified — that is how `--ip host:53320` ended up talking to
                // 53317 and failing against a real LocalSend implementation.
                if !info.alias.is_empty() {
                    peer.info.alias = info.alias;
                }
            }
            (stack, peer)
        }
        None => match peer_from_hosts(alias, port, &to).await? {
            Some(pair) => pair,
            None => {
            let stack = start(
                alias,
                port,
                PathBuf::from("./zapsend-received"),
                None,
                None,
                false,
                ApiServer::Want,
                false,
            )
            .await?;
            eprintln!("scanning for {scan_secs}s…");
            let peers = scan(&stack, scan_secs).await;
            let peer = match resolve_target(&peers, to.as_deref())? {
                Some(p) => p,
                None => {
                    print_peers(&peers);
                    bail!("no device selected");
                }
            };
            if let Some(expected) = fingerprint.as_deref() {
                if !peer.info.fingerprint.eq_ignore_ascii_case(expected) {
                    bail!(
                        "fingerprint mismatch: you pinned {}, but discovery found {}",
                        expected,
                        peer.info.fingerprint
                    );
                }
            }
            (stack, peer)
            }
        },
    };

    let uploads = collect_uploads(&files)?;
    let bytes: u64 = uploads
        .iter()
        .filter_map(|u| std::fs::metadata(&u.path).ok())
        .map(|m| m.len())
        .sum();

    eprintln!(
        "sending {} file(s), {} to \"{}\" ({}:{})",
        uploads.len(),
        human_bytes(bytes),
        peer.info.alias,
        peer.ip,
        peer.info.port
    );
    require_verified(
        &peer,
        "re-trust it first: `zapsend trust NAME --ip ADDR`, or pass --fingerprint",
    )?;
    if !peer.info.fingerprint.is_empty() {
        eprintln!(
            "  pinned to {}",
            identity::short_fingerprint(&peer.info.fingerprint)
        );
    }

    let pin = hosts::resolve_pin(pin, to.as_deref());
    client::send_files(&peer, &stack.me, &uploads, pin.as_deref(), retries).await?;
    if json_mode() {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "send",
                "peer": {
                    "alias": peer.info.alias,
                    "ip": peer.ip.to_string(),
                    "port": peer.info.port,
                    "fingerprint": peer.info.fingerprint,
                },
                "files": uploads.iter().map(|u| u.name.clone()).collect::<Vec<_>>(),
                "count": uploads.len(),
                "bytes": bytes,
            })
        );
    } else {
        println!("✓ done");
    }
    Ok(())
}


/// How many hosts a fan-out talks to at once. Four, because it matches the
/// two bounds already calibrated in `client`: four concurrent file uploads
/// per send, four concurrent hashes. A fan-out of the usual size (two or
/// three hosts) runs fully in parallel under it, while a `--to all` list of
/// dozens still opens at most four TLS sessions at a time instead of one
/// per host. More would not help on the machines this runs on: one 1 GiB
/// send already keeps the sender's hashing and TLS busy, so the gain comes
/// from overlapping the hosts, not from piling more of them on.
const FANOUT_CONCURRENCY: usize = 4;

/// Run one async job per item with at most `limit` in flight, collecting the
/// results in input order. One item's outcome never cancels the others: a
/// job that fails returns its failure as a value, and the caller decides
/// what that means. A job that panics is a bug, not a peer failure, so it
/// still fails the whole run.
async fn run_bounded<T, F, Fut, O>(items: Vec<T>, limit: usize, f: F) -> Result<Vec<O>>
where
    T: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = O> + Send + 'static,
    O: Send + 'static,
{
    let n = items.len();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(limit.max(1)));
    let f = Arc::new(f);
    let mut set = tokio::task::JoinSet::new();
    for (idx, item) in items.into_iter().enumerate() {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("fan-out semaphore closed");
        let f = f.clone();
        set.spawn(async move {
            let _permit = permit;
            (idx, f(item).await)
        });
    }
    let mut out: Vec<Option<O>> = (0..n).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        let (idx, value) = joined?;
        out[idx] = Some(value);
    }
    Ok(out
        .into_iter()
        .map(|v| v.expect("fan-out task never ran"))
        .collect())
}

/// What one host of a fan-out did. The error is a plain string, not the
/// anyhow error, so the outcome stays `Send` without dragging the error
/// type through the task boundary.
struct HostOutcome {
    name: String,
    result: Result<Delivered, String>,
}

/// A host that has the files: what the summary and the JSON report print.
struct Delivered {
    alias: String,
    ip: IpAddr,
    port: u16,
    fingerprint: String,
}

/// Resolve one named host and send it the files. Runs as one job of a
/// fan-out: a host that is down or unknown fails here, on its own, while the
/// other jobs keep going.
async fn send_to_peer(
    me: &DeviceInfo,
    uploads: &[client::Upload],
    name: String,
    pin: Option<String>,
    retries: u32,
) -> HostOutcome {
    let result = async {
        let Some(peer) = hosts::peer(&name).await.map_err(|e| e.to_string())? else {
            // One unknown name must not cost the others their delivery.
            return Err(format!(
                "not in the hosts file — `zapsend trust {name} --ip <addr>` first"
            ));
        };
        // A fingerprint-less entry that now answers over HTTPS is not the
        // plain peer it was trusted as: refuse it the way the single-send
        // path does, instead of letting the unpinned client talk to it.
        require_verified(
            &peer,
            "re-trust it first: `zapsend trust NAME --ip ADDR`, or pass --fingerprint",
        )
        .map_err(|e| format!("{e:#}"))?;
        eprintln!("→ {name} ({}:{})", peer.ip, peer.info.port);
        client::send_files(&peer, me, uploads, pin.as_deref(), retries)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Delivered {
            alias: peer.info.alias.clone(),
            ip: peer.ip,
            port: peer.info.port,
            fingerprint: peer.info.fingerprint.clone(),
        })
    }
    .await;
    HostOutcome { name, result }
}

/// One command, many peers, one summary. The sends run in parallel, bounded
/// to `FANOUT_CONCURRENCY` at a time: a sequential fan-out costs the sum of
/// every host (a 1 GiB push to three hosts measured 28 s against 9 s for one
/// host alone), while parallel sends overlap the per-host TLS, hashing and
/// transfer. One host failing still does not cost the others their delivery,
/// and the summary still names every host in the order given, with a
/// non-zero exit when any of them failed.
async fn fan_out(
    alias: &str,
    port: u16,
    files: Vec<PathBuf>,
    names: &[String],
    pin: Option<String>,
    retries: u32,
) -> Result<()> {
    let uploads = collect_uploads(&files)?;
    let bytes: u64 = uploads
        .iter()
        .filter_map(|u| std::fs::metadata(&u.path).ok())
        .map(|m| m.len())
        .sum();
    let stack = local_only(alias, port)?;
    let me = Arc::new(stack.me.clone());
    let uploads = Arc::new(uploads);

    eprintln!(
        "sending {} file(s), {} to {} peer(s)",
        uploads.len(),
        human_bytes(bytes),
        names.len()
    );

    // Hash once up front: without this, parallel sends all miss the hash
    // cache at once and each pays a full hashing pass over the same bytes.
    // A failure here is not fatal — each send hashes for itself instead.
    let _ = client::warm_hash_cache(&uploads).await;

    // Each host keeps its own remembered PIN; --pin overrides all of them.
    let jobs: Vec<(String, Option<String>)> = names
        .iter()
        .map(|name| (name.clone(), hosts::resolve_pin(pin.clone(), Some(name))))
        .collect();
    let outcomes = run_bounded(jobs, FANOUT_CONCURRENCY, {
        let me = me.clone();
        let uploads = uploads.clone();
        move |(name, pin)| {
            let me = me.clone();
            let uploads = uploads.clone();
            async move { send_to_peer(&me, &uploads, name, pin, retries).await }
        }
    })
    .await?;

    let mut report = Vec::new();
    let mut failed = 0usize;
    let mut delivered = 0u64;
    for outcome in outcomes {
        match outcome.result {
            Ok(d) => {
                delivered += bytes;
                eprintln!("✓ {}", outcome.name);
                report.push(serde_json::json!({
                    "name": outcome.name,
                    "ok": true,
                    "alias": d.alias,
                    "ip": d.ip.to_string(),
                    "port": d.port,
                    "fingerprint": d.fingerprint,
                    "bytes": bytes,
                }));
            }
            Err(e) => {
                failed += 1;
                eprintln!("✗ {}: {e}", outcome.name);
                report.push(serde_json::json!({
                    "name": outcome.name,
                    "ok": false,
                    "error": e,
                }));
            }
        }
    }

    if json_mode() {
        println!(
            "{}",
            serde_json::json!({
                "ok": failed == 0,
                "command": "send",
                "peers": report,
                "count": names.len(),
                "failed": failed,
                "bytes": bytes,
                "delivered": delivered,
            })
        );
    } else {
        println!(
            "{} of {} peer(s), {} delivered",
            names.len() - failed,
            names.len(),
            human_bytes(delivered)
        );
    }
    if failed > 0 {
        bail!("{failed} of {} peer(s) failed", names.len());
    }
    Ok(())
}

/// `zapsend trust` is one deliberate step: reach the machine, take its
/// fingerprint (or check the one you were given), store all of it under a name.
async fn trust(
    name: &str,
    raw_ip: &str,
    fingerprint: Option<String>,
    pin: Option<String>,
    plain: bool,
) -> Result<()> {
    if plain && fingerprint.is_some() {
        bail!("--plain and --fingerprint contradict each other: a plain-HTTP peer has no certificate to pin");
    }
    let (addr, port) = parse_target(raw_ip)?;
    let probe = Peer {
        info: DeviceInfo {
            zapsend_resume: false,
            alias: name.to_string(),
            version: PROTOCOL_VERSION.to_string(),
            device_model: None,
            device_type: None,
            // Deliberately unset: we fetch first and compare ourselves, so a
            // wrong fingerprint reads as a mismatch instead of a TLS error.
            fingerprint: String::new(),
            port,
            protocol: "https".to_string(),
            download: false,
        },
        ip: addr,
    };

    // A plain peer announces no fingerprint, so there is nothing to pin:
    // `stored` is None for one, and the entry is usable because `peer_for`
    // re-asks the machine for its scheme on every use.
    let stored: Option<String> = match (fingerprint, client::fetch_info(&probe).await) {
        (Some(given), Ok(info)) => {
            if info.protocol.eq_ignore_ascii_case("http") {
                bail!("{raw_ip} serves plain HTTP — a --fingerprint is meaningless for it; drop the flag and pass --plain instead (private network only)");
            }
            if !info.fingerprint.eq_ignore_ascii_case(&given) {
                bail!(
                    "fingerprint mismatch — you gave {}, {} announced {}\n  nothing was saved",
                    identity::short_fingerprint(&given),
                    raw_ip,
                    info.fingerprint
                );
            }
            eprintln!("✓ fingerprint matches what {raw_ip} announced");
            Some(given)
        }
        (Some(given), Err(e)) => {
            eprintln!("! {raw_ip} did not answer: {e:#}");
            eprintln!("  saving the fingerprint you gave, without checking it against the machine");
            Some(given)
        }
        (None, Ok(info)) => {
            if info.protocol.eq_ignore_ascii_case("http") {
                if !plain {
                    bail!("{raw_ip} serves plain HTTP and announces no fingerprint — pass --plain to trust it anyway (private network only, never on the open internet)");
                }
                eprintln!("! {raw_ip} serves plain HTTP — there is no certificate to pin, traffic is unencrypted");
                eprintln!("  stored without a fingerprint; only use this on a private network");
                None
            } else if plain {
                // --plain asserts the peer is plain. A peer that answers over
                // HTTPS is not, and trusting it as plain would silently
                // downgrade every later send to unencrypted traffic.
                bail!("{raw_ip} serves HTTPS — --plain would downgrade it; drop --plain and trust it normally");
            } else if info.fingerprint.len() != 64 {
                bail!("{raw_ip} did not announce a fingerprint, nothing to pin");
            } else {
                eprintln!("! trusting {raw_ip} on first sight — compare this with the fingerprint");
                eprintln!("  that machine printed when it started:");
                eprintln!("    {}", info.fingerprint);
                Some(info.fingerprint)
            }
        }
        (None, Err(e)) => {
            bail!("cannot reach {raw_ip}: {e:#}\n  pass --fingerprint to save it without a check")
        }
    };

    let path = hosts::remember(name, &addr.to_string(), port, stored.clone(), pin)?;
    if json_mode() {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "trust",
                "name": name,
                "ip": addr.to_string(),
                "port": port,
                "plain": plain,
                "fingerprint": stored,
                "config": path.display().to_string(),
            })
        );
    } else if stored.is_none() {
        // Only a --plain trust stores without a fingerprint.
        println!("✓ {name} → {addr}:{port}, plain HTTP (no certificate to pin)");
        println!("  saved in {}", path.display());
        println!("  now: zapsend send <file> --to {name} --plain");
    } else {
        println!(
            "✓ {name} → {addr}:{port}, pinned to {}",
            identity::short_fingerprint(stored.as_deref().unwrap_or_default())
        );
        println!("  saved in {}", path.display());
        println!("  now: zapsend send <file> --to {name}");
    }
    Ok(())
}

fn print_hosts() -> Result<()> {
    let map = hosts::load()?;
    let path = hosts::path()?;
    if json_mode() {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "hosts",
                "config": path.display().to_string(),
                "hosts": map.iter().map(|(name, e)| serde_json::json!({
                    "name": name,
                    "ip": e.ip,
                    "port": e.port,
                    "fingerprint": e.fingerprint,
                    "pinSet": e.pin.is_some(),
                })).collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }
    if map.is_empty() {
        println!("no remembered machines");
        println!("  add one: zapsend trust gpu-box --ip 100.64.0.7 --pin 4021");
        println!("  file:    {}", path.display());
        return Ok(());
    }

    println!("{:<20} {:<26} {:<5} {}", "NAME", "ADDRESS", "PIN", "FINGERPRINT");
    for (name, entry) in &map {
        println!(
            "{:<20} {:<26} {:<5} {}",
            name,
            format!("{}:{}", entry.ip, entry.port),
            if entry.pin.is_some() { "yes" } else { "-" },
            entry
                .fingerprint
                .as_deref()
                .map(identity::short_fingerprint)
                .unwrap_or("none")
        );
    }
    println!();
    println!("  {}", path.display());
    Ok(())
}

fn forget(name: &str) -> Result<()> {
    if hosts::forget(name)? {
        if json_mode() {
            println!(
                "{}",
                serde_json::json!({"ok": true, "command": "forget", "name": name})
            );
        } else {
            println!("✓ forgot {name}");
        }
        Ok(())
    } else {
        bail!("no machine named \"{name}\" — see `zapsend hosts`")
    }
}

/// A `--to <name>` that is in the hosts file resolves before discovery: no
/// multicast, no scan, and no flags needed. That is what makes an unattended
/// send possible.
pub(crate) async fn peer_from_hosts(
    alias: &str,
    port: u16,
    to: &Option<String>,
) -> Result<Option<(Stack, Peer)>> {
    let Some(name) = to.as_deref() else {
        return Ok(None);
    };
    let Some(peer) = hosts::peer(name).await? else {
        return Ok(None);
    };
    let stack = local_only(alias, port)?;
    Ok(Some((stack, peer)))
}

pub(crate) fn resolve_target(peers: &[Peer], target: Option<&str>) -> Result<Option<Peer>> {
    match target {
        Some(t) => {
            let needle = t.to_ascii_lowercase();
            let hit = peers.iter().find(|p| {
                p.info.alias.to_ascii_lowercase() == needle
                    || p.info.fingerprint.to_ascii_lowercase().starts_with(&needle)
                    || p.ip.to_string() == t
            });
            match hit {
                Some(p) => Ok(Some(p.clone())),
                None => bail!("no device matching \"{t}\""),
            }
        }
        None => match peers.len() {
            0 => Ok(None),
            1 => Ok(Some(peers[0].clone())),
            _ => {
                println!("multiple devices found — pick one with --to:");
                println!();
                print_peers(peers);
                bail!("ambiguous target");
            }
        },
    }
}

/// Six digits from an OS-random UUID. No new dependency: uuid v4 already
/// pulls entropy from the platform.
pub(crate) fn generate_pin() -> String {
    uuid::Uuid::new_v4()
        .as_bytes()
        .iter()
        .take(6)
        .map(|b| char::from(b'0' + (b % 10)))
        .collect()
}

async fn receive(
    alias: &str,
    port: u16,
    dir: PathBuf,
    share: Option<PathBuf>,
    pin: Option<String>,
    ask: bool,
    plain: bool,
) -> Result<()> {
    let pin = match pin {
        None => None,
        Some(p) if p.is_empty() => Some(generate_pin()),
        Some(p) => {
            if !p.chars().all(|c| c.is_ascii_digit()) {
                bail!("PIN must contain digits only, got \"{p}\"");
            }
            Some(p)
        }
    };

    if ask && !std::io::stdin().is_terminal() {
        bail!("--ask needs an interactive terminal; drop it when running under a service manager");
    }

    std::fs::create_dir_all(&dir).context("creating download dir")?;
    if let Some(shared) = share.as_deref() {
        if !shared.is_dir() {
            bail!("--share needs an existing directory, {} is not one", shared.display());
        }
        eprintln!(
            "! sharing {} through the Download API — anyone with the PIN (or anyone, if no PIN) can pull it",
            shared.display()
        );
    }

    let stack = start(
        alias,
        port,
        dir.clone(),
        share.clone(),
        pin.clone(),
        ask,
        ApiServer::Required,
        plain,
    )
    .await?;

    if json_mode() {
        // One line, then silence: a supervisor reads this and moves on.
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "receive",
                "alias": stack.me.alias,
                "port": port,
                "plain": plain,
                "protocol": stack.me.protocol,
                "fingerprint": stack.me.fingerprint,
                "dir": dir.display().to_string(),
                "share": share.as_ref().map(|s| s.display().to_string()),
                "download": stack.me.download,
                "pinRequired": pin.is_some(),
                "acceptsAutomatically": !ask,
            })
        );
    } else {
    banner();
    println!("  listening   :{port}");
    println!("  alias       {}", stack.me.alias);
    if plain {
        println!("  transport   plain HTTP — no TLS (private network only)");
        println!("  fingerprint (none — plain HTTP, nothing to pin)");
    } else {
        println!("  fingerprint {}", stack.me.fingerprint);
    }
    match pin {
        Some(p) => println!("  pin         {p}  (required for incoming transfers)"),
        None => println!("  pin         none — anyone on this network can send to you"),
    }
    println!("  saving to   {}", dir.display());
    match share.as_deref() {
        Some(shared) => println!("  sharing     {} (Download API on)", shared.display()),
        None => println!("  sharing     off — pass --share DIR to let peers pull files"),
    }
    println!(
        "  mode        {}",
        if ask {
            "ask before accepting"
        } else {
            "accept automatically"
        }
    );
    println!();
    println!("  ctrl-c to stop");
    }

    loop {
        if let Some(sock) = stack.sock.as_ref() {
            let _ = discovery::announce(sock, &stack.me).await;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn refusal_names_the_address_and_all_three_fixes() {
        let msg = unverified_ip_refusal("192.168.1.42".parse().unwrap(), 53317, "send files to");
        assert!(msg.contains("192.168.1.42:53317"), "{msg}");
        assert!(msg.contains("send files to"), "{msg}");
        assert!(msg.contains("zapsend trust NAME --ip 192.168.1.42:53317"), "{msg}");
        assert!(msg.contains("--fingerprint"), "{msg}");
        assert!(msg.contains("--tofu"), "{msg}");
    }

    #[tokio::test]
    async fn run_bounded_runs_jobs_in_parallel() {
        // Three 200 ms jobs under a limit of four finish in one wave, not
        // three: this is the property the parallel fan-out rests on. The
        // 500 ms bound leaves room for a loaded machine; sequential would
        // need 600 ms.
        let start = std::time::Instant::now();
        let out = run_bounded(vec![1, 2, 3], 4, |_| async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            1
        })
        .await
        .unwrap();
        assert_eq!(out, vec![1, 1, 1]);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "3x200ms jobs with limit 4 took {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn run_bounded_respects_the_limit() {
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let out = run_bounded(vec![0; 6], 2, {
            let live = live.clone();
            let peak = peak.clone();
            move |_| {
                let live = live.clone();
                let peak = peak.clone();
                async move {
                    let n = live.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(n, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    live.fetch_sub(1, Ordering::SeqCst);
                    true
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(out.len(), 6);
        assert_eq!(
            peak.load(Ordering::SeqCst),
            2,
            "limit 2 must never run 3 jobs at once"
        );
    }

    #[tokio::test]
    async fn run_bounded_keeps_order_and_isolates_failures() {
        let ran = Arc::new(AtomicUsize::new(0));
        let out = run_bounded(vec![0, 1, 2], 3, {
            let ran = ran.clone();
            move |i| {
                let ran = ran.clone();
                async move {
                    ran.fetch_add(1, Ordering::SeqCst);
                    if i == 1 {
                        Err("boom")
                    } else {
                        Ok(i)
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            ran.load(Ordering::SeqCst),
            3,
            "a failing job must not cancel the others"
        );
        assert_eq!(out, vec![Ok(0), Err("boom"), Ok(2)]);
    }
}

mod cli;
mod client;
mod daemon;
mod discovery;
mod doctor;
mod hosts;
mod identity;
mod protocol;
mod pull;
mod server;
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
pub(crate) async fn start(
    alias: &str,
    port: u16,
    download_dir: PathBuf,
    // Directory to offer through the Download API, if any.
    share: Option<PathBuf>,
    pin: Option<String>,
    ask: bool,
    api: ApiServer,
) -> Result<Stack> {
    let (identity, mut me) = identity::load_or_create(alias, port)?;
    let registry = discovery::new_registry();

    let tls = RustlsConfig::from_pem(
        identity.cert_pem.into_bytes(),
        identity.key_pem.into_bytes(),
    )
    .await
    .context("building TLS config")?;

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
        tokio::spawn(async move {
            if let Err(e) = axum_server::from_tcp_rustls(listener, tls)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
            {
                eprintln!("! API server stopped: {e}");
            }
        });
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
    JSON_MODE.store(cli.json, std::sync::atomic::Ordering::Relaxed);
    let alias = cli.alias.clone();
    let port = cli.port;

    match cli.command {
        Command::Trust {
            name,
            ip,
            fingerprint,
            pin,
        } => trust(&name, &ip, fingerprint, pin).await,
        Command::Hosts => print_hosts(),
        Command::Forget { name } => forget(&name),
        Command::Discover { wait } => discover(&alias, port, wait).await,
        Command::Send {
            files,
            to,
            ip,
            fingerprint,
            pin,
            scan,
            retry,
        } => {
            send(
                &alias,
                port,
                files,
                to,
                ip,
                fingerprint,
                pin,
                scan,
                retry,
            )
            .await
        }
        Command::Receive {
            dir,
            pin,
            ask,
            share,
        } => receive(&alias, port, dir, share, pin, ask).await,
        Command::Pull {
            to,
            ip,
            fingerprint,
            pin,
            dir,
            file,
            scan,
            retry,
        } => {
            pull::run(
                &alias,
                port,
                pull::Options {
                    to,
                    ip,
                    fingerprint,
                    pin,
                    dir,
                    file,
                    scan,
                    retry,
                },
            )
            .await
        }
        Command::Doctor {
            to,
            ip,
            scan,
            dir,
        } => doctor::run(&alias, port, doctor::Options { to, ip, scan, dir }).await,
        Command::Daemon {
            dir,
            to,
            ip,
            fingerprint,
            pin,
            interval,
            settle,
            keep,
            scan,
        } => {
            daemon::run(
                &alias,
                port,
                daemon::Options {
                    dir,
                    to,
                    ip,
                    fingerprint,
                    pin,
                    interval,
                    settle,
                    keep,
                    scan,
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
            out.push(client::Upload { path, name: remote });
        }
    }
    Ok(())
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
    pin: Option<String>,
    scan_secs: u64,
    retries: u32,
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
            let (addr, target_port) = parse_target(&raw)?;
            let stack = local_only(alias, port)?;
            let mut peer = Peer {
                info: DeviceInfo {
                    zapsend_resume: false,
                    alias: raw.clone(),
                    version: PROTOCOL_VERSION.to_string(),
                    device_model: None,
                    device_type: None,
                    fingerprint: fingerprint.clone().unwrap_or_default(),
                    port: target_port,
                    protocol: "https".to_string(),
                    download: false,
                },
                ip: addr,
            };
            // Ask who is actually there before sending: that is how we learn
            // whether it can resume a broken upload, and which scheme it serves.
            // A peer that does not answer /info is not a reason to give up.
            if let Ok(info) = client::fetch_info(&peer).await {
                peer.info.zapsend_resume = info.zapsend_resume;
                peer.info.download = info.download;
                peer.info.protocol = info.protocol;
                peer.info.port = info.port;
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
    if peer.info.fingerprint.is_empty() {
        eprintln!("! unverified peer: pass --fingerprint to pin its certificate");
    } else {
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


/// One command, many peers, one summary. Sequential on purpose: one uplink
/// shared by parallel uploads is slower for everybody, and a fleet push is
/// usually logs and artifacts, not a race.
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
    let mut report = Vec::new();
    let mut failed = 0usize;
    let mut delivered = 0u64;

    eprintln!(
        "sending {} file(s), {} to {} peer(s)",
        uploads.len(),
        human_bytes(bytes),
        names.len()
    );

    for name in names {
        let Some(peer) = hosts::peer(name).await? else {
            // One unknown name must not cost the others their delivery.
            eprintln!("✗ {name}: not in the hosts file — `zapsend trust {name} --ip <addr>` first");
            report.push(serde_json::json!({
                "name": name,
                "ok": false,
                "error": "not in the hosts file",
            }));
            failed += 1;
            continue;
        };
        // Each host keeps its own remembered PIN; --pin overrides all of them.
        let pin = hosts::resolve_pin(pin.clone(), Some(name));
        eprintln!("→ {name} ({}:{})", peer.ip, peer.info.port);
        match client::send_files(&peer, &stack.me, &uploads, pin.as_deref(), retries).await {
            Ok(()) => {
                delivered += bytes;
                eprintln!("✓ {name}");
                report.push(serde_json::json!({
                    "name": name,
                    "ok": true,
                    "alias": peer.info.alias,
                    "ip": peer.ip.to_string(),
                    "port": peer.info.port,
                    "fingerprint": peer.info.fingerprint,
                    "bytes": bytes,
                }));
            }
            Err(e) => {
                failed += 1;
                eprintln!("✗ {name}: {e}");
                report.push(serde_json::json!({
                    "name": name,
                    "ok": false,
                    "error": e.to_string(),
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
) -> Result<()> {
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

    let stored = match (fingerprint, client::fetch_info(&probe).await) {
        (Some(given), Ok(info)) => {
            if !info.fingerprint.eq_ignore_ascii_case(&given) {
                bail!(
                    "fingerprint mismatch — you gave {}, {} announced {}\n  nothing was saved",
                    identity::short_fingerprint(&given),
                    raw_ip,
                    info.fingerprint
                );
            }
            eprintln!("✓ fingerprint matches what {raw_ip} announced");
            given
        }
        (Some(given), Err(e)) => {
            eprintln!("! {raw_ip} did not answer: {e:#}");
            eprintln!("  saving the fingerprint you gave, without checking it against the machine");
            given
        }
        (None, Ok(info)) => {
            if info.fingerprint.len() != 64 {
                bail!("{raw_ip} did not announce a fingerprint, nothing to pin");
            }
            eprintln!("! trusting {raw_ip} on first sight — compare this with the fingerprint");
            eprintln!("  that machine printed when it started:");
            eprintln!("    {}", info.fingerprint);
            info.fingerprint
        }
        (None, Err(e)) => {
            bail!("cannot reach {raw_ip}: {e:#}\n  pass --fingerprint to save it without a check")
        }
    };

    let path = hosts::remember(name, &addr.to_string(), port, Some(stored.clone()), pin)?;
    if json_mode() {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "trust",
                "name": name,
                "ip": addr.to_string(),
                "port": port,
                "fingerprint": stored,
                "config": path.display().to_string(),
            })
        );
    } else {
        println!(
            "✓ {name} → {addr}:{port}, pinned to {}",
            identity::short_fingerprint(&stored)
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
    println!("  fingerprint {}", stack.me.fingerprint);
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

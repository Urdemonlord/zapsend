mod cli;
mod client;
mod discovery;
mod identity;
mod protocol;
mod server;
mod verbose;

use crate::cli::{Cli, Command};
use crate::protocol::{DeviceInfo, Peer, DEFAULT_PORT, PROTOCOL_VERSION};
use anyhow::{bail, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use std::collections::HashMap;
use std::io::IsTerminal;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Everything a running zapsend instance needs: identity, HTTP server, discovery.
struct Stack {
    me: DeviceInfo,
    registry: discovery::Registry,
    /// `None` when we skip networking (sending straight to an --ip target).
    sock: Option<Arc<tokio::net::UdpSocket>>,
}

/// Identity only — no listeners. Used by `send --ip`, which does not need to
/// be discoverable itself and therefore never fights another instance for a port.
fn local_only(alias: &str, port: u16) -> Result<Stack> {
    let (_, me) = identity::load_or_create(alias, port)?;
    Ok(Stack {
        me,
        registry: discovery::new_registry(),
        sock: None,
    })
}

/// Full stack: HTTPS API server + multicast discovery.
///
/// `serve_api: false` is for `send`/`discover`, which need an identity and
/// discovery but never serve a file. They used to die on a busy port, which
/// made `send` unusable while a `receive` instance was running.
async fn start(
    alias: &str,
    port: u16,
    download_dir: PathBuf,
    pin: Option<String>,
    ask: bool,
    serve_api: bool,
) -> Result<Stack> {
    let (identity, me) = identity::load_or_create(alias, port)?;
    let registry = discovery::new_registry();

    let state = Arc::new(server::AppState {
        me: me.clone(),
        registry: registry.clone(),
        download_dir,
        sessions: Mutex::new(HashMap::new()),
        pin: server::PinState::new(pin),
        ask,
    });

    let tls = RustlsConfig::from_pem(
        identity.cert_pem.into_bytes(),
        identity.key_pem.into_bytes(),
    )
    .await
    .context("building TLS config")?;

    let app = server::router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    // Bind before spawning so a taken port fails loudly here instead of
    // silently leaving a receiver that claims to listen but never does.
    // A sender/discoverer has nothing to serve, so a busy port there is not
    // fatal: warn and carry on with discovery only.
    match std::net::TcpListener::bind(addr) {
        Ok(listener) => {
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
        Err(e) if serve_api => {
            return Err(anyhow::Error::new(e).context(format!(
                "cannot bind the API server to :{port} — another instance already holds it"
            )));
        }
        Err(_) => {
            eprintln!("! port :{port} is in use — continuing without the API server");
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
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 refuses to guess a crypto backend when more than one is
    // compiled in (axum-server and reqwest pull different defaults).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    verbose::set(cli.verbose);
    let alias = cli.alias.clone();
    let port = cli.port;

    match cli.command {
        Command::Discover { wait } => discover(&alias, port, wait).await,
        Command::Send {
            files,
            to,
            ip,
            fingerprint,
            pin,
            scan,
        } => send(&alias, port, files, to, ip, fingerprint, pin, scan).await,
        Command::Receive { dir, pin, ask } => receive(&alias, port, dir, pin, ask).await,
    }
}

/// Announce ourselves for `secs` seconds, then return everything we heard.
async fn scan(stack: &Stack, secs: u64) -> Vec<Peer> {
    let Some(sock) = stack.sock.as_ref() else {
        return Vec::new();
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        let _ = discovery::announce(sock, &stack.me).await;
        tokio::time::sleep(Duration::from_millis(800)).await;
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
fn banner() {
    let lines = [
        format!("zapsend {}", env!("CARGO_PKG_VERSION")),
        "headless file transfer, LocalSend protocol".to_string(),
    ];
    let inner = lines.iter().map(|l| l.len()).max().unwrap_or(0) + 2;
    let border = format!("  +{}+", "-".repeat(inner));

    println!("{border}");
    for line in &lines {
        println!("  | {:w$} |", line, w = inner - 2);
    }
    println!("{border}");
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
        false,
        false,
    )
    .await?;
    eprintln!("scanning for {wait}s…");
    let peers = scan(&stack, wait).await;
    print_peers(&peers);
    Ok(())
}

/// Accept `1.2.3.4` or `1.2.3.4:53400`.
fn parse_target(raw: &str) -> Result<(IpAddr, u16)> {
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
) -> Result<()> {
    // Straight-to-address sends need neither a server nor discovery, so they
    // work even while another instance owns the port.
    let (stack, peer) = match ip {
        Some(raw) => {
            let (addr, target_port) = parse_target(&raw)?;
            let stack = local_only(alias, port)?;
            let peer = Peer {
                info: DeviceInfo {
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
            (stack, peer)
        }
        None => {
            let stack = start(
                alias,
                port,
                PathBuf::from("./zapsend-received"),
                None,
                false,
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
    };

    let bytes: u64 = files
        .iter()
        .filter_map(|f| std::fs::metadata(f).ok())
        .map(|m| m.len())
        .sum();

    eprintln!(
        "sending {} file(s), {} to \"{}\" ({}:{})",
        files.len(),
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

    client::send_files(&peer, &stack.me, &files, pin.as_deref()).await?;
    println!("✓ done");
    Ok(())
}

fn resolve_target(peers: &[Peer], target: Option<&str>) -> Result<Option<Peer>> {
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
fn generate_pin() -> String {
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
    let stack = start(alias, port, dir.clone(), pin.clone(), ask, true).await?;

    banner();
    println!("  listening   :{port}");
    println!("  alias       {}", stack.me.alias);
    println!("  fingerprint {}", stack.me.fingerprint);
    match pin {
        Some(p) => println!("  pin         {p}  (required for incoming transfers)"),
        None => println!("  pin         none — anyone on this network can send to you"),
    }
    println!("  saving to   {}", dir.display());
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

    loop {
        if let Some(sock) = stack.sock.as_ref() {
            let _ = discovery::announce(sock, &stack.me).await;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

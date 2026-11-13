mod cli;
mod client;
mod discovery;
mod identity;
mod protocol;
mod server;

use crate::cli::{Cli, Command};
use crate::protocol::{DeviceInfo, Peer, DEFAULT_PORT, PROTOCOL_VERSION};
use anyhow::{bail, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Everything a running zap instance needs: identity, HTTP server, discovery.
struct Stack {
    me: DeviceInfo,
    registry: discovery::Registry,
    sock: Arc<tokio::net::UdpSocket>,
}

async fn start(alias: &str, download_dir: PathBuf) -> Result<Stack> {
    let (identity, me) = identity::load_or_create(alias)?;
    let registry = discovery::new_registry();

    let state = Arc::new(server::AppState {
        me: me.clone(),
        registry: registry.clone(),
        download_dir,
        sessions: Mutex::new(HashMap::new()),
    });

    let tls = RustlsConfig::from_pem(
        identity.cert_pem.into_bytes(),
        identity.key_pem.into_bytes(),
    )
    .await
    .context("building TLS config")?;

    let app = server::router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT));
    tokio::spawn(async move {
        if let Err(e) = axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
        {
            eprintln!("! https server stopped: {e}");
        }
    });

    let sock = Arc::new(discovery::bind_multicast()?);
    tokio::spawn(discovery::listen(
        sock.clone(),
        registry.clone(),
        me.fingerprint.clone(),
    ));

    Ok(Stack { me, registry, sock })
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 refuses to guess a crypto backend when more than one is
    // compiled in (axum-server and reqwest pull different defaults).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let alias = cli.alias.clone();

    match cli.command {
        Command::Discover { wait } => discover(&alias, wait).await,
        Command::Send { file, to, ip, scan } => send(&alias, file, to, ip, scan).await,
        Command::Receive { dir } => receive(&alias, dir).await,
    }
}

/// Announce ourselves for `secs` seconds, then return everything we heard.
async fn scan(stack: &Stack, secs: u64) -> Vec<Peer> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        let _ = discovery::announce(&stack.sock, &stack.me).await;
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
        println!("  · try the fallback:  zap send <file> --ip <address>");
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

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

async fn discover(alias: &str, wait: u64) -> Result<()> {
    let stack = start(alias, PathBuf::from("./zap-received")).await?;
    eprintln!("scanning for {wait}s…");
    let peers = scan(&stack, wait).await;
    print_peers(&peers);
    Ok(())
}

async fn send(
    alias: &str,
    file: PathBuf,
    to: Option<String>,
    ip: Option<String>,
    scan_secs: u64,
) -> Result<()> {
    let stack = start(alias, PathBuf::from("./zap-received")).await?;

    let peer = match ip {
        Some(raw) => {
            let addr: IpAddr = raw.parse().with_context(|| format!("invalid --ip {raw}"))?;
            Peer {
                info: DeviceInfo {
                    alias: raw.clone(),
                    version: PROTOCOL_VERSION.to_string(),
                    device_model: None,
                    device_type: None,
                    fingerprint: String::new(),
                    port: DEFAULT_PORT,
                    protocol: "https".to_string(),
                    download: false,
                },
                ip: addr,
            }
        }
        None => {
            eprintln!("scanning for {scan_secs}s…");
            let peers = scan(&stack, scan_secs).await;
            match resolve_target(&peers, to.as_deref())? {
                Some(p) => p,
                None => {
                    print_peers(&peers);
                    bail!("no device selected");
                }
            }
        }
    };

    eprintln!(
        "sending {} to \"{}\" ({})",
        file.display(),
        peer.info.alias,
        peer.ip
    );

    client::send_file(&peer, &stack.me, &file).await?;
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

async fn receive(alias: &str, dir: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&dir).context("creating download dir")?;
    let stack = start(alias, dir.clone()).await?;

    println!("zap is listening on :{DEFAULT_PORT}");
    println!("  alias       {}", stack.me.alias);
    println!("  fingerprint {}", stack.me.fingerprint);
    println!("  saving to   {}", dir.display());
    println!();
    println!("ctrl-c to stop");

    loop {
        let _ = discovery::announce(&stack.sock, &stack.me).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

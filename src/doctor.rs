//! `zapsend doctor`: explain why discovery or sending is not working.
//!
//! Every check prints what it actually observed, not a green tick over a guess.
//! The order matters: address, then port, then multicast, then sweep, because
//! each one is a precondition for the next and the first failure is the answer.

use crate::client;
use crate::discovery;
use crate::protocol::Peer;
use crate::Stack;
use anyhow::{bail, Result};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// `--json` means stdout is one object; the human report moves to stderr so it
/// still lands in the log instead of being thrown away.
macro_rules! say {
    ($($t:tt)*) => {
        if crate::json_mode() {
            eprintln!($($t)*)
        } else {
            println!($($t)*)
        }
    };
}



pub struct Options {
    /// Device to test reachability against (alias, fingerprint prefix, or IP).
    pub to: Option<String>,
    /// Treat this as an address instead of looking the device up.
    pub ip: Option<String>,
    /// Seconds to listen for multicast answers.
    pub scan: u64,
    /// Directory a receiver would write into.
    pub dir: PathBuf,
}

pub async fn run(alias: &str, port: u16, opts: Options) -> Result<()> {
    let mut problems: Vec<String> = Vec::new();

    say!("zapsend doctor");
    say!();

    // Probe the port *before* starting anything: the stack below binds it, and a
    // probe afterwards reports our own listener as a stranger's.
    let port_taken = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).err();

    // The stack is started with `Want`: a busy port is a finding, not a reason
    // to abort the diagnosis.
    let stack = crate::start(
        alias,
        port,
        opts.dir.clone(),
        None,
        None,
        false,
        crate::ApiServer::Want,
    )
    .await?;

    say!("  version     {}", env!("CARGO_PKG_VERSION"));
    say!(
        "  device      \"{}\" ({})",
        stack.me.alias,
        stack.me.device_type.as_deref().unwrap_or("headless")
    );
    say!(
        "  fingerprint {}",
        crate::identity::short_fingerprint(&stack.me.fingerprint)
    );
    if stack.me.port == port {
        say!("  api port    {port}");
    } else {
        say!("  api port    {} (fell back from {port})", stack.me.port);
    }

    // Naming a device means discovery is not the thing being tested: a quiet
    // multicast bus is expected on a VPN or across subnets, and reporting it as
    // a failure would fail a perfectly good setup.
    let named = opts.to.is_some() || opts.ip.is_some();

    // 1. Addresses. Without one there is nothing to announce and nothing to
    //    sweep, and every later failure is a symptom of this.
    let addrs = local_addrs().await;
    if addrs.is_empty() {
        problems.push("no IPv4 address on any interface".into());
        say!("  ✗ address   none — is the machine connected to a network?");
    } else {
        say!("  ✓ address   {}", addrs.join(", "));
        if addrs.iter().any(|a| a.starts_with("10.42.")) {
            say!("    ! 10.42.x.x looks like Docker — peers cannot reach that from the LAN");
        }
    }

    // 2. Was the port free when we looked?
    match port_taken {
        None => say!("  ✓ port      :{port} is free"),
        Some(e) => {
            problems.push(format!("port :{port} is already in use"));
            say!("  ✗ port      :{port} is taken ({e})");
            say!("              `receive` refuses to start; `send`/`discover` fall back to a random port");
            say!("              on Windows: Get-Process zapsend | Stop-Process -Force");
        }
    }

    // 3. Download dir.
    match std::fs::create_dir_all(&opts.dir) {
        Ok(()) => {
            let probe = opts.dir.join(".zapsend-write-test");
            match std::fs::write(&probe, b"ok") {
                Ok(()) => {
                    let _ = std::fs::remove_file(&probe);
                    say!("  ✓ download  {} (writable)", opts.dir.display());
                }
                Err(e) => {
                    problems.push(format!("cannot write to {}", opts.dir.display()));
                    say!("  ✗ download  {} is not writable: {e}", opts.dir.display());
                }
            }
        }
        Err(e) => {
            problems.push(format!("cannot create {}", opts.dir.display()));
            say!("  ✗ download  cannot create {}: {e}", opts.dir.display());
        }
    }

    // 4. Multicast: announce, then count who answered.
    if let Some(sock) = stack.sock.as_ref() {
        let _ = discovery::announce(sock, &stack.me).await;
    }
    let started = Instant::now();
    tokio::time::sleep(Duration::from_secs(opts.scan)).await;
    let peers = snapshot(&stack);
    if peers.is_empty() {
        if !named {
            problems.push("no device answered discovery".into());
        }
        say!(
            "  ! multicast no answers in {}s",
            started.elapsed().as_secs()
        );
        say!("              common causes: firewall, VPN, Hyper-V/WSL adapter,");
        say!("              phone hotspot isolating clients, or the peer is not running");
    } else {
        say!("  ✓ multicast {} device(s) answered", peers.len());
        for p in &peers {
            say!(
                "              \"{}\" {} {}:{}",
                p.info.alias, p.info.protocol, p.ip, p.info.port
            );
        }
    }

    // 5. Sweep: the fallback that saves a tethered laptop, since a hotspot often
    //    isolates multicast clients from each other.
    if peers.is_empty() {
        match discovery::sweep(&stack.registry, &stack.me, true).await {
            Ok(n) if n > 0 => {
                say!("  ✓ sweep     {n} device(s) answered unicast on this /24");
                for p in snapshot(&stack) {
                    say!("              \"{}\" {}:{}", p.info.alias, p.ip, p.info.port);
                }
            }
            Ok(_) => {
                if !named {
                    problems.push("no device answered discovery".into());
                }
                say!("  ! sweep     nothing on this /24 either");
            }
            Err(e) => {
                if !named {
                    problems.push("the /24 sweep failed".into());
                }
                say!("  ! sweep     failed: {e}");
            }
        }
    }

    // 6. Reachability of a specific device, if one was named.
    if let Some(target) = opts.to.as_ref().or(opts.ip.as_ref()) {
        let peer = resolve(&stack, &opts, target).await?;
        match client::fetch_info(&peer).await {
            Ok(info) => {
                say!(
                    "  ✓ peer      \"{}\" {}:{} over {} (LocalSend {})",
                    info.alias, peer.ip, info.port, info.protocol, info.version
                );
                if info.fingerprint.eq_ignore_ascii_case(&peer.info.fingerprint) {
                    say!("              fingerprint matches what discovery announced");
                } else if !peer.info.fingerprint.is_empty() {
                    say!("              ! fingerprint differs from the announcement — pass --ip to skip discovery");
                }
                if info.download {
                    say!("              peer offers a download API");
                }
            }
            Err(e) => {
                problems.push(format!("cannot reach \"{target}\""));
                say!("  ✗ peer      {e}");
            }
        }
    }

    say!();
    if crate::json_mode() {
        println!(
            "{}",
            serde_json::json!({
                "ok": problems.is_empty(),
                "command": "doctor",
                "problems": problems,
            })
        );
    }

    if problems.is_empty() {
        say!("  no problems found");
        Ok(())
    } else {
        for p in &problems {
            say!("  problem: {p}");
        }
        bail!("{} problem(s) found", problems.len())
    }
}

fn snapshot(stack: &Stack) -> Vec<Peer> {
    let reg = stack.registry.lock().unwrap();
    let mut v = reg.values().cloned().collect::<Vec<_>>();
    v.sort_by(|a, b| a.info.alias.cmp(&b.info.alias));
    v
}

async fn resolve(stack: &Stack, opts: &Options, target: &str) -> Result<Peer> {
    if let Some(raw) = opts.ip.as_ref() {
        let (addr, port) = crate::parse_target(raw)?;
        return Ok(Peer {
            info: crate::protocol::DeviceInfo {
            zapsend_resume: false,
                alias: raw.clone(),
                version: crate::protocol::PROTOCOL_VERSION.to_string(),
                device_model: None,
                device_type: None,
                fingerprint: String::new(),
                port,
                protocol: "https".to_string(),
                download: false,
            },
            ip: addr,
        });
    }

    // A remembered machine is answered from the hosts file: doctor should test
    // the address you actually use, not whatever multicast happens to find.
    if let Some(map) = crate::hosts::load().ok() {
        if let Some(entry) = opts.to.as_deref().and_then(|t| map.get(t)) {
            return crate::hosts::peer_for(target, entry).await;
        }
    }

    let known = snapshot(stack);
    let peers = if known.is_empty() {
        crate::scan(stack, opts.scan).await
    } else {
        known
    };
    match crate::resolve_target(&peers, Some(target))? {
        Some(p) => Ok(p),
        None => bail!("no device matching \"{target}\" — try `zapsend discover`"),
    }
}

/// The address the routing table would use for a LAN destination — the one a

/// peer on the same network can actually reach. Loopback does not count.
async fn local_addrs() -> Vec<String> {
    match discovery::local_ipv4().await {
        Some(ip) => vec![format!("{ip} (default route)")],
        None => Vec::new(),
    }
}

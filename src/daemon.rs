//! `zapsend daemon`: watch a folder and push whatever appears in it.
//!
//! Polling, not inotify: one `read_dir` per tick is cheaper than a dependency,
//! and the stability check (size and mtime unchanged for a whole tick) is what
//! actually stops half-written downloads from being sent. A file dropped in by
//! a browser download or a copy is not readable-and-complete on first sight.

use crate::client;
use crate::protocol::Peer;
use crate::Stack;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub struct Options {
    pub dir: PathBuf,
    pub to: Option<String>,
    pub ip: Option<String>,
    pub fingerprint: Option<String>,
    pub pin: Option<String>,
    pub interval: u64,
    pub settle: Option<u64>,
    pub keep: bool,
    pub scan: u64,
}

/// Names that are still being written by whatever produced them. Skipped for
/// good, not just once: a `.part` file never turns into a `.part`-less name.
const NOISE: &[&str] = &[
    ".tmp",
    ".part",
    ".partial",
    ".crdownload",
    ".download",
    ".swp",
    ".filepart",
];

fn is_noise(name: &str) -> bool {
    if name.starts_with('.') || name.starts_with("~$") {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    NOISE.iter().any(|suffix| lower.ends_with(suffix))
}

/// What we compare between ticks. A directory is folded into one signature
/// (file count, total bytes, newest mtime) so a tree that is still being copied
/// into looks unstable, and so a tree that nobody has touched looks settled.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Sig {
    files: u64,
    bytes: u64,
    newest: u128,
}

fn nanos(t: std::io::Result<SystemTime>) -> u128 {
    t.ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn sig_of(path: &Path, depth: usize) -> Option<Sig> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.is_symlink() {
        // Never follow: a link to / would walk the whole disk, and a link loop
        // would never finish.
        return None;
    }
    if !meta.is_dir() {
        return Some(Sig {
            files: 1,
            bytes: meta.len(),
            newest: nanos(meta.modified()),
        });
    }
    if depth == 0 {
        return Some(Sig {
            files: 0,
            bytes: 0,
            newest: nanos(meta.modified()),
        });
    }
    let mut sig = Sig {
        files: 0,
        bytes: 0,
        newest: nanos(meta.modified()),
    };
    for entry in std::fs::read_dir(path).ok()?.flatten() {
        if let Some(inner) = sig_of(&entry.path(), depth - 1) {
            sig.files += inner.files;
            sig.bytes += inner.bytes;
            sig.newest = sig.newest.max(inner.newest);
        }
    }
    Some(sig)
}

fn listing(dir: &Path) -> Vec<(PathBuf, Sig)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| !is_noise(&e.file_name().to_string_lossy()))
        .filter_map(|e| {
            let path = e.path();
            sig_of(&path, 64).map(|sig| (path, sig))
        })
        .collect()
}

fn now_nanos() -> u128 {
    nanos(Ok(SystemTime::now()))
}

pub async fn run(alias: &str, port: u16, opts: Options) -> Result<()> {
    std::fs::create_dir_all(&opts.dir)?;
    let watch = std::fs::canonicalize(&opts.dir)?;
    let sent_dir = watch.join(".sent");
    let incoming = watch.join(".incoming");

    let stack = match &opts.ip {
        Some(_) => crate::local_only(alias, port)?,
        None => {
            crate::start(
                alias,
                port,
                incoming.clone(),
                None,
                None,
                false,
                crate::ApiServer::Want,
            )
            .await?
        }
    };

    // Announce continuously: without this the peer's device list never learns
    // we exist, and `--to` would have nothing to resolve.
    if let Some(sock) = stack.sock.clone() {
        let me = stack.me.clone();
        let registry = stack.registry.clone();
        tokio::spawn(async move {
            let mut tick = 0u32;
            loop {
                let _ = crate::discovery::announce(&sock, &me).await;
                if tick % 10 == 0 {
                    let _ = crate::discovery::sweep(&registry, &me, true).await;
                }
                tick = tick.wrapping_add(1);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    println!("  watching    {} (every {}s)", watch.display(), opts.interval);
    match &opts.ip {
        Some(raw) => println!("  target      {raw}"),
        None => println!(
            "  target      {}",
            opts.to.as_deref().unwrap_or("first device found")
        ),
    }
    if opts.keep {
        println!("  after send  leave files in place");
    } else {
        println!("  after send  move to {}", sent_dir.display());
    }
    if opts.ip.is_none() {
        println!("  incoming    {} (nothing is expected here)", incoming.display());
    }
    println!();
    println!("  ctrl-c to stop");

    // Two silent ticks are not enough to call a file finished: a slow copy can
    // pause between writes and we would ship a truncated file. Require the
    // whole tree to be untouched for a settle window instead.
    let settle = Duration::from_secs(
        opts.settle
            .unwrap_or((opts.interval.max(1) * 2).max(3)),
    );

    let mut seen: HashMap<PathBuf, Sig> = HashMap::new();
    // Same failure every tick is one line, not a wall of them.
    let mut last_error: HashMap<PathBuf, String> = HashMap::new();
    // Only used with --keep, and as a fallback when a move fails: anything in
    // here has been delivered already and must not be sent twice.
    let mut delivered: HashMap<PathBuf, Sig> = HashMap::new();
    let mut peer: Option<Peer> = None;

    loop {
        let current = listing(&watch);
        let present: Vec<PathBuf> = current.iter().map(|(p, _)| p.clone()).collect();
        seen.retain(|p, _| present.contains(p));
        delivered.retain(|p, _| present.contains(p));

        for (path, sig) in current {
            match seen.get(&path) {
                // Second sighting with an unchanged signature: it has settled.
                Some(prev) if *prev == sig => {}
                // First sighting, or still changing. Remember and wait a tick.
                _ => {
                    seen.insert(path, sig);
                    continue;
                }
            }
            if delivered.get(&path) == Some(&sig) {
                continue;
            }
            if now_nanos().saturating_sub(sig.newest) < settle.as_nanos() {
                continue;
            }

            let name = path
                .strip_prefix(&watch)
                .unwrap_or(&path)
                .display()
                .to_string();

            let target = match ensure_peer(&stack, &opts, &mut peer).await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("! {name}: {e}");
                    peer = None;
                    tokio::time::sleep(Duration::from_secs(opts.interval)).await;
                    continue;
                }
            };

            match send_one(&stack, &opts, &target, &path).await {
                Ok((files, bytes)) => {
                    let how = if opts.keep {
                        String::from("kept")
                    } else {
                        match move_to(&sent_dir, &path, &name) {
                            Ok(dest) => format!("→ {}", dest.display()),
                            Err(e) => {
                                eprintln!("! {name}: sent but could not move it: {e}");
                                String::from("kept")
                            }
                        }
                    };
                    delivered.insert(path.clone(), sig);
                    last_error.remove(&path);
                    println!(
                        "✓ {name} ({files} file(s), {}) → \"{}\" {how}",
                        crate::human_bytes(bytes),
                        target.info.alias
                    );
                }
                Err(e) => {
                    let msg = format!("{e}");
                    if last_error.get(&path).map(|s| s.as_str()) != Some(msg.as_str()) {
                        eprintln!("! {name}: {msg}");
                        last_error.insert(path.clone(), msg);
                    }
                    // The address may have changed (DHCP, hotspot re-join), so
                    // throw away what we resolved and look again next tick.
                    peer = None;
                    tokio::time::sleep(Duration::from_secs(opts.interval)).await;
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(opts.interval.max(1))).await;
    }
}

async fn send_one(stack: &Stack, opts: &Options, peer: &Peer, path: &Path) -> Result<(usize, u64)> {
    let uploads = crate::collect_uploads(std::slice::from_ref(&path.to_path_buf()))?;
    let bytes: u64 = uploads
        .iter()
        .filter_map(|u| std::fs::metadata(&u.path).ok())
        .map(|m| m.len())
        .sum();
    client::send_files(peer, &stack.me, &uploads, opts.pin.as_deref()).await?;
    Ok((uploads.len(), bytes))
}

/// Resolve the target once and keep it: discovery is a 4 second round trip and
/// the daemon may be pushing several files in a row.
async fn ensure_peer(stack: &Stack, opts: &Options, cached: &mut Option<Peer>) -> Result<Peer> {
    if let Some(peer) = cached.as_ref() {
        return Ok(peer.clone());
    }

    let peer = match &opts.ip {
        Some(raw) => {
            let (addr, target_port) = crate::parse_target(raw)?;
            Peer {
                info: crate::protocol::DeviceInfo {
                    alias: raw.clone(),
                    version: crate::protocol::PROTOCOL_VERSION.to_string(),
                    device_model: None,
                    device_type: None,
                    fingerprint: opts.fingerprint.clone().unwrap_or_default(),
                    port: target_port,
                    protocol: "https".to_string(),
                    download: false,
                },
                ip: addr,
            }
        }
        None => {
            // Cheap path first: the announce loop may already have filled the
            // registry, in which case there is nothing to wait for.
            let known = {
                let reg = stack.registry.lock().unwrap();
                let mut v = reg.values().cloned().collect::<Vec<_>>();
                v.sort_by(|a, b| a.info.alias.cmp(&b.info.alias));
                v
            };
            let peers = if known.is_empty() {
                crate::scan(stack, opts.scan).await
            } else {
                known
            };
            let found = crate::resolve_target(&peers, opts.to.as_deref())?;
            match found {
                Some(p) => p,
                None => bail!("no device found — is the other side running LocalSend?"),
            }
        }
    };

    if let Some(expected) = opts.fingerprint.as_deref() {
        if !peer.info.fingerprint.eq_ignore_ascii_case(expected) {
            bail!(
                "fingerprint mismatch: pinned {}, found {}",
                expected,
                peer.info.fingerprint
            );
        }
    }

    if peer.info.fingerprint.is_empty() {
        eprintln!("! unverified peer: pass --fingerprint to pin its certificate");
    }
    println!(
        "  target      \"{}\" {}:{}",
        peer.info.alias, peer.ip, peer.info.port
    );
    *cached = Some(peer.clone());
    Ok(peer)
}

/// Never overwrite a previous delivery: two `photo.jpg` on different days are
/// both worth keeping.
fn move_to(sent_dir: &Path, path: &Path, name: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(sent_dir)?;
    let mut dest = sent_dir.join(name);
    if dest.exists() {
        let stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let stem = Path::new(name)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| String::from("file"));
        let ext = Path::new(name)
            .extension()
            .map(|s| format!(".{}", s.to_string_lossy()))
            .unwrap_or_default();
        dest = sent_dir.join(format!("{stem}-{stamp}{ext}"));
    }
    std::fs::rename(path, &dest).or_else(|_| {
        // Different filesystem, or a Windows handle still open: copy instead.
        copy_recursive(path, &dest)?;
        if path.is_dir() {
            std::fs::remove_dir_all(path)?;
        } else {
            std::fs::remove_file(path)?;
        }
        Ok::<(), std::io::Error>(())
    })?;
    Ok(dest)
}

fn copy_recursive(from: &Path, to: &Path) -> std::io::Result<()> {
    if from.is_dir() {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            copy_recursive(&entry.path(), &to.join(entry.file_name()))?;
        }
        Ok(())
    } else {
        std::fs::copy(from, to).map(|_| ())
    }
}

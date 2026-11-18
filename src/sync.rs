//! `zapsend sync`: push only the files the other side does not already have.
//!
//! LocalSend has no "what do you hold?" call, so this leans on the manifest
//! endpoint that zapsend receivers expose. Against a plain LocalSend app the
//! question cannot be answered at all, and an unanswered question is not an
//! empty answer: we refuse and say so instead of re-sending the whole folder
//! every night.
//!
//! The other half of the honesty is what sync will *not* do. LocalSend's upload
//! has no replace, so a file that exists on the peer with different bytes would
//! arrive as `report (1).csv` and the two sides would disagree forever. Those
//! are reported as conflicts and the run exits non-zero, because a duplicate is
//! worse than a refusal.

use crate::client::{self, Upload};
use crate::protocol::{DeviceInfo, Peer, PROTOCOL_VERSION};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

pub struct Options {
    pub dir: PathBuf,
    pub to: Option<String>,
    pub ip: Option<String>,
    pub fingerprint: Option<String>,
    pub pin: Option<String>,
    pub dry_run: bool,
    pub retries: u32,
}

pub async fn run(alias: &str, port: u16, opts: Options) -> Result<()> {
    if !opts.dir.is_dir() {
        bail!("{} is not a folder", opts.dir.display());
    }
    let peer = resolve(alias, port, &opts).await?;
    // `--pin` wins, otherwise the PIN `zapsend trust` remembered for this name.
    let pin = crate::hosts::resolve_pin(opts.pin.clone(), opts.to.as_deref());
    let Some(manifest) = client::manifest(&peer, pin.as_deref()).await? else {
        bail!(
            "{} does not answer /api/zapsend/v1/manifest — it is probably a plain LocalSend \
             app, which cannot say what it already has; use `zapsend send` instead",
            peer.info.alias
        );
    };
    let remote = parse_manifest(&manifest)?;
    let local = scan(&opts.dir)?;

    let mut todo: Vec<Upload> = Vec::new();
    let mut skipped = 0usize;
    let mut conflicts: Vec<String> = Vec::new();
    let mut bytes = 0u64;

    for (rel, path, size) in &local {
        match remote.get(rel) {
            Some((remote_size, remote_sha)) => {
                // Same size is not proof; a build that rewrites a report with the
                // same length is exactly the case worth catching.
                if *remote_size == *size && sha256_file(path)?.eq_ignore_ascii_case(remote_sha) {
                    skipped += 1;
                    continue;
                }
                conflicts.push(rel.clone());
            }
            None => {
                bytes += size;
                todo.push(Upload {
                    path: path.clone(),
                    name: rel.clone(),
                });
            }
        }
    }

    if opts.dry_run {
        for u in &todo {
            eprintln!("would send {}", u.name);
        }
        eprintln!(
            "{} to send, {skipped} already there, {} conflicting — nothing was sent",
            todo.len(),
            conflicts.len()
        );
    } else if !todo.is_empty() {
        let stack = crate::local_only(alias, port)?;
        client::send_files(
            &peer,
            &stack.me,
            &todo,
            pin.as_deref(),
            opts.retries,
        )
        .await
        .context("the peer took the manifest but refused the upload")?;
    }

    for rel in &conflicts {
        eprintln!("! {rel}: different content on the peer — LocalSend cannot replace a file, resolve it by hand");
    }

    if crate::json_mode() {
        println!(
            "{}",
            serde_json::json!({
                "ok": conflicts.is_empty(),
                "command": "sync",
                "peer": {
                    "alias": peer.info.alias,
                    "ip": peer.ip.to_string(),
                    "port": peer.info.port,
                    "fingerprint": peer.info.fingerprint,
                },
                "dir": opts.dir.display().to_string(),
                "scanned": local.len(),
                "sent": if opts.dry_run { 0 } else { todo.len() },
                "wouldSend": todo.len(),
                "skipped": skipped,
                "conflicts": conflicts,
                "bytes": bytes,
                "dryRun": opts.dry_run,
            })
        );
    } else {
        println!(
            "{} sent ({}), {skipped} already there, {} conflicting",
            if opts.dry_run { 0 } else { todo.len() },
            crate::human_bytes(bytes),
            conflicts.len()
        );
    }

    if !conflicts.is_empty() {
        bail!("{} file(s) differ on the peer", conflicts.len());
    }
    Ok(())
}

/// A name from the hosts file, or `--ip` for a machine nobody trusted yet. No
/// discovery: sync runs from cron, where there is nobody to pick between three
/// devices that answered.
async fn resolve(alias: &str, port: u16, opts: &Options) -> Result<Peer> {
    if let Some(raw) = opts.ip.as_deref() {
        let (addr, target_port) = crate::parse_target(raw)?;
        return Ok(Peer {
            info: DeviceInfo {
                zapsend_resume: false,
                alias: raw.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                device_model: None,
                device_type: None,
                fingerprint: opts.fingerprint.clone().unwrap_or_default(),
                port: target_port,
                protocol: "https".to_string(),
                download: false,
            },
            ip: addr,
        });
    }
    match crate::peer_from_hosts(alias, port, &opts.to).await? {
        Some((_stack, known)) => Ok(known),
        None => bail!(
            "sync needs a name it can trust: `zapsend trust {} --ip <addr>` first, or pass --ip",
            opts.to.as_deref().unwrap_or("NAME")
        ),
    }
}

/// The peer's answer, as `relative path -> (size, sha256)`.
fn parse_manifest(body: &serde_json::Value) -> Result<BTreeMap<String, (u64, String)>> {
    let files = body
        .get("files")
        .and_then(|f| f.as_object())
        .context("the peer's manifest has no files object")?;
    let mut out = BTreeMap::new();
    for (rel, meta) in files {
        let size = meta.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
        let sha = meta
            .get("sha256")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string();
        out.insert(rel.clone(), (size, sha));
    }
    Ok(out)
}

/// Every file under `root`, with the relative path a sender would use.
fn scan(root: &Path) -> Result<Vec<(String, PathBuf, u64)>> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .with_context(|| format!("cannot read folder {}", dir.display()))?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Dot entries are this tool's own bookkeeping (partial uploads,
            // .sent, .git). Syncing them would push state at the other side.
            if name.starts_with('.') {
                continue;
            }
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            // `file_type` does not follow symlinks: a link to a parent folder
            // would otherwise walk forever, and a link out of the tree would
            // quietly sync files the user never put there.
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                stack.push((entry.path(), rel));
                continue;
            }
            let size = entry.metadata()?.len();
            out.push((rel, entry.path(), size));
        }
    }
    out.sort();
    Ok(out)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

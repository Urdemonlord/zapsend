//! `zapsend pull`: the Download API, in the other direction.
//!
//! The sender runs a receiver with `--share DIR`; this asks for the file list and
//! streams the files back. Protocol v2, section 5.

use crate::protocol::{DeviceInfo, Peer, PROTOCOL_VERSION};
use crate::{client, human_bytes, identity, parse_target, resolve_target, scan, start, ApiServer};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

pub struct Options {
    /// Device to pull from (alias or fingerprint prefix, from `discover`).
    pub to: Option<String>,
    /// Connect straight to this address, skipping discovery.
    pub ip: Option<String>,
    /// Pin the peer's certificate (64 hex chars).
    pub fingerprint: Option<String>,
    /// PIN the sharing device requires.
    pub pin: Option<String>,
    /// Where to save the files.
    pub dir: PathBuf,
    /// Only pull files whose path or name contains one of these.
    pub file: Vec<String>,
    /// How many times to retry a broken download, resuming from the partial.
    pub retry: u32,
    /// Discovery scan duration in seconds (ignored with --ip).
    pub scan: u64,
}

pub async fn run(alias: &str, port: u16, opts: Options) -> Result<()> {
    let mut peer = match opts.ip.as_deref() {
        Some(raw) => {
            let (addr, target_port) = parse_target(raw)?;
            Peer {
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
            }
        }
        None => {
            if let Some((_stack, known)) =
                crate::peer_from_hosts(alias, port, &opts.to).await?
            {
                known
            } else {
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
            eprintln!("scanning for {}s…", opts.scan);
            let peers = scan(&stack, opts.scan).await;
            let Some(found) = resolve_target(&peers, opts.to.as_deref())? else {
                crate::print_peers(&peers);
                bail!("no device selected");
            };
            if let Some(expected) = opts.fingerprint.as_deref() {
                if !found.info.fingerprint.eq_ignore_ascii_case(expected) {
                    bail!(
                        "fingerprint mismatch: you pinned {}, but discovery found {}",
                        expected,
                        found.info.fingerprint
                    );
                }
            }
            found
            }
        }
    };

    // Ask the peer who it is before asking for files: that is where we learn
    // whether it offers the Download API at all, and which port it really serves.
    let info = client::fetch_info(&peer)
        .await
        .with_context(|| format!("cannot reach {}:{}", peer.ip, peer.info.port))?;
    peer.info.alias = info.alias.clone();
    peer.info.protocol = info.protocol.clone();
    peer.info.port = info.port;
    peer.info.download = info.download;

    if peer.info.fingerprint.is_empty() {
        eprintln!("! unverified peer: pass --fingerprint to pin its certificate");
    } else {
        eprintln!(
            "  pinned to {}",
            identity::short_fingerprint(&peer.info.fingerprint)
        );
    }

    if !info.download {
        bail!(
            "\"{}\" does not offer the Download API — its receiver needs `--share DIR`",
            info.alias
        );
    }

    let pin = crate::hosts::resolve_pin(opts.pin.clone(), opts.to.as_deref());
    let (session_id, files) = client::prepare_download(&peer, pin.as_deref()).await?;
    let mut wanted: Vec<_> = files
        .into_values()
        .filter(|f| {
            opts.file.is_empty()
                || opts
                    .file
                    .iter()
                    .any(|want| f.id.contains(want) || f.file_name.contains(want))
        })
        .collect();
    wanted.sort_by(|a, b| a.id.cmp(&b.id));

    if wanted.is_empty() {
        bail!("the peer shares files, but none match --file");
    }

    eprintln!(
        "pulling {} file(s) from \"{}\" into {}",
        wanted.len(),
        info.alias,
        opts.dir.display()
    );

    let mut total = 0u64;
    let mut failed = 0usize;
    let mut session_id = session_id;
    let mut report: Vec<serde_json::Value> = Vec::new();
    for file in &wanted {
        let dest = unique_dest(&opts.dir, &file.file_name);
        let mut last_error = None;
        let mut finished = None;
        for attempt in 0..=opts.retry {
            if attempt > 0 {
                eprintln!(
                    "  retry {attempt}/{} for {}",
                    opts.retry, file.file_name
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            match client::download_file(&peer, &session_id, file, &dest).await {
                Ok(bytes) => {
                    finished = Some(bytes);
                    break;
                }
                Err(e) => {
                    // The peer keeps download sessions in memory, so a restarted
                    // receiver answers 403. Ask for a fresh one and resume: the
                    // bytes on disk are still good.
                    if e.to_string().contains("403") {
                        if let Ok((fresh, _)) =
                            client::prepare_download(&peer, pin.as_deref()).await
                        {
                            eprintln!("  download session expired, asked for a new one");
                            session_id = fresh;
                        }
                    }
                    last_error = Some(e);
                }
            }
        }

        match (finished, last_error) {
            (Some(bytes), _) => {
                total += bytes;
                report.push(serde_json::json!({
                    "name": file.file_name,
                    "size": bytes,
                    "path": dest.display().to_string(),
                    "ok": true,
                }));
                if !crate::json_mode() {
                    println!("✓ {} ({})", file.file_name, human_bytes(bytes));
                }
            }
            (None, Some(e)) => {
                failed += 1;
                report.push(serde_json::json!({
                    "name": file.file_name,
                    "ok": false,
                    "error": e.to_string(),
                }));
                eprintln!("✗ {}: {e}", file.file_name);
            }
            (None, None) => unreachable!("a download either finishes or fails"),
        }
    }

    if crate::json_mode() {
        println!(
            "{}",
            serde_json::json!({
                "ok": failed == 0,
                "command": "pull",
                "peer": {
                    "alias": info.alias,
                    "ip": peer.ip.to_string(),
                    "port": peer.info.port,
                    "fingerprint": peer.info.fingerprint,
                },
                "dir": opts.dir.display().to_string(),
                "files": report,
                "count": wanted.len(),
                "failed": failed,
                "bytes": total,
            })
        );
    }

    if failed > 0 {
        bail!("{failed} of {} file(s) failed", wanted.len());
    }
    eprintln!("{} file(s), {}", wanted.len(), human_bytes(total));
    Ok(())
}

/// Never overwrite something already in the target directory: a pull that
/// silently replaces yesterday's copy is data loss.
fn unique_dest(dir: &Path, file_name: &str) -> PathBuf {
    let mut candidate = dir.join(file_name);
    if !candidate.exists() {
        return candidate;
    }

    let stem = candidate
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string();
    let ext = candidate.extension().and_then(|s| s.to_str()).map(String::from);

    for n in 1..10_000 {
        let name = match &ext {
            Some(ext) => format!("{stem} ({n}).{ext}"),
            None => format!("{stem} ({n})"),
        };
        candidate = dir.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(file_name)
}

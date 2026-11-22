//! `zapsend pull`: the Download API, in the other direction.
//!
//! The sender runs a receiver with `--share DIR`; this asks for the file list and
//! streams the files back. Protocol v2, section 5.

use crate::protocol::Peer;
use crate::{client, human_bytes, identity, resolve_target, scan, start, ApiServer};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

pub struct Options {
    /// Device to pull from (alias or fingerprint prefix, from `discover`).
    pub to: Option<String>,
    /// Connect straight to this address, skipping discovery.
    pub ip: Option<String>,
    /// Pin the peer's certificate (64 hex chars).
    pub fingerprint: Option<String>,
    /// Trust the address on first sight (see --tofu in the CLI help).
    pub tofu: bool,
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
    /// The peer serves plain HTTP (`receive --plain` on a private network).
    pub plain: bool,
}

pub async fn run(alias: &str, port: u16, opts: Options) -> Result<()> {
    // `--to a,b,c` or `--to all` pulls from several peers at once, each into its
    // own subdirectory: two machines can share a file name, and one overwrite is
    // one data loss.
    if let Some(list) = opts
        .to
        .as_deref()
        .filter(|t| t.contains(',') || *t == "all")
    {
        if opts.ip.is_some() {
            bail!("--ip takes a single peer; use --to for a list");
        }
        let names: Vec<String> = if list == "all" {
            crate::hosts::load()?.keys().cloned().collect()
        } else {
            list.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        };
        if names.is_empty() {
            bail!("nothing to pull from: the hosts file is empty (`zapsend trust NAME --ip ADDR`)");
        }
        return pull_many(&opts, &names).await;
    }

    let peer = match opts.ip.as_deref() {
        Some(raw) => {
            crate::resolve_ip_peer(raw, opts.fingerprint.as_deref(), opts.tofu, "pull files from", opts.plain)
                .await?
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
                false,
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

    // One peer: the shape that was already there, printed and exit-coded as before.
    let mut out = pull_one(&opts, peer, opts.to.as_deref(), &opts.dir).await?;
    if crate::json_mode() {
        if let Some(obj) = out.as_object_mut() {
            obj.insert("command".into(), serde_json::json!("pull"));
        }
        println!("{out}");
    }
    let failed = out["failed"].as_u64().unwrap_or(0);
    if failed > 0 {
        bail!(
            "{failed} of {} file(s) failed",
            out["count"].as_u64().unwrap_or(0)
        );
    }
    Ok(())
}

/// Pull from one peer. Returns what happened instead of deciding what to print:
/// the single-target path turns it into the familiar `pull --json` object, and
/// the list path aggregates several of them.
async fn pull_one(
    opts: &Options,
    mut peer: Peer,
    name: Option<&str>,
    dir: &Path,
) -> Result<serde_json::Value> {
    // Ask the peer who it is before asking for files: that is where we learn
    // whether it offers the Download API at all, and which port it really serves.
    let info = client::fetch_info(&peer)
        .await
        .with_context(|| format!("cannot reach {}:{}", peer.ip, peer.info.port))?;
    peer.info.alias = info.alias.clone();
    peer.info.protocol = info.protocol.clone();
    // Port stays as given: it is the one that answered.
    peer.info.download = info.download;

    crate::require_verified(
        &peer,
        opts.plain,
        "re-trust it first: `zapsend trust NAME --ip ADDR`, or pass --fingerprint",
    )?;
    if !peer.info.fingerprint.is_empty() {
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

    let pin = crate::hosts::resolve_pin(opts.pin.clone(), name);
    // A peer that shares over plain HTTP (the Download API in browser mode)
    // answers https with a TLS error that reads like a broken machine. Flip the
    // scheme once and keep the peer we flipped: the downloads that follow must
    // use the same one.
    let (session_id, files) = match client::prepare_download(&peer, pin.as_deref()).await {
        Ok(pair) => pair,
        Err(e) if format!("{e:#}").to_lowercase().contains("invalidcontenttype")
            || format!("{e:#}").to_lowercase().contains("corrupt message") =>
        {
            peer.info.protocol = if peer.info.protocol.eq_ignore_ascii_case("http") {
                "https".to_string()
            } else {
                "http".to_string()
            };
            eprintln!(
                "! {} did not answer over the first scheme — retrying over {}",
                peer.ip, peer.info.protocol
            );
            client::prepare_download(&peer, pin.as_deref()).await?
        }
        Err(e) => return Err(e),
    };
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
        dir.display()
    );

    let mut total = 0u64;
    let mut transferred = 0u64;
    let mut failed = 0usize;
    let mut session_id = session_id;
    let mut report: Vec<serde_json::Value> = Vec::new();
    for file in &wanted {
        let dest = unique_dest(&dir, &file.file_name);
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
            match client::download_file(&peer, &session_id, file, &dest, &mut transferred).await {
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

    let out = serde_json::json!({
        "ok": failed == 0,
        "peer": {
            "alias": info.alias,
            "ip": peer.ip.to_string(),
            "port": peer.info.port,
            "fingerprint": peer.info.fingerprint,
        },
        "dir": dir.display().to_string(),
        "files": report,
        "count": wanted.len(),
        "failed": failed,
        "bytes": total,
        // What the transfer cost, not what it produced: resumed and retried
        // downloads move more or less than the final size.
        "transferred": transferred,
    });
    eprintln!("{} file(s), {}", wanted.len(), human_bytes(total));
    Ok(out)
}

/// Pull from every named peer in turn. One unreachable machine must not cost the
/// others their files, so each failure is recorded and the rest still run.
async fn pull_many(opts: &Options, names: &[String]) -> Result<()> {
    let mut peers_report: Vec<serde_json::Value> = Vec::new();
    let mut failed_peers = 0usize;
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut transferred = 0u64;

    for name in names {
        let Some(peer) = crate::hosts::peer(name).await? else {
            eprintln!("✗ {name}: not in the hosts file — `zapsend trust {name} --ip <addr>` first");
            peers_report.push(serde_json::json!({
                "name": name,
                "ok": false,
                "error": "not in the hosts file",
            }));
            failed_peers += 1;
            continue;
        };
        let dir = opts.dir.join(name);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        eprintln!("→ {name} ({})", peer.ip);
        match pull_one(opts, peer, Some(name), &dir).await {
            Ok(v) => {
                let peer_failed = v["failed"].as_u64().unwrap_or(0);
                files += v["count"].as_u64().unwrap_or(0);
                bytes += v["bytes"].as_u64().unwrap_or(0);
                transferred += v["transferred"].as_u64().unwrap_or(0);
                if peer_failed > 0 {
                    failed_peers += 1;
                }
                peers_report.push(serde_json::json!({
                    "name": name,
                    "ok": peer_failed == 0,
                    "alias": v["peer"]["alias"],
                    "ip": v["peer"]["ip"],
                    "port": v["peer"]["port"],
                    "dir": v["dir"],
                    "files": v["files"],
                    "count": v["count"],
                    "failed": v["failed"],
                    "bytes": v["bytes"],
                    "transferred": v["transferred"],
                }));
            }
            Err(e) => {
                failed_peers += 1;
                eprintln!("✗ {name}: {e}");
                peers_report.push(serde_json::json!({
                    "name": name,
                    "ok": false,
                    "error": e.to_string(),
                }));
            }
        }
    }

    if crate::json_mode() {
        println!(
            "{}",
            serde_json::json!({
                "ok": failed_peers == 0,
                "command": "pull",
                "peers": peers_report,
                "count": names.len(),
                "failed": failed_peers,
                // In a list, `files` is how many arrived; the per-peer arrays
                // are in peers[].files.
                "files": files,
                "bytes": bytes,
                "transferred": transferred,
            })
        );
    } else {
        println!(
            "{} of {} peer(s), {} file(s), {}",
            names.len() - failed_peers,
            names.len(),
            files,
            human_bytes(bytes)
        );
    }
    if failed_peers > 0 {
        bail!("{failed_peers} of {} peer(s) failed", names.len());
    }
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

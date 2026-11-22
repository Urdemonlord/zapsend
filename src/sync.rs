//! `zapsend sync`: push only the files the other side does not already have.
//!
//! LocalSend has no "what do you hold?" call, so this leans on the manifest
//! endpoint that zapsend receivers expose. Against a plain LocalSend app the
//! question cannot be answered at all, and an unanswered question is not an
//! empty answer: we refuse and say so instead of re-sending the whole folder
//! every night.
//!
//! The other half of the honesty is what sync will *not* do by default.
//! LocalSend's upload has no replace, so a file that exists on the peer with
//! different bytes would arrive as `report (1).csv` and the two sides would
//! disagree forever. Those are reported as conflicts and the run exits
//! non-zero, because a duplicate is worse than a refusal.
//!
//! With `--replace` the sender may overwrite those files, and only those
//! files. The replacement is a zapsend extension (`FileMeta.replace`): the
//! receiver only honours it from a peer that answered the manifest endpoint,
//! the new bytes are hash-verified before the old file is touched, and the
//! old file is moved aside first and only deleted once the new one is in
//! place. After the send, sync re-reads the manifest and checks every
//! replaced file's hash against the local copy.

use crate::client::{self, Upload};
use crate::protocol::Peer;
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
    pub tofu: bool,
    pub pin: Option<String>,
    pub dry_run: bool,
    pub replace: bool,
    pub retries: u32,
    /// The peer serves plain HTTP (`receive --plain` on a private network).
    /// Only the --ip path reads it; with --to the stored entry already
    /// carries the scheme, so the flag is not needed there.
    pub plain: bool,
}

pub async fn run(alias: &str, port: u16, opts: Options) -> Result<()> {
    if !opts.dir.is_dir() {
        bail!("{} is not a folder", opts.dir.display());
    }
    let peer = resolve(alias, port, &opts).await?;
    crate::require_verified(
        &peer,
        "re-trust it first: `zapsend trust NAME --ip ADDR`, or pass --fingerprint",
    )?;
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
    let plan = plan(&local, &remote, opts.replace)?;

    if opts.dry_run {
        for u in &plan.todo {
            if u.replace {
                eprintln!("would replace {}", u.name);
            } else {
                eprintln!("would send {}", u.name);
            }
        }
        eprintln!(
            "{} to send, {} to replace, {} already there, {} conflicting — nothing was sent",
            plan.todo.len() - plan.replaced.len(),
            plan.replaced.len(),
            plan.skipped,
            plan.conflicts.len()
        );
    } else if !plan.todo.is_empty() {
        let stack = crate::local_only(alias, port)?;
        client::send_files(
            &peer,
            &stack.me,
            &plan.todo,
            pin.as_deref(),
            opts.retries,
        )
        .await
        .context("the peer took the manifest but refused the upload")?;
        if !plan.replaced.is_empty() {
            verify_replaced(&peer, pin.as_deref(), &plan.replaced).await?;
        }
    }

    for rel in &plan.conflicts {
        eprintln!("! {rel}: different content on the peer — LocalSend cannot replace a file, resolve it by hand (or re-run with --replace)");
    }

    let replaced_names: Vec<&str> = plan
        .replaced
        .iter()
        .map(|(rel, _)| rel.as_str())
        .collect();
    if crate::json_mode() {
        println!(
            "{}",
            serde_json::json!({
                "ok": plan.conflicts.is_empty(),
                "command": "sync",
                "peer": {
                    "alias": peer.info.alias,
                    "ip": peer.ip.to_string(),
                    "port": peer.info.port,
                    "fingerprint": peer.info.fingerprint,
                },
                "dir": opts.dir.display().to_string(),
                "scanned": local.len(),
                "sent": if opts.dry_run { 0 } else { plan.todo.len() },
                "wouldSend": plan.todo.len(),
                "replaced": replaced_names,
                "replace": opts.replace,
                "skipped": plan.skipped,
                "conflicts": plan.conflicts,
                "bytes": plan.bytes,
            })
        );
    } else {
        println!(
            "{} sent ({}), {} replaced, {} already there, {} conflicting",
            if opts.dry_run { 0 } else { plan.todo.len() },
            crate::human_bytes(plan.bytes),
            if opts.dry_run { 0 } else { plan.replaced.len() },
            plan.skipped,
            plan.conflicts.len()
        );
    }

    if !plan.conflicts.is_empty() {
        bail!("{} file(s) differ on the peer", plan.conflicts.len());
    }
    Ok(())
}

/// What one sync run will do, decided from the local scan and the peer's
/// manifest. Kept apart from `run` so the decision itself can be unit-tested
/// without a peer: the only IO is hashing a local file whose size matches
/// the remote one.
struct Plan {
    todo: Vec<Upload>,
    replaced: Vec<(String, PathBuf)>,
    skipped: usize,
    conflicts: Vec<String>,
    bytes: u64,
}

fn plan(
    local: &[(String, PathBuf, u64)],
    remote: &BTreeMap<String, (u64, String)>,
    replace: bool,
) -> Result<Plan> {
    let mut todo = Vec::new();
    let mut replaced = Vec::new();
    let mut skipped = 0usize;
    let mut conflicts = Vec::new();
    let mut bytes = 0u64;

    for (rel, path, size) in local {
        match remote.get(rel) {
            Some((remote_size, remote_sha)) => {
                // Same size is not proof; a build that rewrites a report with the
                // same length is exactly the case worth catching.
                if *remote_size == *size && sha256_file(path)?.eq_ignore_ascii_case(remote_sha)
                {
                    skipped += 1;
                    continue;
                }
                if replace {
                    bytes += size;
                    todo.push(Upload {
                        path: path.clone(),
                        name: rel.clone(),
                        replace: true,
                    });
                    replaced.push((rel.clone(), path.clone()));
                } else {
                    conflicts.push(rel.clone());
                }
            }
            None => {
                bytes += size;
                todo.push(Upload {
                    path: path.clone(),
                    name: rel.clone(),
                    replace: false,
                });
            }
        }
    }
    Ok(Plan {
        todo,
        replaced,
        skipped,
        conflicts,
        bytes,
    })
}

/// After a `--replace` run, ask the peer again and confirm every replaced
/// file now hashes to the local bytes. The old file is already gone, so a
/// mismatch here is reported loudly — re-running `sync --replace` re-sends
/// the local copy.
async fn verify_replaced(
    peer: &Peer,
    pin: Option<&str>,
    replaced: &[(String, PathBuf)],
) -> Result<()> {
    let Some(manifest) = client::manifest(peer, pin).await? else {
        bail!("the peer stopped answering the manifest after the replace — verify by hand");
    };
    let remote = parse_manifest(&manifest)?;
    let mut bad = Vec::new();
    for (rel, path) in replaced {
        let want = sha256_file(path)?;
        match remote.get(rel) {
            Some((_, got)) if got.eq_ignore_ascii_case(&want) => {}
            _ => bad.push(rel.clone()),
        }
    }
    if !bad.is_empty() {
        bail!(
            "replace did not land for {} — re-run `sync --replace` to send the local copy again",
            bad.join(", ")
        );
    }
    Ok(())
}

/// A name from the hosts file, or `--ip` for a machine nobody trusted yet. No
/// discovery: sync runs from cron, where there is nobody to pick between three
/// devices that answered.
async fn resolve(alias: &str, port: u16, opts: &Options) -> Result<Peer> {
    if let Some(raw) = opts.ip.as_deref() {
        return crate::resolve_ip_peer(raw, opts.fingerprint.as_deref(), opts.tofu, "sync with", opts.plain)
            .await;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(dir: &str, name: &str, content: &[u8]) -> PathBuf {
        let root = std::env::temp_dir().join(dir);
        let _ = std::fs::create_dir_all(&root);
        let path = root.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    fn local(entries: &[(&str, PathBuf)]) -> Vec<(String, PathBuf, u64)> {
        entries
            .iter()
            .map(|(rel, path)| {
                (
                    rel.to_string(),
                    path.clone(),
                    std::fs::metadata(path).unwrap().len(),
                )
            })
            .collect()
    }

    #[test]
    fn plan_sends_new_skips_identical_and_conflicts_on_change() {
        let dir = "zapsend-sync-plan";
        let new = write_tmp(dir, "new.txt", b"brand new");
        let same = write_tmp(dir, "same.txt", b"identical");
        let changed = write_tmp(dir, "changed.txt", b"version two");
        let mut remote = BTreeMap::new();
        remote.insert(
            "same.txt".to_string(),
            (
                9,
                sha256_file(&same).unwrap(),
            ),
        );
        remote.insert("changed.txt".to_string(), (11, "0".repeat(64)));

        let p = plan(&local(&[("new.txt", new), ("same.txt", same), ("changed.txt", changed)]), &remote, false).unwrap();
        assert_eq!(p.todo.len(), 1);
        assert_eq!(p.todo[0].name, "new.txt");
        assert!(!p.todo[0].replace);
        assert_eq!(p.skipped, 1);
        assert_eq!(p.conflicts, vec!["changed.txt".to_string()]);
        assert!(p.replaced.is_empty());
    }

    #[test]
    fn plan_replace_turns_conflicts_into_replacements() {
        let dir = "zapsend-sync-plan-replace";
        let changed = write_tmp(dir, "report.csv", b"v2,more,rows");
        let mut remote = BTreeMap::new();
        remote.insert("report.csv".to_string(), (7, "f".repeat(64)));

        let p = plan(&local(&[("report.csv", changed)]), &remote, true).unwrap();
        assert_eq!(p.todo.len(), 1);
        assert!(p.todo[0].replace);
        assert_eq!(p.replaced.len(), 1);
        assert_eq!(p.replaced[0].0, "report.csv");
        assert!(p.conflicts.is_empty());
    }

    #[test]
    fn plan_same_size_different_bytes_is_not_a_skip() {
        let dir = "zapsend-sync-plan-samesize";
        let f = write_tmp(dir, "a.bin", b"AAAA");
        let mut remote = BTreeMap::new();
        remote.insert("a.bin".to_string(), (4, sha256_file(&write_tmp(dir, "b.bin", b"BBBB")).unwrap()));
        let p = plan(&local(&[("a.bin", f)]), &remote, false).unwrap();
        assert_eq!(p.skipped, 0);
        assert_eq!(p.conflicts, vec!["a.bin".to_string()]);
    }
}

//! Cache of whole-file SHA-256 hashes, keyed by (path, size, mtime).
//!
//! The sender must hash every file before `prepare-upload`, which is a full
//! extra read pass over bytes that are about to be read again for the upload
//! itself. A repeat send of an unchanged file skips that pass entirely: the
//! cached hash is reused when the file on disk still has the same size and
//! modification time. A file that changed (different size or mtime) is
//! re-hashed, so the cache can only serve a stale hash if a file is rewritten
//! with identical size *and* mtime — the same heuristic rsync uses.
//!
//! The cache is best-effort and never fails a send: a missing, corrupt or
//! unwritable cache file is silently ignored and the send proceeds with a
//! fresh hash. It holds no secrets, only paths, sizes, mtimes and hashes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Bound the file so a machine that sends many distinct files does not grow
/// it without limit. Eviction keeps the most recently used entries.
const MAX_ENTRIES: usize = 4096;

#[derive(Serialize, Deserialize)]
struct Entry {
    size: u64,
    mtime_secs: i64,
    mtime_nanos: u32,
    sha256: String,
    #[serde(default)]
    last_used: u64,
}

pub struct HashCache {
    path: Option<PathBuf>,
    entries: HashMap<String, Entry>,
}

fn cache_path() -> Option<PathBuf> {
    let dir = dirs::cache_dir()?;
    Some(dir.join("zapsend").join("hashes.json"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// (mtime secs, mtime nanos) for a file that still has the given size.
/// `None` when the file cannot be read or its size changed.
fn file_sig(path: &Path, size: u64) -> Option<(i64, u32)> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() != size {
        return None;
    }
    let mtime = meta.modified().ok()?;
    let d = mtime.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    Some((d.as_secs() as i64, d.subsec_nanos()))
}

fn key_for(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

impl HashCache {
    /// Load the cache; an absent or unreadable file means an empty cache.
    pub fn load() -> Self {
        let path = cache_path();
        let entries = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self { path, entries }
    }

    /// The cached hash, if the file on disk still matches the recorded
    /// size and mtime. A hit refreshes the entry's recency.
    pub fn lookup(&mut self, path: &Path, size: u64) -> Option<String> {
        let (secs, nanos) = file_sig(path, size)?;
        let entry = self.entries.get_mut(&key_for(path))?;
        if entry.size == size && entry.mtime_secs == secs && entry.mtime_nanos == nanos {
            entry.last_used = now_secs();
            Some(entry.sha256.clone())
        } else {
            None
        }
    }

    /// Record a freshly computed hash. A no-op when the file cannot be
    /// re-stat'ed (it may have been deleted mid-send).
    pub fn store(&mut self, path: &Path, size: u64, sha: &str) {
        let Some((secs, nanos)) = file_sig(path, size) else {
            return;
        };
        self.entries.insert(
            key_for(path),
            Entry {
                size,
                mtime_secs: secs,
                mtime_nanos: nanos,
                sha256: sha.to_string(),
                last_used: now_secs(),
            },
        );
    }

    /// Persist the cache atomically (write temp file, rename). Failures are
    /// ignored: the cache is an optimisation, not part of the transfer.
    pub fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if self.entries.is_empty() {
            return;
        }
        let mut items: Vec<(&String, &Entry)> = self.entries.iter().collect();
        items.sort_by_key(|(_, e)| std::cmp::Reverse(e.last_used));
        items.truncate(MAX_ENTRIES);
        let kept: HashMap<&String, &Entry> = items.into_iter().collect();
        let Ok(text) = serde_json::to_string(&kept) else {
            return;
        };
        let Some(parent) = path.parent() else {
            return;
        };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let tmp = parent.join("hashes.json.tmp");
        if std::fs::write(&tmp, text).is_err() {
            return;
        }
        let _ = std::fs::rename(&tmp, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_hit_requires_same_size_and_mtime() {
        let dir = std::env::temp_dir().join("zapsend-hashcache-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("f.bin");
        std::fs::write(&path, b"hello").unwrap();
        let mut cache = HashCache {
            path: None,
            entries: HashMap::new(),
        };
        cache.store(&path, 5, "abc");
        assert_eq!(cache.lookup(&path, 5).as_deref(), Some("abc"));
        // Same path, different size: miss.
        assert_eq!(cache.lookup(&path, 6), None);
        // Same size, different mtime: miss (the file was rewritten).
        let f = std::fs::File::options().write(true).open(&path).unwrap();
        let later = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        f.set_modified(later).unwrap();
        drop(f);
        assert_eq!(cache.lookup(&path, 5), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

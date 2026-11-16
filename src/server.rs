//! The receiving side: an HTTPS server that speaks the LocalSend upload API.
//!
//! Endpoints (all under `/api/localsend/v2`):
//!   POST /register        — peer announces itself to us
//!   POST /prepare-upload  — peer offers file metadata, we hand back tokens
//!   POST /upload          — peer streams one file

use crate::discovery::Registry;
use crate::protocol::{DeviceInfo, FileMeta, PrepareUploadRequest, PrepareUploadResponse, API};
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use futures_util::{StreamExt, TryStreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::io::StreamReader;

pub struct Session {
    /// file id -> (metadata, token)
    pub files: HashMap<String, (FileMeta, String)>,
}

pub struct AppState {
    pub me: DeviceInfo,
    pub registry: Registry,
    pub download_dir: PathBuf,
    pub sessions: Mutex<HashMap<String, Session>>,
    pub pin: PinState,
    pub ask: bool,
}

/// A 6-digit PIN is only 10^6 guesses, so the PIN is useless without a
/// throttle. Five wrong attempts lock preparation for a minute.
const MAX_PIN_FAILURES: u32 = 5;
const PIN_LOCKOUT: Duration = Duration::from_secs(60);

pub struct PinState {
    expected: Option<String>,
    inner: Mutex<PinInner>,
}

#[derive(Default)]
struct PinInner {
    failures: u32,
    locked_until: Option<Instant>,
}

impl PinState {
    pub fn new(expected: Option<String>) -> Self {
        Self {
            expected,
            inner: Mutex::new(PinInner::default()),
        }
    }

    pub fn is_required(&self) -> bool {
        self.expected.is_some()
    }

    /// `Ok` when the supplied PIN is right, or when no PIN is required.
    pub fn check(&self, supplied: Option<&str>) -> Result<(), (StatusCode, String)> {
        let Some(expected) = self.expected.as_deref() else {
            return Ok(());
        };

        let mut inner = self.inner.lock().unwrap();

        if let Some(until) = inner.locked_until {
            let now = Instant::now();
            if now < until {
                let wait = (until - now).as_secs() + 1;
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("too many attempts, retry in {wait}s"),
                ));
            }
            inner.locked_until = None;
        }

        match supplied {
            Some(given) if ct_eq(given, expected) => {
                inner.failures = 0;
                Ok(())
            }
            Some(_) => {
                inner.failures += 1;
                if inner.failures >= MAX_PIN_FAILURES {
                    inner.failures = 0;
                    inner.locked_until = Some(Instant::now() + PIN_LOCKOUT);
                    Err((
                        StatusCode::TOO_MANY_REQUESTS,
                        "too many attempts, locked for 60s".to_string(),
                    ))
                } else {
                    Err((StatusCode::UNAUTHORIZED, "invalid PIN".to_string()))
                }
            }
            None => Err((StatusCode::UNAUTHORIZED, "PIN required".to_string())),
        }
    }
}

/// Length-independent comparison, so a wrong PIN leaks nothing through timing.
/// Length itself is not secret — a PIN is always short.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(&format!("{API}/register"), post(register))
        .route(&format!("{API}/prepare-upload"), post(prepare_upload))
        .route(&format!("{API}/upload"), post(upload))
        .with_state(state)
}

async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Json<DeviceInfo> {
    crate::verbose::dump("←", "register", &body);

    // Be liberal here: even if their body is unparsable, they still deserve
    // our information back so we show up in their device list.
    match serde_json::from_slice::<DeviceInfo>(&body) {
        Ok(info) => {
            if !info.fingerprint.is_empty() && info.fingerprint != state.me.fingerprint {
                state.registry.lock().unwrap().insert(
                    info.fingerprint.clone(),
                    crate::protocol::Peer {
                        info: info.clone(),
                        ip: addr.ip(),
                    },
                );
            }
        }
        Err(e) => eprintln!("! could not parse register body: {e}"),
    }

    Json(state.me.clone())
}

#[derive(Debug, Deserialize)]
struct PinQuery {
    pin: Option<String>,
}

/// One terminal, one prompt: serialise confirmations so two simultaneous
/// transfers cannot interleave their questions.
static STDIN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn confirm(from: &str, files: &HashMap<String, FileMeta>) -> bool {
    let mut listing = String::new();
    for meta in files.values() {
        listing.push_str(&format!(
            "      {}  ({})\n",
            meta.file_name,
            crate::human_bytes(meta.size)
        ));
    }

    let _guard = STDIN.lock().await;
    print!(
        "\n← {} file(s) from \"{from}\"\n{listing}  accept? [y/N] ",
        files.len()
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // Reading stdin is blocking, and the handler must not stall the runtime.
    match tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map(|_| line)
    })
    .await
    {
        Ok(Ok(line)) => matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        _ => false,
    }
}

async fn prepare_upload(
    State(state): State<Arc<AppState>>,
    Query(q): Query<PinQuery>,
    body: Bytes,
) -> axum::response::Response {
    crate::verbose::dump("←", "prepare-upload", &body);

    // `info` is optional in our model: protocol 2.0 senders may omit it, and a
    // 422 here would look like a network bug instead of a format mismatch.
    let req: PrepareUploadRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("✗ bad prepare-upload body: {e}");
            return (StatusCode::BAD_REQUEST, format!("invalid body: {e}")).into_response();
        }
    };

    if let Err((code, msg)) = state.pin.check(q.pin.as_deref()) {
        eprintln!("✗ rejected transfer: {msg}");
        return (code, msg).into_response();
    }

    let from = req
        .info
        .as_ref()
        .map(|i| i.alias.clone())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    if state.ask && !confirm(&from, &req.files).await {
        eprintln!("✗ declined: {} file(s) from \"{from}\"", req.files.len());
        return (StatusCode::FORBIDDEN, "declined by receiver".to_string()).into_response();
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let mut tokens = HashMap::new();
    let mut files = HashMap::new();

    for (id, meta) in req.files {
        let token = uuid::Uuid::new_v4().to_string();
        tokens.insert(id.clone(), token.clone());
        files.insert(id, (meta, token));
    }

    let count = files.len();
    state
        .sessions
        .lock()
        .unwrap()
        .insert(session_id.clone(), Session { files });

    eprintln!("→ incoming: {} file(s) from \"{}\"", count, from);

    (
        StatusCode::OK,
        Json(PrepareUploadResponse {
            session_id,
            files: tokens,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadQuery {
    session_id: String,
    file_id: String,
    token: String,
}

async fn upload(
    State(state): State<Arc<AppState>>,
    Query(q): Query<UploadQuery>,
    body: Body,
) -> impl IntoResponse {
    let found = {
        let sessions = state.sessions.lock().unwrap();
        sessions
            .get(&q.session_id)
            .and_then(|s| s.files.get(&q.file_id))
            .map(|(meta, token)| (meta.clone(), token.clone()))
    };

    let Some((meta, expected_token)) = found else {
        return (StatusCode::FORBIDDEN, "unknown session or file".to_string());
    };

    if expected_token != q.token {
        return (StatusCode::FORBIDDEN, "invalid token".to_string());
    }

    if let Err(e) = tokio::fs::create_dir_all(&state.download_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot create download dir: {e}"),
        );
    }

    let path = unique_path(&state.download_dir, &meta.file_name);
    if let Some(parent) = path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot create folder {}: {e}", parent.display()),
            );
        }
    }
    let file = match tokio::fs::File::create(&path).await {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot create file: {e}"),
            )
        }
    };

    let pb = Arc::new(ProgressBar::new(meta.size));
    if let Ok(style) = ProgressStyle::with_template("{msg} [{bar:30}] {bytes}/{total_bytes}") {
        pb.set_style(style.progress_chars("=> "));
    }
    pb.set_message(meta.file_name.clone());

    let bar = pb.clone();
    let stream = body.into_data_stream().map(move |chunk| {
        if let Ok(ref c) = chunk {
            bar.inc(c.len() as u64);
        }
        chunk
    });

    let mut reader = StreamReader::new(stream.map_err(std::io::Error::other));

    let mut out = tokio::io::BufWriter::new(file);
    let result = tokio::io::copy(&mut reader, &mut out).await;
    pb.finish_and_clear();

    match result {
        Ok(_) => {
            eprintln!("✓ saved {}", path.display());
            (StatusCode::OK, String::new())
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&path).await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("write failed: {e}"),
            )
        }
    }
}

/// Never silently clobber an existing file: `a.txt` -> `a (1).txt`, and keep
/// the folder part a peer sent (`holiday/img.jpg`) instead of flattening it.
fn unique_path(dir: &Path, file_name: &str) -> PathBuf {
    let rel = safe_rel(file_name);
    let mut candidate = dir.join(&rel);
    if !candidate.exists() {
        return candidate;
    }

    let parent = candidate.parent().unwrap_or(dir).to_path_buf();
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
        candidate = parent.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(rel)
}

/// Keep the relative folders a peer sent, but drop anything that could escape
/// our download dir: `..`, absolute roots, control characters, silly depth.
fn safe_rel(file_name: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for part in file_name.split(['/', '\\']) {
        let cleaned: String = part.trim().chars().filter(|c| !c.is_control()).collect();
        if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
            continue;
        }
        if out.iter().count() >= 32 {
            break;
        }
        out.push(cleaned);
    }
    if out.as_os_str().is_empty() {
        out.push("unnamed");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_paths_stay_inside_the_download_dir() {
        assert_eq!(safe_rel("holiday/img.jpg"), Path::new("holiday/img.jpg"));
        assert_eq!(safe_rel("../../etc/passwd"), Path::new("etc/passwd"));
        assert_eq!(safe_rel("/etc/passwd"), Path::new("etc/passwd"));
        assert_eq!(safe_rel("a/../b.txt"), Path::new("a/b.txt"));
        assert_eq!(safe_rel(".."), Path::new("unnamed"));
        assert_eq!(safe_rel(""), Path::new("unnamed"));
        assert_eq!(safe_rel("a\\b\\c.txt"), Path::new("a/b/c.txt"));
    }
}

//! The receiving side: an HTTPS server that speaks the LocalSend upload API.
//!
//! Endpoints (all under `/api/localsend/v2`):
//!   POST /register        — peer announces itself to us
//!   POST /prepare-upload  — peer offers file metadata, we hand back tokens
//!   POST /upload          — peer streams one file

use crate::discovery::Registry;
use crate::protocol::{DeviceInfo, FileMeta, PrepareUploadRequest, PrepareUploadResponse, API};
use axum::{
    body::Body,
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
    Json(info): Json<DeviceInfo>,
) -> Json<DeviceInfo> {
    if !info.fingerprint.is_empty() && info.fingerprint != state.me.fingerprint {
        state.registry.lock().unwrap().insert(
            info.fingerprint.clone(),
            crate::protocol::Peer {
                info: info.clone(),
                ip: addr.ip(),
            },
        );
    }
    Json(state.me.clone())
}

#[derive(Debug, Deserialize)]
struct PinQuery {
    pin: Option<String>,
}

async fn prepare_upload(
    State(state): State<Arc<AppState>>,
    Query(q): Query<PinQuery>,
    Json(req): Json<PrepareUploadRequest>,
) -> axum::response::Response {
    if let Err((code, msg)) = state.pin.check(q.pin.as_deref()) {
        eprintln!("✗ rejected transfer: {msg}");
        return (code, msg).into_response();
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

    eprintln!(
        "→ incoming: {} file(s) from \"{}\"",
        count,
        if req.info.alias.is_empty() {
            "unknown"
        } else {
            &req.info.alias
        }
    );

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

/// Never silently clobber an existing file: `a.txt` -> `a (1).txt`.
fn unique_path(dir: &Path, file_name: &str) -> PathBuf {
    let safe = sanitize(file_name);
    let mut candidate = dir.join(&safe);
    if !candidate.exists() {
        return candidate;
    }

    let path = Path::new(&safe);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = path.extension().and_then(|s| s.to_str());

    for n in 1..10_000 {
        let name = match ext {
            Some(ext) => format!("{stem} ({n}).{ext}"),
            None => format!("{stem} ({n})"),
        };
        candidate = dir.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(safe)
}

/// Strip path separators and traversal so a peer cannot write outside our dir.
fn sanitize(file_name: &str) -> String {
    let base = file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(file_name)
        .trim();
    let cleaned: String = base.chars().filter(|c| !c.is_control()).collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "unnamed".to_string()
    } else {
        cleaned
    }
}

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

async fn prepare_upload(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PrepareUploadRequest>,
) -> impl IntoResponse {
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

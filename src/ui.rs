//! Local web UI for `zapsend ui`.
//!
//! Plain HTTP on loopback only, on purpose: the protocol's API is HTTPS with a
//! self-signed certificate, and a browser would refuse those fetches (or nag on
//! every load). Peers keep talking to the normal HTTPS server; this page is just
//! a front end that shares the same `AppState` and registry.

use crate::client;
use crate::protocol::Peer;
use crate::server::AppState;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, Json};
use axum::routing::{get, post, put};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

const PAGE: &str = include_str!("ui.html");

pub struct UiState {
    pub app: Arc<AppState>,
    /// Drag & drop lands here first: the browser cannot hand us a file path,
    /// only bytes, so dropped files are staged and then sent from disk.
    pub staging: PathBuf,
}

type Fail = (StatusCode, String);

pub fn router(state: Arc<UiState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/favicon.svg", get(favicon))
        .route("/ui/state", get(state_of_things))
        .route("/ui/stage", put(stage).delete(clear_staging))
        .route("/ui/send", post(send))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(PAGE)
}

async fn favicon() -> impl axum::response::IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/svg+xml")],
        include_str!("../assets/favicon.svg"),
    )
}

#[derive(Serialize)]
struct DeviceDto {
    alias: String,
    address: String,
    port: u16,
    fingerprint: String,
    device_type: String,
}

#[derive(Serialize)]
struct StateDto {
    alias: String,
    port: u16,
    download_dir: String,
    pin_required: bool,
    staging_dir: String,
    staged: Vec<String>,
    devices: Vec<DeviceDto>,
}

async fn state_of_things(State(ui): State<Arc<UiState>>) -> Json<StateDto> {
    let mut devices: Vec<DeviceDto> = ui
        .app
        .registry
        .lock()
        .unwrap()
        .values()
        .map(|p| DeviceDto {
            alias: p.info.alias.clone(),
            address: p.ip.to_string(),
            port: p.info.port,
            fingerprint: p.info.fingerprint.clone(),
            device_type: p.info.device_type.clone().unwrap_or_else(|| "?".into()),
        })
        .collect();
    devices.sort_by(|a, b| a.alias.to_lowercase().cmp(&b.alias.to_lowercase()));

    Json(StateDto {
        alias: ui.app.me.alias.clone(),
        port: ui.app.me.port,
        download_dir: ui.app.download_dir.display().to_string(),
        pin_required: ui.app.pin.is_required(),
        staging_dir: ui.staging.display().to_string(),
        staged: list_staged(&ui.staging),
        devices,
    })
}

fn list_staged(dir: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .collect();
    names.sort();
    names
}

#[derive(Deserialize)]
struct StageQuery {
    name: String,
}

/// Raw body upload — no multipart parsing needed for one file at a time.
async fn stage(
    State(ui): State<Arc<UiState>>,
    Query(q): Query<StageQuery>,
    body: Bytes,
) -> Result<Json<Vec<String>>, Fail> {
    let name = safe_name(&q.name);
    std::fs::create_dir_all(&ui.staging).map_err(internal)?;
    tokio::fs::write(ui.staging.join(&name), &body)
        .await
        .map_err(internal)?;
    Ok(Json(list_staged(&ui.staging)))
}

async fn clear_staging(State(ui): State<Arc<UiState>>) -> Json<Vec<String>> {
    let _ = std::fs::remove_dir_all(&ui.staging);
    Json(Vec::new())
}

/// Keep the leaf name only: dropped files have no folder context anyway.
fn safe_name(raw: &str) -> String {
    let base = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(raw)
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>();
    if base.is_empty() || base == "." || base == ".." {
        format!("file-{}", std::process::id())
    } else {
        base
    }
}

#[derive(Deserialize)]
struct SendRequest {
    /// Fingerprint from the device list.
    #[serde(default)]
    fingerprint: Option<String>,
    /// `ip` or `ip:port`, for a device discovery has not seen.
    #[serde(default)]
    ip: Option<String>,
    /// Absolute paths on this machine (folders allowed).
    #[serde(default)]
    paths: Vec<String>,
    /// File names previously staged by drag & drop.
    #[serde(default)]
    staged: Vec<String>,
    #[serde(default)]
    pin: Option<String>,
}

#[derive(Serialize)]
struct SendResponse {
    ok: bool,
    files: usize,
    bytes: u64,
    target: String,
}

async fn send(
    State(ui): State<Arc<UiState>>,
    Json(req): Json<SendRequest>,
) -> Result<Json<SendResponse>, Fail> {
    let peer = resolve_peer(&ui, &req)?;

    let mut inputs: Vec<PathBuf> = req.paths.iter().map(PathBuf::from).collect();
    for name in &req.staged {
        let path = ui.staging.join(safe_name(name));
        if path.is_file() {
            inputs.push(path);
        }
    }
    if inputs.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "pick a folder or drop some files first".to_string(),
        ));
    }

    let uploads = crate::collect_uploads(&inputs).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("{e:#}"),
        )
    })?;
    let bytes: u64 = uploads
        .iter()
        .filter_map(|u| std::fs::metadata(&u.path).ok())
        .map(|m| m.len())
        .sum();
    let files = uploads.len();

    // The web UI has no --plain opt-in, so a fingerprinted peer is never
    // retried over cleartext here; an unpinned --ip peer still flips, the
    // way a plain receiver needs it to.
    client::send_files(&peer, &ui.app.me, &uploads, req.pin.as_deref(), 3, false)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("{e:#}")))?;

    Ok(Json(SendResponse {
        ok: true,
        files,
        bytes,
        target: format!("{}:{}", peer.ip, peer.info.port),
    }))
}

fn resolve_peer(ui: &UiState, req: &SendRequest) -> Result<Peer, Fail> {
    if let Some(raw) = req.ip.as_deref() {
        let (addr, port) = crate::parse_target(raw)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:#}")))?;
        return Ok(Peer {
            info: crate::protocol::DeviceInfo {
            zapsend_resume: false,
                alias: raw.to_string(),
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

    let want = req.fingerprint.as_deref().ok_or((
        StatusCode::BAD_REQUEST,
        "no target: pick a device or give an ip".to_string(),
    ))?;
    let found = ui
        .app
        .registry
        .lock()
        .unwrap()
        .values()
        .find(|p| {
            p.info.fingerprint.eq_ignore_ascii_case(want)
                || p.info.fingerprint.to_lowercase().starts_with(&want.to_lowercase())
        })
        .cloned();
    found.ok_or((
        StatusCode::NOT_FOUND,
        "that device is gone — it has not announced itself lately".to_string(),
    ))
}

fn internal(e: std::io::Error) -> Fail {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Open the page in the default browser. Best effort: a headless box has none.
pub fn open_browser(url: &str) {
    let (cmd, args): (&str, Vec<&str>) = if cfg!(target_os = "windows") {
        ("cmd", vec!["/C", "start", "", url])
    } else if cfg!(target_os = "macos") {
        ("open", vec![url])
    } else {
        ("xdg-open", vec![url])
    };
    let _ = std::process::Command::new(cmd).args(args).spawn();
}

/// `zapsend ui`: the normal receiver stack plus a plain-HTTP page on loopback.
pub async fn run(
    alias: &str,
    port: u16,
    dir: PathBuf,
    pin: Option<String>,
    ui_port: u16,
    no_open: bool,
) -> anyhow::Result<()> {
    let pin = match pin {
        None => None,
        Some(p) if p.is_empty() => Some(crate::generate_pin()),
        Some(p) if p.chars().all(|c| c.is_ascii_digit()) => Some(p),
        Some(p) => anyhow::bail!("PIN must contain digits only, got \"{p}\""),
    };

    std::fs::create_dir_all(&dir)?;
    let stack = crate::start(
        alias,
        port,
        dir.clone(),
        None,
        pin.clone(),
        false,
        crate::ApiServer::Required,
        false,
    )
        .await?;

    // Keep announcing: the page's device list is this registry, and peers only
    // fill it if we keep showing up in theirs.
    if let Some(sock) = stack.sock.clone() {
        let me = stack.me.clone();
        let registry = stack.registry.clone();
        tokio::spawn(async move {
            let mut tick = 0u32;
            loop {
                let _ = crate::discovery::announce(&sock, &me).await;
                // Multicast is blocked on hotspots and guest networks, and the
                // page would sit empty — sweep now and then as a safety net.
                if tick % 10 == 0 {
                    let _ = crate::discovery::sweep(&registry, &me, true).await;
                }
                tick = tick.wrapping_add(1);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    let staging = std::env::temp_dir().join("zapsend-ui-staging");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)?;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", ui_port)).await?;
    let url = format!("http://127.0.0.1:{ui_port}/");

    println!("  page        {url}");
    println!("  api         :{port} (https)");
    println!("  saving to   {}", dir.display());
    if let Some(pin) = &pin {
        println!("  pin         {pin}");
    }
    println!();
    println!("  ctrl-c to stop");

    if !no_open {
        open_browser(&url);
    }

    axum::serve(
        listener,
        router(Arc::new(UiState {
            app: stack.state.clone(),
            staging,
        })),
    )
    .await?;
    Ok(())
}

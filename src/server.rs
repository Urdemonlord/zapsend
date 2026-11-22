//! The receiving side: an HTTPS server that speaks the LocalSend upload API.
//!
//! `receive --plain` serves the same router over plain HTTP instead — same
//! endpoints, same PIN checks, no TLS. Only for a private network, where the
//! link itself is already encrypted (Tailscale, WireGuard).
//!
//! Endpoints (all under `/api/localsend/v2`):
//!   POST /register        — peer announces itself to us
//!   POST /prepare-upload  — peer offers file metadata, we hand back tokens
//!   POST /upload          — peer streams one file

use crate::discovery::Registry;
use crate::protocol::{
    DeviceInfo, FileMeta, PrepareDownloadResponse, PrepareUploadRequest, PrepareUploadResponse,
    ResumeState, API,
};
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use futures_util::{StreamExt, TryStreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::io::SeekFrom;
use tokio::io::AsyncSeekExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::io::{ReaderStream, StreamReader};

pub struct Session {
    /// file id -> (metadata, token)
    pub files: HashMap<String, (FileMeta, String)>,
    /// Who opened it. The spec's 403 is "invalid token or IP address", and a
    /// session id is not a secret — it travels in URLs.
    pub ip: std::net::IpAddr,
}

pub struct AppState {
    pub me: DeviceInfo,
    pub registry: Registry,
    pub download_dir: PathBuf,
    pub sessions: Mutex<HashMap<String, Session>>,
    pub pin: PinState,
    pub ask: bool,
    /// Directory offered through the Download API. `None` disables it: sharing
    /// is opt-in, never a side effect of receiving.
    pub share: Option<PathBuf>,
    /// Live download sessions. Without this the API would be an open file
    /// server for the whole share dir instead of one the puller asked for.
    pub downloads: Mutex<HashMap<String, Instant>>,
}

/// How long a `/prepare-download` session stays usable. Long enough for a slow
/// phone to pull a big folder, short enough that a leaked id goes stale.
const DOWNLOAD_SESSION_TTL: Duration = Duration::from_secs(3600);
/// Bounds on what `--share` will enumerate, so pointing it at a home directory
/// by accident does not produce a million-entry response.
const MAX_SHARE_FILES: usize = 5_000;
const MAX_SHARE_DEPTH: usize = 8;

/// A 6-digit PIN is only 10^6 guesses, so the PIN is useless without a
/// throttle. Five wrong attempts from one address lock that address for a
/// minute.
///
/// Per address, not globally: a global counter lets any stranger on the LAN
/// lock the owner out of their own receiver by guessing wrong five times.
const MAX_PIN_FAILURES: u32 = 5;
const PIN_LOCKOUT: Duration = Duration::from_secs(60);
/// Cap on remembered addresses, so a sweep of spoofed sources cannot grow this
/// map without bound. Only locked addresses survive a prune, so forgetting an
/// idle one costs nothing.
const MAX_TRACKED_ADDRS: usize = 256;

pub struct PinState {
    expected: Option<String>,
    inner: Mutex<PinInner>,
}

#[derive(Default)]
struct PinInner {
    per_addr: HashMap<IpAddr, Attempts>,
}

#[derive(Default)]
struct Attempts {
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
    /// `from` is the address the attempt came from, which is what the lockout is
    /// scoped to.
    pub fn check(&self, from: IpAddr, supplied: Option<&str>) -> Result<(), (StatusCode, String)> {
        let Some(expected) = self.expected.as_deref() else {
            return Ok(());
        };

        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();

        let attempts = inner.per_addr.entry(from).or_default();

        if let Some(until) = attempts.locked_until {
            if now < until {
                let wait = (until - now).as_secs() + 1;
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("too many attempts from {from}, retry in {wait}s"),
                ));
            }
            attempts.locked_until = None;
            attempts.failures = 0;
        }

        match supplied {
            Some(given) if ct_eq(given, expected) => {
                // A good PIN clears the slate for this address only.
                inner.per_addr.remove(&from);
                Ok(())
            }
            Some(_) => {
                attempts.failures += 1;
                if attempts.failures >= MAX_PIN_FAILURES {
                    attempts.failures = 0;
                    attempts.locked_until = Some(now + PIN_LOCKOUT);
                    let msg = format!("too many attempts from {from}, locked for 60s");
                    if inner.per_addr.len() > MAX_TRACKED_ADDRS {
                        inner.per_addr.retain(|_, a| a.locked_until.is_some());
                    }
                    Err((StatusCode::TOO_MANY_REQUESTS, msg))
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
        // A share link handed to a human lands here, in a browser.
        .route("/", get(index))
        .route(&format!("{API}/info"), get(info))
        .route(&format!("{API}/register"), post(register))
        // A sender may attach base64 previews for a whole batch; the default
        // 2 MB extractor limit rejects those before we ever see the JSON.
        .route(
            &format!("{API}/prepare-upload"),
            post(prepare_upload).layer(DefaultBodyLimit::max(32 * 1024 * 1024)),
        )
        .route(&format!("{API}/cancel"), post(cancel))
        .route(&format!("{API}/upload"), post(upload))
        .route(&format!("{API}/resume"), get(resume))
        .route(&format!("{API}/prepare-download"), post(prepare_download))
        .route(&format!("{API}/download"), get(download))
        .route(&format!("{API}/verify-download"), get(verify_download))
        // Not part of LocalSend: `sync` has to know what the other side holds,
        // and the spec has no call for that. A plain client never asks.
        .route("/api/zapsend/v1/manifest", get(manifest))
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

/// `GET /info`: who we are. Peers and `zapsend doctor` use this to tell a
/// reachable device from a wrong port, and to compare the fingerprint we
/// announced with the certificate we actually serve.
async fn info(State(state): State<Arc<AppState>>) -> Json<DeviceInfo> {
    Json(state.me.clone())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DownloadListQuery {
    #[serde(default)]
    pin: Option<String>,
    /// Offered by a browser refresh so the same session is reused.
    #[serde(default)]
    session_id: Option<String>,
}

/// `POST /prepare-download`: hand out the file list and a session id.
///
/// The spec puts no body here, and the PIN travels in the query string, which is
/// what makes `zapsend pull --pin` work against a real LocalSend share.
/// Open a download session and return its id.
///
/// Shared by `prepare-download` and the browser page: a session is what makes
/// `download` serve one listing instead of the whole share dir, and both need
/// exactly the same bookkeeping.
fn open_download_session(state: &AppState) -> String {
    let session_id = uuid::Uuid::new_v4().to_string();
    let mut live = state.downloads.lock().unwrap();
    live.retain(|_, seen| seen.elapsed() < DOWNLOAD_SESSION_TTL);
    live.insert(session_id.clone(), Instant::now());
    session_id
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    pin: Option<String>,
}

/// `GET /`: the page a browser gets from a share link.
///
/// LocalSend's app serves one, which is why a device with no LocalSend can
/// still take a file. Same listener and same PIN as everything else — no extra
/// port, and nothing is exposed unless `--share` was passed.
async fn index(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<PageQuery>,
) -> axum::response::Response {
    let Some(root) = state.share.clone() else {
        return (StatusCode::NOT_FOUND, "nothing is shared here".to_string()).into_response();
    };

    // A browser cannot send a header of our invention, so the PIN travels in the
    // query string. It ends up in the address bar and in history — the same
    // trade the LocalSend share link makes.
    if state.pin.check(addr.ip(), q.pin.as_deref()).is_err() {
        return Html(pin_form()).into_response();
    }

    let files = match walk_share(&root) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("✗ cannot read share dir {}: {e}", root.display());
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot read share dir: {e}"),
            )
                .into_response();
        }
    };
    if files.is_empty() {
        return Html(page(
            "nothing to share",
            "<p>This folder is empty.</p>",
        ))
        .into_response();
    }

    let session = open_download_session(&state);
    let mut rows: Vec<(String, u64)> = files.into_iter().map(|(k, f)| (k, f.size)).collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let total: u64 = rows.iter().map(|(_, size)| *size).sum();

    let mut body = String::new();
    for (rel, size) in &rows {
        let href = format!(
            "{API}/download?sessionId={}&fileId={}",
            session,
            urlencode(rel)
        );
        // A nested file keeps its relative path (that is what `pull` and `sync`
        // preserve), but the folder prefix is dimmed so it does not read as part
        // of the file name.
        let (dir, name) = match rel.rsplit_once('/') {
            Some((dir, name)) => (
                format!("<span class=\"d\">{}/</span>", html_escape(dir)),
                html_escape(name),
            ),
            None => (String::new(), html_escape(rel)),
        };
        body.push_str(&format!(
            "<tr><td class=\"n\"><a href=\"{href}\">{dir}{name}</a></td>\
             <td class=\"s\"><span class=\"v\">↓</span><span class=\"z\">{}</span></td></tr>",
            crate::human_bytes(*size)
        ));
    }
    // The path on disk is the operator's business, not the visitor's.
    let summary = match rows.len() {
        1 => format!("1 file, {}", crate::human_bytes(total)),
        n => format!("{n} files, {}", crate::human_bytes(total)),
    };
    Html(page(
        &summary,
        &format!("<p>{summary}</p><table>{body}</table>"),
    ))
    .into_response()
}

fn pin_form() -> String {
    page(
        "PIN required",
        r#"<p>This share is protected. Ask the owner for the PIN.</p>
<form method="get" action="/">
  <input name="pin" inputmode="numeric" autocomplete="one-time-code" placeholder="PIN" autofocus>
  <button>Open</button>
</form>"#,
    )
}

/// The page shell. Deliberately plain: it has to work in a bare browser on a
/// network with no internet, so no fonts, no scripts, no CDN.
fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>zapsend — {t}</title><style>
:root{{color-scheme:dark}}
body{{background:#0B0F10;color:#F8FAFC;font:16px/1.5 system-ui,sans-serif;margin:0;padding:24px;max-width:720px}}
h1{{font-size:18px;margin:0 0 4px;color:#20E889;font-weight:600;letter-spacing:-.01em}}
p{{margin:0 0 16px;color:#94a3b8}}
table{{width:100%;border-collapse:collapse}}
tr{{position:relative}}
td{{padding:12px 0;border-bottom:1px solid #1e293b;vertical-align:top}}
td.n{{padding-right:16px;overflow-wrap:anywhere;word-break:break-word}}
a{{color:#F8FAFC;text-decoration:none}}
tr:hover a{{color:#20E889}}
/* The whole row is the target, not just the glyphs: on a phone a 20px tall
   text link is a miss waiting to happen. */
td.n a::after{{content:"";position:absolute;inset:0}}
.d{{display:block;color:#94a3b8;font-size:13px;line-height:1.3}}
.v{{color:#334155;display:inline-block;width:1.2em;text-align:right}}
.z{{display:inline-block;min-width:5.5em;text-align:right}}
.s{{color:#94a3b8;text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums;width:1%}}
input{{background:#111827;border:1px solid #334155;color:inherit;padding:10px;border-radius:6px;width:8em;font-size:16px}}
button{{background:#20E889;color:#0B0F10;border:0;padding:10px 16px;border-radius:6px;font-weight:600;margin-left:8px;font-size:16px}}
</style></head><body><h1>zapsend</h1>{b}</body></html>"#,
        t = html_escape(title),
        b = body
    )
}

/// Minimal percent-encoding for a query value: everything outside the
/// unreserved set becomes `%XX`. `fileId` is a path, so spaces, `#` and `&` all
/// have to survive the trip.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// File names come from the filesystem and land in HTML: escape them.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

async fn prepare_download(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<DownloadListQuery>,
) -> axum::response::Response {
    let Some(root) = state.share.clone() else {
        // Not a 404: the route exists, we are simply not sharing. The spec's
        // table for this route has 403, not 404.
        return (
            StatusCode::FORBIDDEN,
            "download api is off — start the receiver with --share DIR".to_string(),
        )
            .into_response();
    };

    if let Err((code, msg)) = state.pin.check(addr.ip(), q.pin.as_deref()) {
        eprintln!("✗ rejected download list: {msg}");
        return (code, msg).into_response();
    }

    let files = match walk_share(&root) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("✗ cannot read share dir {}: {e}", root.display());
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot read share dir: {e}"),
            )
                .into_response();
        }
    };

    if files.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            format!("nothing to share in {}", root.display()),
        )
            .into_response();
    }

    let session_id = q
        .session_id
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| open_download_session(&state));

    eprintln!("→ download list: {} file(s) for {addr}", files.len());

    (
        StatusCode::OK,
        Json(PrepareDownloadResponse {
            info: state.me.clone(),
            session_id,
            files,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CancelQuery {
    session_id: Option<String>,
}

/// `POST /cancel`: the sender gave up. Dropping the session is enough — partial
/// uploads stay on disk, so a later attempt can still resume them.
async fn cancel(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CancelQuery>,
) -> StatusCode {
    if let Some(id) = q.session_id {
        state.sessions.lock().unwrap().remove(&id);
        eprintln!("✗ peer cancelled session {id}");
    }
    StatusCode::OK
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DownloadFileQuery {
    session_id: String,
    file_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyQuery {
    session_id: String,
    file_id: String,
    offset: u64,
}

/// `GET /verify-download`: the SHA-256 of the first `offset` bytes of a shared
/// file.
///
/// A resumed pull must not splice the bytes it already has with the rest of a
/// different file, and the Download API carries no checksum, so the client asks
/// the server to describe the prefix it is about to continue from. Hashing the
/// prefix costs a local read; trusting it blindly costs the file.
async fn verify_download(
    State(state): State<Arc<AppState>>,
    Query(q): Query<VerifyQuery>,
) -> axum::response::Response {
    let Some(root) = state.share.clone() else {
        return (StatusCode::NOT_FOUND, "download api is off".to_string()).into_response();
    };
    let known = {
        let mut live = state.downloads.lock().unwrap();
        live.retain(|_, seen| seen.elapsed() < DOWNLOAD_SESSION_TTL);
        live.contains_key(&q.session_id)
    };
    if !known {
        return (
            StatusCode::FORBIDDEN,
            "unknown or expired session — call prepare-download first".to_string(),
        )
            .into_response();
    }
    let Some(path) = share_path(&root, &q.file_id) else {
        return (StatusCode::NOT_FOUND, "no such file in the share".to_string()).into_response();
    };

    // Hashing can take a while on a big file, and this is an async handler.
    let probe = path.clone();
    let limit = q.offset;
    match tokio::task::spawn_blocking(move || prefix_sha256(&probe, limit)).await {
        Ok(Ok(Some(prefix_sha256))) => Json(ResumeState {
            offset: q.offset,
            prefix_sha256,
        })
        .into_response(),
        Ok(Ok(None)) => (
            StatusCode::RANGE_NOT_SATISFIABLE,
            format!("the file is shorter than {} bytes", q.offset),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot read the file: {e}"),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("the prefix check died: {e}"),
        )
            .into_response(),
    }
}

/// SHA-256 of the first `limit` bytes, or `None` when the file is shorter than
/// that. `stored_prefix` hashes everything; this one stops early.
fn prefix_sha256(path: &Path, limit: u64) -> std::io::Result<Option<String>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut left = limit;
    while left > 0 {
        let want = std::cmp::min(left, buf.len() as u64) as usize;
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            return Ok(None);
        }
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(Some(hex::encode(hasher.finalize())))
}

/// `GET /download`: stream one file from the share.
async fn download(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DownloadFileQuery>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(root) = state.share.clone() else {
        return (StatusCode::NOT_FOUND, "download api is off".to_string()).into_response();
    };

    let known = {
        let mut live = state.downloads.lock().unwrap();
        live.retain(|_, seen| seen.elapsed() < DOWNLOAD_SESSION_TTL);
        live.contains_key(&q.session_id)
    };
    if !known {
        return (
            StatusCode::FORBIDDEN,
            "unknown or expired session — call prepare-download first".to_string(),
        )
            .into_response();
    }

    let Some(path) = share_path(&root, &q.file_id) else {
        return (StatusCode::NOT_FOUND, "no such file in the share".to_string()).into_response();
    };

    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot open file: {e}"),
            )
                .into_response()
        }
    };
    let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);

    // A pull that died halfway should continue where it stopped, so honour a
    // plain `bytes=N-` range. Anything fancier (multiple ranges, suffixes) is
    // answered with the whole file, which every client understands.
    let start = match headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_range_start)
    {
        Some(start) if start < size => start,
        Some(_) => {
            return (
                StatusCode::RANGE_NOT_SATISFIABLE,
                format!("range starts at or past the end of a {size} byte file"),
            )
                .into_response()
        }
        None => 0,
    };
    if start > 0 {
        if let Err(e) = file.seek(SeekFrom::Start(start)).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot seek: {e}"),
            )
                .into_response();
        }
    }

    eprintln!(
        "→ sending {}{}",
        path.display(),
        if start > 0 {
            format!(" from byte {start}")
        } else {
            String::new()
        }
    );

    let body = Body::from_stream(ReaderStream::new(file));
    let mut resp = if start > 0 {
        (StatusCode::PARTIAL_CONTENT, body).into_response()
    } else {
        body.into_response()
    };
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Ok(len) = HeaderValue::from_str(&(size - start).to_string()) {
        headers.insert(header::CONTENT_LENGTH, len);
    }
    if start > 0 {
        if let Ok(range) = HeaderValue::from_str(&format!("bytes {start}-{}/{size}", size - 1)) {
            headers.insert(header::CONTENT_RANGE, range);
        }
    }
    resp
}

/// `bytes=N-` → N. Other range forms return None, which means "send the whole
/// file": a wrong guess about offsets is worse than a slower restart.
fn parse_range_start(raw: &str) -> Option<u64> {
    let rest = raw.trim().strip_prefix("bytes=")?;
    let (from, to) = rest.split_once('-')?;
    if !to.trim().is_empty() {
        return None;
    }
    from.trim().parse::<u64>().ok()
}

/// Every file under the share root, keyed by its path relative to that root.
///
/// Symlinks are skipped: following one would hand out a file from outside the
/// directory the user actually chose to share.
fn walk_share(root: &Path) -> std::io::Result<HashMap<String, FileMeta>> {
    let mut out = HashMap::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];

    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_SHARE_DEPTH || out.len() >= MAX_SHARE_FILES {
            break;
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                stack.push((path, depth + 1));
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let Ok(rel) = path.strip_prefix(root) else {
                continue;
            };
            let rel = rel.to_string_lossy().replace('\\', "/");
            out.insert(
                rel.clone(),
                FileMeta {
                    id: rel,
                    file_type: Some(crate::protocol::guess_mime(&name)),
                    file_name: name,
                    size: meta.len(),
                    sha256: None,
                    replace: false,
                },
            );
        }
    }
    Ok(out)
}

/// Resolve a requested file id inside the share root, or `None`.
///
/// Two layers on purpose: `safe_rel` strips `..` lexically, and the canonical
/// check catches anything that still resolves outside the root (a symlinked
/// parent directory, for instance).
fn share_path(root: &Path, file_id: &str) -> Option<PathBuf> {
    let rel = safe_rel(file_id);
    // `walk_share` hides dotfiles, so serving one by id would be an inconsistency
    // worth exploiting: `.git/config` is not in the listing but would still leak.
    if rel
        .components()
        .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
    {
        return None;
    }
    let root = root.canonicalize().ok()?;
    let full = root.join(&rel).canonicalize().ok()?;
    if !full.starts_with(&root) || !full.is_file() {
        return None;
    }
    Some(full)
}

async fn prepare_upload(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
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

    if let Err((code, msg)) = state.pin.check(addr.ip(), q.pin.as_deref()) {
        eprintln!("✗ rejected transfer: {msg}");
        return (code, msg).into_response();
    }

    // An empty list would otherwise mint a session with no files and leave the
    // sender waiting for a token that does not exist.
    if req.files.is_empty() {
        return (StatusCode::BAD_REQUEST, "no files provided".to_string()).into_response();
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
        .insert(session_id.clone(), Session { files, ip: addr.ip() });

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
    /// Byte offset this request continues from. Absent means "start over".
    #[serde(default)]
    offset: Option<u64>,
}

/// Everything the receiver already holds of one upload.
///
/// The name is derived from the file itself (name, size, checksum), not from the
/// session: a receiver that was restarted mid-transfer must find the same bytes
/// again, and the session id is long gone by then.
fn part_key(meta: &FileMeta) -> String {
    let mut hasher = Sha256::new();
    hasher.update(meta.file_name.as_bytes());
    hasher.update(meta.size.to_le_bytes());
    hasher.update(meta.sha256.as_deref().unwrap_or("").as_bytes());
    hex::encode(hasher.finalize())[..32].to_string()
}

/// Partial uploads live in a dot-directory inside the download dir: out of the
/// way, and skipped by `walk_share` if someone shares that directory.
fn part_dir(dir: &Path) -> PathBuf {
    dir.join(".zapsend-parts")
}

fn part_path(dir: &Path, meta: &FileMeta) -> PathBuf {
    part_dir(dir).join(format!("{}.part", part_key(meta)))
}

/// Bytes on disk plus the SHA-256 of exactly those bytes.
fn stored_prefix(path: &Path) -> std::io::Result<(u64, String)> {
    use std::io::Read;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, String::new())),
        Err(e) => return Err(e),
    };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((total, hex::encode(hasher.finalize())))
}

/// Session + file + token in one check, shared by `upload` and `resume`.
fn authorized(state: &AppState, q: &UploadQuery, from: std::net::IpAddr) -> Option<FileMeta> {
    let sessions = state.sessions.lock().unwrap();
    let session = sessions.get(&q.session_id)?;
    if session.ip != from {
        return None;
    }
    let (meta, token) = session.files.get(&q.file_id)?;
    if token != &q.token {
        return None;
    }
    Some(meta.clone())
}

/// A finished file's token stops working, so replaying an upload cannot write a
/// second copy under a new name.
fn consume(state: &AppState, q: &UploadQuery) {
    let mut sessions = state.sessions.lock().unwrap();
    if let Some(session) = sessions.get_mut(&q.session_id) {
        session.files.remove(&q.file_id);
    }
}

/// `GET /resume`: how far the previous attempt got.
async fn resume(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<UploadQuery>,
) -> axum::response::Response {
    let Some(meta) = authorized(&state, &q, addr.ip()) else {
        return (StatusCode::FORBIDDEN, "unknown session or file".to_string()).into_response();
    };

    let path = part_path(&state.download_dir, &meta);
    match tokio::task::spawn_blocking(move || stored_prefix(&path)).await {
        Ok(Ok((offset, prefix_sha256))) => (
            StatusCode::OK,
            Json(ResumeState {
                offset,
                prefix_sha256,
            }),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot inspect the partial file: {e}"),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot inspect the partial file: {e}"),
        )
            .into_response(),
    }
}

async fn upload(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<UploadQuery>,
    body: Body,
) -> impl IntoResponse {
    let Some(meta) = authorized(&state, &q, addr.ip()) else {
        return (StatusCode::FORBIDDEN, "unknown session or file".to_string());
    };
    let offset = q.offset.unwrap_or(0);

    let parts = part_dir(&state.download_dir);
    if let Err(e) = tokio::fs::create_dir_all(&parts).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot create the partial-upload dir: {e}"),
        );
    }

    let part = part_path(&state.download_dir, &meta);
    let stored = tokio::fs::metadata(&part).await.map(|m| m.len()).unwrap_or(0);
    if offset > stored {
        // The sender thinks we have more than we do. Refusing is the only safe
        // answer: appending there would leave a hole in the file.
        return (
            StatusCode::CONFLICT,
            format!("cannot resume at {offset}, only {stored} bytes are stored"),
        );
    }

    let mut file = match tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&part)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot open the partial file: {e}"),
            )
        }
    };
    // `set_len` both starts a fresh upload (offset 0) and drops bytes the sender
    // is not claiming, so what is on disk always matches what was acknowledged.
    if let Err(e) = file.set_len(offset).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot size the partial file: {e}"),
        );
    }
    // The open starts the cursor at 0 and `set_len` does not move it: without
    // this seek a resumed upload overwrites the stored prefix from position
    // 0 instead of appending at `offset`. The transfer still completed --
    // the sender's prefix-hash check caught the splice and restarted from
    // zero -- but every kept byte was re-sent. (Found by killing a 1 GiB
    // send mid-transfer: the partial grew to exactly the tail length
    // written from 0, and the next attempt's prefix hash mismatched.)
    if let Err(e) = file.seek(SeekFrom::Start(offset)).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot seek the partial file: {e}"),
        );
    }

    let pb = Arc::new(ProgressBar::new(meta.size));
    if let Ok(style) = ProgressStyle::with_template("{msg} [{bar:30}] {bytes}/{total_bytes}") {
        pb.set_style(style.progress_chars("=> "));
    }
    pb.set_message(meta.file_name.clone());
    pb.set_position(offset);

    let bar = pb.clone();
    // Hash the bytes as they arrive, so a fresh upload (offset 0) is verified
    // without a second full read of the file afterwards. A resumed upload
    // (offset > 0) still uses the post-upload re-read below: the stream only
    // carries the tail, not the prefix already on disk.
    let stream_hasher = Arc::new(std::sync::Mutex::new(Sha256::new()));
    let hasher = stream_hasher.clone();
    let stream = body.into_data_stream().map(move |chunk| {
        if let Ok(ref c) = chunk {
            bar.inc(c.len() as u64);
            if let Ok(mut h) = hasher.lock() {
                h.update(c);
            }
        }
        chunk
    });

    let mut reader = StreamReader::new(stream.map_err(std::io::Error::other));
    let mut out = tokio::io::BufWriter::with_capacity(256 * 1024, file);
    // copy_buf (the AsyncBufRead variant) forwards the stream's own
    // chunks with no extra allocation, so the read size is the chunk
    // size the sender used — not tokio::io::copy's 8 KiB buffer.
    let result = tokio::io::copy_buf(&mut reader, &mut out).await;
    pb.finish_and_clear();

    if let Err(e) = result {
        // Keep whatever arrived: that is the whole point of resuming.
        let kept = tokio::fs::metadata(&part).await.map(|m| m.len()).unwrap_or(offset);
        eprintln!("! {e} while receiving {} — {kept} byte(s) kept for resume", meta.file_name);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write failed: {e} (kept {kept} byte(s))"),
        );
    }
    if let Err(e) = tokio::io::AsyncWriteExt::flush(&mut out).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("flush failed: {e}"),
        );
    }
    drop(out);

    let written = tokio::fs::metadata(&part).await.map(|m| m.len()).unwrap_or(0);
    if written < meta.size {
        // A short body is a dropped connection, not an error to throw away.
        // 409, not 500: the receiver is fine, the transfer is not finished, and
        // the body says exactly where to pick it up. A 500 tells a peer the
        // server is broken, so it retries from zero instead of resuming.
        return (
            StatusCode::CONFLICT,
            format!(
                "incomplete: {written} of {} bytes stored — resume at offset {written}",
                meta.size
            ),
        );
    }

    if let Some(expected) = meta.sha256.clone() {
        // Fresh upload: the hasher above already saw every byte, so compare
        // its digest — no second read of the file. Resumed upload: the stream
        // only carried the tail, so fall back to hashing the stored file.
        let got = if offset == 0 {
            let h = stream_hasher.lock().expect("stream hasher poisoned").clone();
            Some(hex::encode(h.finalize()))
        } else {
            let probe = part.clone();
            match tokio::task::spawn_blocking(move || stored_prefix(&probe)).await {
                Ok(Ok((_, got))) => Some(got),
                _ => None,
            }
        };
        match got {
            Some(got) if got.eq_ignore_ascii_case(&expected) => {}
            Some(got) => {
                let _ = tokio::fs::remove_file(&part).await;
                eprintln!("✗ checksum mismatch for {} — discarded", meta.file_name);
                // The spec asks for 422 here, not 500: the request was fine,
                // the bytes were not.
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("checksum mismatch: sender said {expected}, we computed {got}"),
                );
            }
            None => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "cannot verify the received file".to_string(),
                );
            }
        }
    }

    // A replace upload lands on the exact path, not `name (1).ext` — but only
    // after the bytes were hash-verified above. Anything else keeps the
    // never-clobber behaviour.
    let path = if meta.replace {
        state.download_dir.join(safe_rel(&meta.file_name))
    } else {
        unique_path(&state.download_dir, &meta.file_name)
    };
    if let Some(parent) = path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot create folder {}: {e}", parent.display()),
            );
        }
    }
    if meta.replace {
        if let Err(e) = place_replacement(&state.download_dir, &path, &part).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, e);
        }
    } else if let Err(e) = tokio::fs::rename(&part, &path).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("cannot move the finished file into place: {e}"),
        );
    }

    consume(&state, &q);
    eprintln!("✓ saved {}", path.display());
    (StatusCode::OK, String::new())
}

/// Move a hash-verified replacement into place: the file already there is
/// moved aside first, and only deleted once the new file is in place. A
/// failed rename restores the old file, so a replace never loses bytes it
/// cannot prove it replaced. Backups live under a dot-directory, which
/// `list_tree` (and therefore the manifest) never reports.
async fn place_replacement(dir: &Path, target: &Path, part: &Path) -> Result<(), String> {
    if !target.exists() {
        return tokio::fs::rename(part, target)
            .await
            .map_err(|e| format!("cannot move the finished file into place: {e}"));
    }
    let backup = replaced_backup_path(dir, target);
    if let Some(parent) = backup.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("cannot create the backup folder: {e}"))?;
    }
    tokio::fs::rename(target, &backup)
        .await
        .map_err(|e| format!("cannot move the old file aside: {e}"))?;
    if let Err(e) = tokio::fs::rename(part, target).await {
        let _ = tokio::fs::rename(&backup, target).await;
        return Err(format!(
            "cannot move the finished file into place: {e} (the old file was restored)"
        ));
    }
    let _ = tokio::fs::remove_file(&backup).await;
    Ok(())
}

/// `.zapsend-replaced/<relative path>.<nanos>` — unique per replace, and
/// dot-prefixed so it never shows up in a manifest or a share listing.
fn replaced_backup_path(dir: &Path, target: &Path) -> PathBuf {
    let rel = target.strip_prefix(dir).unwrap_or(target);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    dir.join(".zapsend-replaced")
        .join(format!("{}.{nanos}", rel.display()))
}

/// Never silently clobber an existing file: `a.txt` -> `a (1).txt`, and keep
/// the folder part a peer sent (`holiday/img.jpg`) instead of flattening it.
#[derive(Deserialize)]
struct ManifestQuery {
    pin: Option<String>,
}

/// `GET /manifest`: what this receiver already holds, keyed by the relative path
/// a sender would use. Costs one read of the whole receive folder, which is the
/// honest price of not re-sending everything.
async fn manifest(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<ManifestQuery>,
) -> impl IntoResponse {
    if let Err((code, msg)) = state.pin.check(addr.ip(), q.pin.as_deref()) {
        return (code, msg).into_response();
    }
    let root = state.download_dir.clone();
    let files = tokio::task::spawn_blocking(move || list_tree(&root))
        .await
        .unwrap_or_default();
    (StatusCode::OK, Json(serde_json::json!({ "files": files }))).into_response()
}

fn list_tree(root: &Path) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut out = std::collections::BTreeMap::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Dot entries are our own bookkeeping (partial uploads, .sent).
            if name.starts_with('.') {
                continue;
            }
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            // `file_type` does not follow symlinks: a link to a parent would walk
            // forever, and a link out of the tree would answer for files the user
            // never received.
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                stack.push((entry.path(), rel));
                continue;
            }
            let Ok((size, sha)) = stored_prefix(&entry.path()) else {
                continue;
            };
            out.insert(rel, serde_json::json!({ "size": size, "sha256": sha }));
        }
    }
    out
}

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

    #[test]
    fn pin_lockout_is_per_address_not_global() {
        use std::net::Ipv4Addr;
        let pin = PinState::new(Some("123456".into()));
        let attacker = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 66));
        let owner = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        for _ in 0..MAX_PIN_FAILURES {
            assert!(pin.check(attacker, Some("000000")).is_err());
        }
        // The attacker is locked...
        let (code, _) = pin.check(attacker, Some("123456")).unwrap_err();
        assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);

        // ...but the owner's phone is not, and a correct PIN still works.
        assert!(pin.check(owner, Some("123456")).is_ok());
    }

    #[test]
    fn right_pin_clears_earlier_failures_for_that_address() {
        use std::net::Ipv4Addr;
        let pin = PinState::new(Some("123456".into()));
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));

        for _ in 0..(MAX_PIN_FAILURES - 1) {
            assert!(pin.check(addr, Some("111111")).is_err());
        }
        assert!(pin.check(addr, Some("123456")).is_ok());
        // A fresh run of mistakes must not trip the lockout early.
        for _ in 0..(MAX_PIN_FAILURES - 1) {
            assert!(pin.check(addr, Some("111111")).is_err());
        }
        assert!(pin.check(addr, Some("123456")).is_ok());
    }

    #[test]
    fn share_paths_cannot_escape_the_shared_dir() {
        let root = std::env::temp_dir().join(format!("zapsend-share-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/ok.txt"), b"hi").unwrap();
        std::fs::write(root.join("top.txt"), b"top").unwrap();

        assert!(share_path(&root, "sub/ok.txt").is_some());
        assert!(share_path(&root, "top.txt").is_some());
        assert!(share_path(&root, "../../etc/passwd").is_none());
        assert!(share_path(&root, "sub/../../etc/passwd").is_none());
        assert!(share_path(&root, "missing.txt").is_none());
        // A directory is not something to stream.
        assert!(share_path(&root, "sub").is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn walk_share_lists_nested_files_and_skips_dotfiles() {
        let root = std::env::temp_dir().join(format!("zapsend-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("a.txt"), b"a").unwrap();
        std::fs::write(root.join("nested/b.txt"), b"bb").unwrap();
        std::fs::write(root.join(".hidden"), b"x").unwrap();

        let files = walk_share(&root).unwrap();
        assert!(files.contains_key("a.txt"));
        assert!(files.contains_key("nested/b.txt"));
        assert!(!files.contains_key(".hidden"));
        assert_eq!(files.len(), 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn partial_upload_key_follows_the_file_identity() {
        let a = FileMeta {
            id: "0".to_string(),
            file_name: "a.bin".to_string(),
            size: 10,
            file_type: None,
            sha256: Some("aa".to_string()),
            replace: false,
        };
        let mut other = a.clone();
        other.sha256 = Some("bb".to_string());

        assert_eq!(part_key(&a), part_key(&a.clone()));
        assert_ne!(part_key(&a), part_key(&other));
        let mut bigger = a.clone();
        bigger.size = 11;
        assert_ne!(part_key(&a), part_key(&bigger));
    }

    #[test]
    fn range_parsing_only_trusts_the_open_ended_form() {
        assert_eq!(parse_range_start("bytes=100-"), Some(100));
        assert_eq!(parse_range_start("bytes=0-"), Some(0));
        // Anything we would have to guess at is answered with the whole file.
        assert_eq!(parse_range_start("bytes=0-99"), None);
        assert_eq!(parse_range_start("bytes=-100"), None);
        assert_eq!(parse_range_start("items=0-"), None);
        assert_eq!(parse_range_start("bytes=abc-"), None);
    }

    #[test]
    fn prefix_sha256_hashes_exactly_the_prefix() {
        let path = std::env::temp_dir().join(format!("zapsend-prefix-{}.bin", std::process::id()));
        std::fs::write(&path, b"abcdefghij").unwrap();
        let got = prefix_sha256(&path, 4).unwrap().unwrap();
        let mut h = Sha256::new();
        h.update(b"abcd");
        assert_eq!(got, hex::encode(h.finalize()));
        // Longer than the file: nothing to describe.
        assert!(prefix_sha256(&path, 11).unwrap().is_none());
        assert!(prefix_sha256(&path, 10).unwrap().is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stored_prefix_of_a_missing_partial_is_zero() {
        let path = std::env::temp_dir().join("zapsend-definitely-not-here.part");
        let _ = std::fs::remove_file(&path);
        let (offset, hash) = stored_prefix(&path).unwrap();
        assert_eq!(offset, 0);
        assert!(hash.is_empty());
    }
}

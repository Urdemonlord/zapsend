//! The sending side: prepare-upload, then stream the bytes.
//!
//! TLS is pinned to the peer's certificate fingerprint. LocalSend hands the
//! fingerprint out during discovery, so we never have to trust the network:
//! the certificate the peer presents must hash to exactly that value.

use crate::protocol::{
    DeviceInfo, FileMeta, Peer, PrepareDownloadResponse, PrepareUploadRequest, PrepareUploadResponse,
    ResumeState, API,
};
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_util::io::ReaderStream;

/// Accepts exactly one certificate: the one whose SHA-256 matches `expected`.
#[derive(Debug)]
struct PinnedVerifier {
    expected: Vec<u8>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let got = Sha256::digest(end_entity.as_ref());
        if got.as_slice() == self.expected.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "certificate fingerprint mismatch: expected {}, got {}",
                hex::encode(&self.expected),
                hex::encode(got)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn pinned_client(fingerprint_hex: &str) -> Result<reqwest::Client> {
    let expected = hex::decode(fingerprint_hex).context("fingerprint is not valid hex")?;
    if expected.len() != 32 {
        bail!(
            "fingerprint must be 64 hex characters (32 bytes), got {} characters",
            fingerprint_hex.len()
        );
    }

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { expected }))
        .with_no_client_auth();

    Ok(reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .connect_timeout(std::time::Duration::from_secs(10))
        // ponytail: a total `.timeout()` bounds the whole request, so any
        // transfer longer than the bound dies mid-flight — a 300 MB file at
        // 5 MB/s over Tailscale is 60 s. `read_timeout` is per-read inactivity:
        // a peer that stops sending still fails, a slow one does not.
        .read_timeout(std::time::Duration::from_secs(60))
        .build()?)
}

/// Only for peers whose fingerprint we do not know (plain `--ip` without
/// `--fingerprint`). Everything discovered over multicast is pinned.
fn unpinned_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .connect_timeout(std::time::Duration::from_secs(10))
        // Same reasoning as `pinned_client`: bound inactivity, not duration.
        .read_timeout(std::time::Duration::from_secs(60))
        .build()?)
}

struct Pending {
    id: String,
    path: PathBuf,
    name: String,
    size: u64,
}

/// Send, retrying once over the other scheme when the peer refuses our TLS.
///
/// LocalSend v2 lets a device advertise `protocol: http | https`, and phones
/// commonly serve plain HTTP. A `--ip` target has no announcement to read that
/// field from, so we probe: one failed handshake is cheaper than asking the
/// user to discover a flag they cannot see.
/// One file to upload: the local path, and the name the peer will see. A name
/// may carry `/` separators to land inside a folder on the receiver.
pub struct Upload {
    pub path: PathBuf,
    pub name: String,
}

/// Read a peer's own `info` document, the way `doctor` proves a device is
/// reachable. Tries the advertised scheme first and the other one once, because
/// a `--ip` target has no announcement telling us whether it serves HTTP or
/// HTTPS.
pub async fn fetch_info(peer: &Peer) -> Result<DeviceInfo> {
    let http = peer_client(peer)?;

    let mut tried: Vec<String> = Vec::new();
    for scheme in [peer.info.protocol.as_str(), other_scheme(&peer.info.protocol)] {
        let url = format!("{scheme}://{}:{}{API}/info", peer.ip, peer.info.port);
        match http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body = resp.bytes().await?;
                return serde_json::from_slice(&body)
                    .with_context(|| format!("peer answered {url} with something that is not info"));
            }
            Ok(resp) => {
                let code = resp.status();
                let body = resp.text().await.unwrap_or_default();
                let snippet: String = body.chars().take(120).collect();
                tried.push(format!("{url} → {code} {snippet}"));
            }
            Err(e) => tried.push(format!("{url} → {e}")),
        }
    }
    bail!("no info from the peer: {}", tried.join("; "))
}

fn other_scheme(scheme: &str) -> &'static str {
    if scheme.eq_ignore_ascii_case("http") {
        "https"
    } else {
        "http"
    }
}

/// A client that trusts exactly this peer: its pinned certificate when we know
/// the fingerprint, otherwise anything (a `--ip` target has no announcement to
/// compare against, so the caller is told it is unverified).
/// Answer an announcement the way the spec asks: one `POST /register` at the
/// origin, so the peer learns about us now instead of at our next announce.
/// Best effort — a peer that does not answer costs nothing.
pub async fn register_back(peer: &Peer, me: &DeviceInfo) -> Result<()> {
    let http = peer_client(peer)?;
    let url = format!("{}{API}/register", peer.base_url());
    let resp = http.post(&url).json(me).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("register answered {}", resp.status()));
    }
    Ok(())
}

fn peer_client(peer: &Peer) -> Result<reqwest::Client> {
    if peer.info.fingerprint.is_empty() {
        unpinned_client()
    } else {
        pinned_client(&peer.info.fingerprint)
    }
}

/// Percent-encode a query value. File ids are relative paths and may contain
/// spaces, `&`, `#` or non-ASCII names, all of which would otherwise corrupt the
/// request line.
fn encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Ask a peer that offers the Download API for its file list.
pub async fn prepare_download(
    peer: &Peer,
    pin: Option<&str>,
) -> Result<(String, HashMap<String, FileMeta>)> {
    let http = peer_client(peer)?;
    let mut url = format!("{}{API}/prepare-download", peer.base_url());
    if let Some(pin) = pin {
        url.push_str(&format!("?pin={}", encode_query(pin)));
    }

    let resp = http.post(&url).send().await?;
    let status = resp.status();
    let body = resp.bytes().await?;
    if !status.is_success() {
        let snippet: String = String::from_utf8_lossy(&body).chars().take(200).collect();
        bail!("peer refused the download list: {status} {snippet}");
    }

    let parsed: PrepareDownloadResponse = serde_json::from_slice(&body)
        .context("peer answered prepare-download with something that is not a file list")?;
    Ok((parsed.session_id, parsed.files))
}

/// Pull one file into `dest`, verifying the SHA-256 when the peer published one.
/// Download one file, continuing a `.part` left behind by an earlier attempt.
///
/// The bytes on disk are trusted only after the whole file's SHA-256 matches what
/// the peer advertised, so a resumed download can never splice two different
/// files together — the worst case is a restart.
pub async fn download_file(
    peer: &Peer,
    session_id: &str,
    file: &FileMeta,
    dest: &Path,
    // Bytes that actually crossed the wire, accumulated by the caller across
    // retries and files. Distinct from the file size: a resumed download moves
    // fewer bytes than it ends up holding, and a broken attempt still cost some.
    wire: &mut u64,
) -> Result<u64> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let part = part_path(dest);
    let mut have = tokio::fs::metadata(&part)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    if have > file.size {
        // Bigger than the file cannot be ours: someone else's leftovers.
        let _ = tokio::fs::remove_file(&part).await;
        have = 0;
    }

    let mut written = have;
    if have != file.size || file.size == 0 {
        let http = peer_client(peer)?;
        let url = format!(
            "{}{API}/download?sessionId={}&fileId={}",
            peer.base_url(),
            encode_query(session_id),
            encode_query(&file.id)
        );

        // Never splice our bytes onto a file we cannot recognise: ask the peer
        // to hash the prefix we already hold. A peer that cannot answer (a plain
        // LocalSend app has no such route) gets a fresh download instead.
        if have > 0 {
            match verified_prefix(&http, &peer.base_url(), session_id, &file.id, &part, have).await {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!(
                        "  {} does not match the peer's copy at byte {have} — starting over",
                        file.file_name
                    );
                    let _ = tokio::fs::remove_file(&part).await;
                    have = 0;
                    written = 0;
                }
                Err(e) => {
                    eprintln!(
                        "  cannot verify the partial of {} ({e}) — starting over",
                        file.file_name
                    );
                    let _ = tokio::fs::remove_file(&part).await;
                    have = 0;
                    written = 0;
                }
            }
        }

        let mut req = http.get(&url);
        if have > 0 {
            req = req.header(reqwest::header::RANGE, format!("bytes={have}-"));
            eprintln!(
                "  resuming {} at {} of {}",
                file.file_name,
                crate::human_bytes(have),
                crate::human_bytes(file.size)
            );
        }
        let resp = req.send().await?;
        let status = resp.status();

        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            // Appending, `have` is what the server sent us from.
        } else if status.is_success() {
            if have > 0 {
                eprintln!(
                    "  peer sent the whole file instead of the rest — starting {} over",
                    file.file_name
                );
            }
            have = 0;
            written = 0;
        } else {
            let body = resp.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(200).collect();
            bail!(
                "peer refused {status} for \"{}\": {snippet}",
                file.file_name
            );
        }

        let mut out = if have > 0 {
            tokio::fs::OpenOptions::new()
                .append(true)
                .open(&part)
                .await?
        } else {
            tokio::fs::File::create(&part).await?
        };
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            tokio::io::AsyncWriteExt::write_all(&mut out, &chunk).await?;
            written += chunk.len() as u64;
            *wire += chunk.len() as u64;
        }
        tokio::io::AsyncWriteExt::flush(&mut out).await?;
    }

    if file.size != 0 && written != file.size {
        // Keep the partial on purpose: the next attempt continues from here.
        bail!(
            "short read for \"{}\": expected {} bytes, have {written} (kept for resume)",
            file.file_name,
            file.size
        );
    }
    if let Some(expected) = file.sha256.as_deref() {
        let got = sha256_file(&part)?;
        if !got.eq_ignore_ascii_case(expected) {
            let _ = tokio::fs::remove_file(&part).await;
            bail!(
                "checksum mismatch for \"{}\": peer said {expected}, we got {got} (partial discarded)",
                file.file_name
            );
        }
    }

    tokio::fs::rename(&part, dest).await?;
    Ok(written)
}

/// Does the first `have` bytes of `part` match what the peer has at that point?
async fn verified_prefix(
    http: &reqwest::Client,
    base: &str,
    session_id: &str,
    file_id: &str,
    part: &Path,
    have: u64,
) -> Result<bool> {
    let url = format!(
        "{base}{API}/verify-download?sessionId={}&fileId={}&offset={have}",
        encode_query(session_id),
        encode_query(file_id)
    );
    let resp = http.get(&url).send().await?;
    if !resp.status().is_success() {
        bail!("peer answered {}", resp.status());
    }
    let state: crate::protocol::ResumeState = resp.json().await?;
    let mine = sha256_prefix(part, have)?;
    Ok(mine.eq_ignore_ascii_case(&state.prefix_sha256))
}

/// `<dest>.part` — next to the target, so the resume survives a restart and a
/// half file never looks like a finished one.
fn part_path(dest: &Path) -> PathBuf {
    let mut name = dest
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".part");
    dest.with_file_name(name)
}

pub async fn send_files(
    peer: &Peer,
    me: &DeviceInfo,
    uploads: &[Upload],
    pin: Option<&str>,
    retries: u32,
) -> Result<()> {
    match send_files_over(peer, me, uploads, pin, retries).await {
        Err(e) if looks_like_scheme_mismatch(&e) => {
            let mut flipped = peer.clone();
            flipped.info.protocol = if peer.info.protocol.eq_ignore_ascii_case("http") {
                "https".to_string()
            } else {
                "http".to_string()
            };
            eprintln!(
                "! {} did not answer over {} — retrying over {}",
                peer.ip, peer.info.protocol, flipped.info.protocol
            );
            send_files_over(&flipped, me, uploads, pin, retries).await
        }
        other => other,
    }
}

/// The receiver forgot our session (it restarted, or the session aged out).
/// Retrying the same token is pointless; the caller prepares again.
#[derive(Debug)]
struct SessionGone;

impl std::fmt::Display for SessionGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the receiver no longer knows this session")
    }
}

impl std::error::Error for SessionGone {}

async fn prepare_upload(
    http: &reqwest::Client,
    base: &str,
    me: &DeviceInfo,
    pin: Option<&str>,
    files: HashMap<String, FileMeta>,
) -> Result<PrepareUploadResponse> {
    let endpoint = match pin {
        Some(p) => format!("{base}{API}/prepare-upload?pin={p}"),
        None => format!("{base}{API}/prepare-upload"),
    };
    let payload = serde_json::to_vec(&PrepareUploadRequest {
        info: Some(me.clone()),
        files,
    })?;
    crate::verbose::dump("→", "prepare-upload", &payload);

    let resp = http
        .post(endpoint)
        .header("content-type", "application/json")
        .body(payload)
        .send()
        .await
        .map_err(|e| {
            // Surface a pinning failure as a pinning failure, not as a
            // generic connection error three layers deep.
            let err = anyhow::Error::new(e);
            let chain = format!("{err:#}");
            if chain.contains("fingerprint mismatch") {
                anyhow::anyhow!(
                    "TLS pinning failed — the peer presented a different certificate than the one you pinned\n  {chain}"
                )
            } else {
                err.context("prepare-upload request failed")
            }
        })?;

    if !resp.status().is_success() {
        let code = resp.status();
        let body = resp.text().await.unwrap_or_default();
        match code {
            reqwest::StatusCode::UNAUTHORIZED => match pin {
                Some(_) => bail!("the receiver rejected the PIN: {body}"),
                None => {
                    bail!("this receiver requires a PIN — retry with --pin <digits>\n  ({body})")
                }
            },
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                bail!("too many attempts, wait a minute: {body}")
            }
            reqwest::StatusCode::FORBIDDEN => {
                bail!("the receiver declined the transfer: {body}")
            }
            _ => bail!("receiver rejected the transfer ({code}): {body}"),
        }
    }

    resp.json().await.context("bad prepare-upload body")
}

/// How many bytes of this file the receiver already has, or 0.
///
/// The offset alone is not enough: it must be the *same* file. The receiver
/// sends the SHA-256 of its prefix and we compare it with ours, so a file that
/// changed on disk restarts instead of being spliced into a corrupt whole.
async fn stored_offset(http: &reqwest::Client, url: &str, item: &Pending) -> u64 {
    let Ok(resp) = http.get(url).send().await else {
        return 0;
    };
    if !resp.status().is_success() {
        return 0;
    }
    let Ok(state) = resp.json::<ResumeState>().await else {
        return 0;
    };
    if state.offset == 0 || state.offset > item.size {
        return 0;
    }

    let path = item.path.clone();
    let offset = state.offset;
    let Ok(Ok(local)) = tokio::task::spawn_blocking(move || sha256_prefix(&path, offset)).await
    else {
        return 0;
    };

    if local.eq_ignore_ascii_case(&state.prefix_sha256) {
        offset
    } else {
        // Safe but blunt: the receiver holds a partial that is not a prefix of
        // this file (a stale `.part` from an earlier run, or the file changed).
        // There is no endpoint to drop it, so start over and let `set_len` reset it.
        eprintln!(
            "! {} — the partial the receiver kept is not this file, starting over",
            item.name
        );
        0
    }
}

#[allow(clippy::too_many_arguments)]
async fn upload_once(
    http: &reqwest::Client,
    base: &str,
    prepared: &PrepareUploadResponse,
    item: &Pending,
    offset: u64,
    pb: &Arc<ProgressBar>,
    overall: &ProgressBar,
    finished: u64,
) -> Result<()> {
    let token = prepared
        .files
        .get(&item.id)
        .with_context(|| format!("receiver did not return a token for {}", item.name))?;

    let url = format!(
        "{base}{API}/upload?sessionId={}&fileId={}&token={}&offset={offset}",
        encode_query(&prepared.session_id),
        encode_query(&item.id),
        encode_query(&token)
    );

    let mut file = tokio::fs::File::open(&item.path).await?;
    if offset > 0 {
        tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(offset)).await?;
    }
    pb.set_position(offset);
    overall.set_position(finished + offset);

    let bar = pb.clone();
    let done = overall.clone();
    let stream = ReaderStream::new(file).map(move |chunk| {
        if let Ok(ref c) = chunk {
            bar.inc(c.len() as u64);
            done.inc(c.len() as u64);
        }
        chunk
    });

    let resp = http
        .post(&url)
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .map_err(|e| anyhow::Error::new(e).context(format!("upload failed for {}", item.name)))?;
    pb.finish_and_clear();

    if !resp.status().is_success() {
        let code = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if code == reqwest::StatusCode::FORBIDDEN {
            return Err(anyhow::Error::new(SessionGone).context(body));
        }
        bail!("upload rejected for {} ({code}): {body}", item.name);
    }
    Ok(())
}

/// SHA-256 of the first `limit` bytes, so a resumed upload can prove it is
/// appending to the same file the receiver kept.
fn sha256_prefix(path: &Path, limit: u64) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut left = limit;
    while left > 0 {
        let want = buf.len().min(left as usize);
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(hex::encode(hasher.finalize()))
}

fn looks_like_scheme_mismatch(e: &anyhow::Error) -> bool {
    let msg = format!("{e:#}").to_lowercase();
    msg.contains("invalidcontenttype")
        || msg.contains("corrupt message")
        || msg.contains("handshake failure")
        || msg.contains("received corrupt message")
}

async fn send_files_over(
    peer: &Peer,
    me: &DeviceInfo,
    uploads: &[Upload],
    pin: Option<&str>,
    retries: u32,
) -> Result<()> {
    if uploads.is_empty() {
        bail!("no files to send");
    }

    let mut pending = Vec::new();
    for (idx, upload) in uploads.iter().enumerate() {
        let meta = std::fs::metadata(&upload.path)
            .with_context(|| format!("cannot read {}", upload.path.display()))?;
        pending.push(Pending {
            id: idx.to_string(),
            path: upload.path.clone(),
            name: upload.name.clone(),
            size: meta.len(),
        });
    }

    let spinner = ProgressBar::new_spinner();
    spinner.set_message("hashing…");
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    let mut files = HashMap::new();
    for item in &pending {
        let path = item.path.clone();
        let sha = tokio::task::spawn_blocking(move || sha256_file(&path)).await??;
        files.insert(
            item.id.clone(),
            FileMeta {
                id: item.id.clone(),
                file_name: item.name.clone(),
                size: item.size,
                file_type: Some(mime_for(&item.name)),
                sha256: Some(sha),
            },
        );
    }
    spinner.finish_and_clear();

    let http = peer_client(peer)?;
    let base = peer.base_url();
    let mut prepared = prepare_upload(&http, &base, me, pin, files.clone()).await?;

    let total: u64 = pending.iter().map(|p| p.size).sum();
    let overall = ProgressBar::new(total);
    if let Ok(style) =
        ProgressStyle::with_template("{msg}\n[{bar:32}] {bytes}/{total_bytes} overall ({eta})")
    {
        overall.set_style(style.progress_chars("=> "));
    }
    overall.set_message(format!("{} file(s)", pending.len()));

    // Only zapsend receivers advertise this. Real LocalSend peers get the plain
    // upload, and a retry simply starts the file again.
    let can_resume = peer.info.zapsend_resume;
    let mut finished = 0u64;

    for item in &pending {
        let mut attempt = 0u32;
        loop {
            attempt += 1;

            // Ask what the receiver already has, on every attempt — that is also
            // what makes a *new* `send` pick up bytes an earlier run left behind.
            let offset = if can_resume {
                let token = prepared.files.get(&item.id).map(|t| t.as_str()).unwrap_or("");
                let url = format!(
                    "{base}{API}/resume?sessionId={}&fileId={}&token={}",
                    prepared.session_id, item.id, token
                );
                stored_offset(&http, &url, item).await
            } else {
                0
            };
            if offset > 0 {
                eprintln!(
                    "↻ {} — receiver already has {}, resuming",
                    item.name,
                    crate::human_bytes(offset)
                );
            }

            let pb = Arc::new(ProgressBar::new(item.size));
            if let Ok(style) =
                ProgressStyle::with_template("{msg} [{bar:24}] {bytes}/{total_bytes} ({eta})")
            {
                pb.set_style(style.progress_chars("=> "));
            }
            pb.set_message(item.name.clone());

            match upload_once(&http, &base, &prepared, item, offset, &pb, &overall, finished).await {
                Ok(()) => {
                    finished += item.size;
                    break;
                }
                Err(e) => {
                    if attempt > retries {
                        bail!("{} failed after {attempt} attempt(s): {e:#}", item.name);
                    }
                    if e.downcast_ref::<SessionGone>().is_some() {
                        eprintln!("! receiver restarted — preparing the transfer again");
                        prepared = prepare_upload(&http, &base, me, pin, files.clone()).await?;
                    } else {
                        eprintln!("! {} interrupted: {e:#}", item.name);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                }
            }
        }
    }

    overall.finish_and_clear();
    Ok(())
}

/// `fileType` is mandatory in the receiver's schema — LocalSend's `FileDto`
/// has no default for it, so omitting the field makes the whole request fail to
/// parse and the peer answers `400 Invalid JSON body`.
///
/// ponytail: a short extension table; swap in `mime_guess` if exotic types start
/// mattering (only the receiver's icon/preview choice depends on this).
fn mime_for(name: &str) -> String {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mime = match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "zip" => "application/zip",
        "apk" => "application/vnd.android.package-archive",
        _ => "application/octet-stream",
    };
    mime.to_string()
}

fn sha256_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

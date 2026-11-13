//! The sending side: prepare-upload, then stream the bytes.

use crate::protocol::{
    DeviceInfo, FileMeta, Peer, PrepareUploadRequest, PrepareUploadResponse, API,
};
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio_util::io::ReaderStream;

fn client() -> Result<reqwest::Client> {
    // LocalSend uses self-signed certs pinned by fingerprint. For v0.0.1 we
    // accept any cert; TODO: verify the peer fingerprint we got from discovery.
    Ok(reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}

pub async fn send_file(peer: &Peer, me: &DeviceInfo, path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("no such file: {}", path.display());
    }

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid file name")?
        .to_string();
    let size = std::fs::metadata(path)?.len();

    let spinner = ProgressBar::new_spinner();
    spinner.set_message("hashing…");
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    let hash_path = path.to_path_buf();
    let sha256 = tokio::task::spawn_blocking(move || sha256_file(&hash_path)).await??;
    spinner.finish_and_clear();

    let file_id = "0".to_string();
    let mut files = HashMap::new();
    files.insert(
        file_id.clone(),
        FileMeta {
            id: file_id.clone(),
            file_name: file_name.clone(),
            size,
            file_type: None,
            sha256: Some(sha256),
        },
    );

    let http = client()?;
    let base = peer.base_url();

    let resp = http
        .post(format!("{base}{API}/prepare-upload"))
        .json(&PrepareUploadRequest {
            info: me.clone(),
            files,
        })
        .send()
        .await
        .context("prepare-upload request failed")?;

    if !resp.status().is_success() {
        let code = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("receiver rejected the transfer ({code}): {body}");
    }

    let prepared: PrepareUploadResponse = resp.json().await.context("bad prepare-upload body")?;
    let token = prepared
        .files
        .get(&file_id)
        .context("receiver did not return a token for our file")?
        .clone();

    let url = format!(
        "{base}{API}/upload?sessionId={}&fileId={}&token={}",
        prepared.session_id, file_id, token
    );

    let file = tokio::fs::File::open(path).await?;
    let pb = Arc::new(ProgressBar::new(size));
    if let Ok(style) =
        ProgressStyle::with_template("{msg} [{bar:30}] {bytes}/{total_bytes} ({eta})")
    {
        pb.set_style(style.progress_chars("=> "));
    }
    pb.set_message(file_name.clone());

    let bar = pb.clone();
    let stream = ReaderStream::new(file).map(move |chunk| {
        if let Ok(ref c) = chunk {
            bar.inc(c.len() as u64);
        }
        chunk
    });

    let resp = http
        .post(&url)
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .context("upload failed")?;
    pb.finish_and_clear();

    if !resp.status().is_success() {
        let code = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("upload rejected ({code}): {body}");
    }

    Ok(())
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

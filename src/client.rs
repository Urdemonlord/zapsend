//! The sending side: prepare-upload, then stream the bytes.
//!
//! TLS is pinned to the peer's certificate fingerprint. LocalSend hands the
//! fingerprint out during discovery, so we never have to trust the network:
//! the certificate the peer presents must hash to exactly that value.

use crate::protocol::{
    DeviceInfo, FileMeta, Peer, PrepareUploadRequest, PrepareUploadResponse, API,
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
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}

/// Only for peers whose fingerprint we do not know (plain `--ip` without
/// `--fingerprint`). Everything discovered over multicast is pinned.
fn unpinned_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}

struct Pending {
    id: String,
    path: PathBuf,
    name: String,
    size: u64,
}

pub async fn send_files(
    peer: &Peer,
    me: &DeviceInfo,
    paths: &[PathBuf],
    pin: Option<&str>,
) -> Result<()> {
    if paths.is_empty() {
        bail!("no files to send");
    }

    let mut pending = Vec::new();
    for (idx, path) in paths.iter().enumerate() {
        let meta =
            std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
        if meta.is_dir() {
            bail!(
                "{} is a directory — folder transfer is not implemented yet",
                path.display()
            );
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .with_context(|| format!("invalid file name: {}", path.display()))?
            .to_string();
        pending.push(Pending {
            id: idx.to_string(),
            path: path.clone(),
            name,
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
                file_type: None,
                sha256: Some(sha),
            },
        );
    }
    spinner.finish_and_clear();

    let http = if peer.info.fingerprint.is_empty() {
        eprintln!("! no fingerprint for this peer — TLS certificate is NOT verified");
        unpinned_client()?
    } else {
        pinned_client(&peer.info.fingerprint)?
    };

    let base = peer.base_url();
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

    let prepared: PrepareUploadResponse = resp.json().await.context("bad prepare-upload body")?;

    let total: u64 = pending.iter().map(|p| p.size).sum();
    let overall = ProgressBar::new(total);
    if let Ok(style) =
        ProgressStyle::with_template("{msg}\n[{bar:32}] {bytes}/{total_bytes} overall ({eta})")
    {
        overall.set_style(style.progress_chars("=> "));
    }
    overall.set_message(format!("{} file(s)", pending.len()));

    for item in &pending {
        let token = prepared
            .files
            .get(&item.id)
            .with_context(|| format!("receiver did not return a token for {}", item.name))?;

        let url = format!(
            "{base}{API}/upload?sessionId={}&fileId={}&token={}",
            prepared.session_id, item.id, token
        );

        let file = tokio::fs::File::open(&item.path).await?;
        let pb = Arc::new(ProgressBar::new(item.size));
        if let Ok(style) =
            ProgressStyle::with_template("{msg} [{bar:24}] {bytes}/{total_bytes} ({eta})")
        {
            pb.set_style(style.progress_chars("=> "));
        }
        pb.set_message(item.name.clone());

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
            .with_context(|| format!("upload failed for {}", item.name))?;
        pb.finish_and_clear();

        if !resp.status().is_success() {
            let code = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("upload rejected for {} ({code}): {body}", item.name);
        }
    }

    overall.finish_and_clear();
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

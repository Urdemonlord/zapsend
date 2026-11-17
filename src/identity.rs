//! Device identity: a self-signed certificate plus its SHA-256 fingerprint.
//!
//! LocalSend authenticates peers by pinning the certificate fingerprint instead
//! of relying on a CA chain, so we generate one cert on first run and reuse it.

use crate::protocol::{DeviceInfo, PROTOCOL_VERSION};
use anyhow::{Context, Result};
use rcgen::generate_simple_self_signed;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
    /// Lowercase hex SHA-256 of the DER certificate.
    pub fingerprint: String,
}

/// Where we keep the cert. `~/.local/share/zapsend` on Linux, AppData on Windows.
pub fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zapsend")
}

pub fn load_or_create(alias: &str, port: u16) -> Result<(Identity, DeviceInfo)> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir).context("creating data directory")?;

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let fp_path = dir.join("fingerprint");

    let identity = if cert_path.exists() && key_path.exists() && fp_path.exists() {
        Identity {
            cert_pem: std::fs::read_to_string(&cert_path)?,
            key_pem: std::fs::read_to_string(&key_path)?,
            fingerprint: std::fs::read_to_string(&fp_path)?.trim().to_string(),
        }
    } else {
        let certified = generate_simple_self_signed(vec!["zapsend.local".to_string()])
            .context("generating cert")?;
        let cert_pem = certified.cert.pem();
        let key_pem = certified.key_pair.serialize_pem();
        let fingerprint = hex::encode(Sha256::digest(certified.cert.der().as_ref()));

        std::fs::write(&cert_path, &cert_pem)?;
        std::fs::write(&key_path, &key_pem)?;
        std::fs::write(&fp_path, &fingerprint)?;

        Identity {
            cert_pem,
            key_pem,
            fingerprint,
        }
    };

    let info = DeviceInfo {
            zapsend_resume: false,
        alias: alias.to_string(),
        version: PROTOCOL_VERSION.to_string(),
        device_model: Some(format!(
            "{} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )),
        // This is the whole point of the project: we tell peers we are headless.
        device_type: Some("headless".to_string()),
        fingerprint: identity.fingerprint.clone(),
        port,
        protocol: "https".to_string(),
        // We do not serve /prepare-download yet. Advertising it would invite
        // peers to try, and they would get a 404 instead of a clean "no".
        download: false,
    };

    Ok((identity, info))
}

pub fn short_fingerprint(fp: &str) -> &str {
    if fp.len() >= 8 {
        &fp[..8]
    } else {
        fp
    }
}

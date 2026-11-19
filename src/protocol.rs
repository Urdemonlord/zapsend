//! Wire types for the LocalSend protocol v2.
//!
//! Spec: <https://github.com/localsend/protocol>
//!
//! We only implement the subset needed for headless send/receive:
//! multicast announce, register, prepare-upload, upload.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Default port for the HTTP API. The spec allows any port here.
pub const DEFAULT_PORT: u16 = 53317;

/// The multicast socket always listens here; the `port` field in the payload
/// tells peers where the HTTP API actually is. Keeping these separate is what
/// lets two instances run on one machine.
pub const MULTICAST_PORT: u16 = 53317;

/// Default multicast group. The spec uses 224.0.0.167 inside 224.0.0.0/24
/// because some Android devices reject anything wider.
pub const MULTICAST_IP: [u8; 4] = [224, 0, 0, 167];

/// Protocol version we advertise. LocalSend is lenient about this field.
pub const PROTOCOL_VERSION: &str = "2.0";

/// Base path for every HTTP endpoint.
pub const API: &str = "/api/localsend/v2";

fn default_version() -> String {
    PROTOCOL_VERSION.to_string()
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

fn default_scheme() -> String {
    "https".to_string()
}

/// A device on the network, as described in the `info` field of the protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub alias: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    /// mobile | desktop | web | headless | server
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// http | https
    #[serde(default = "default_scheme")]
    pub protocol: String,
    /// Non-standard: this receiver can resume a half-finished upload. Peers that
    /// do not know the field ignore it, and we only resume when it is true.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub zapsend_resume: bool,
    #[serde(default)]
    pub download: bool,
}

/// A device plus the IP we learned it from. The protocol never puts the IP in
/// the payload, so we carry it out of band.
#[derive(Debug, Clone, Serialize)]
pub struct Peer {
    #[serde(flatten)]
    pub info: DeviceInfo,
    pub ip: IpAddr,
}

impl Peer {
    pub fn base_url(&self) -> String {
        format!("{}://{}:{}", self.info.protocol, self.ip, self.info.port)
    }
}

/// Multicast payload. `announce: true` means "reply to me"; `false` is a reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announcement {
    #[serde(flatten)]
    pub info: DeviceInfo,
    #[serde(default)]
    pub announce: bool,
}

/// Write `fileType` even when we never learned it: the spec marks it required,
/// and a missing key makes a strict client drop the whole file list.
fn file_type_or_default<S: serde::Serializer>(
    value: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(t) => serializer.serialize_str(t),
        None => serializer.serialize_str("application/octet-stream"),
    }
}

/// Enough of a MIME guess for a peer's file-type icon; the spec has no opinion.
pub fn guess_mime(name: &str) -> String {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let mime = match ext.as_str() {
        "txt" | "log" | "md" | "csv" => "text/plain",
        "json" => "application/json",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        _ => "application/octet-stream",
    };
    mime.to_string()
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Metadata for one file inside a transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMeta {
    pub id: String,
    pub file_name: String,
    pub size: u64,
    // The spec lists `fileType` on every file object and the official client
    // parses it as a required string, so it is always written — never omitted.
    #[serde(default, serialize_with = "file_type_or_default")]
    pub file_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Zapsend extension, not part of the LocalSend spec: replace the file the
    /// receiver already holds instead of landing as `name (1).ext`. Only ever
    /// sent by `sync --replace`, and only to a peer that answered the zapsend
    /// manifest endpoint, so a plain LocalSend receiver never sees it set.
    /// Unknown fields are ignored by other implementations.
    #[serde(default, skip_serializing_if = "is_false")]
    pub replace: bool,
}

/// Body of `POST /prepare-upload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareUploadRequest {
    /// Optional: protocol 2.0 senders may omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<DeviceInfo>,
    pub files: HashMap<String, FileMeta>,
}

/// What the receiver already holds of one upload, and the SHA-256 of exactly
/// those bytes so the sender can prove its prefix is the same file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumeState {
    pub offset: u64,
    #[serde(default)]
    pub prefix_sha256: String,
}

/// Response to `POST /prepare-download`: our identity, a session id, and the
/// metadata of every file in the share. No tokens here — the session id is what
/// `/download` checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareDownloadResponse {
    pub info: DeviceInfo,
    pub session_id: String,
    pub files: HashMap<String, FileMeta>,
}

/// Response to `POST /prepare-upload`: a session id plus one token per file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUploadResponse {
    pub session_id: String,
    pub files: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_type_is_never_omitted_from_the_json() {
        let meta = FileMeta {
            id: "a".into(),
            file_name: "a.txt".into(),
            size: 1,
            file_type: None,
            sha256: None,
            replace: false,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(
            json.contains("\"fileType\":\"application/octet-stream\""),
            "a strict client drops the whole file list without fileType: {json}"
        );
    }

    #[test]
    fn guess_mime_knows_the_common_ones() {
        assert_eq!(guess_mime("x.png"), "image/png");
        assert_eq!(guess_mime("X.JPG"), "image/jpeg");
        assert_eq!(guess_mime("notes.md"), "text/plain");
        assert_eq!(guess_mime("no-extension"), "application/octet-stream");
    }
}

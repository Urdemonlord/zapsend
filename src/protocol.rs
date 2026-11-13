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
pub const PROTOCOL_VERSION: &str = "2.1";

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
#[derive(Debug, Clone, Serialize)]
pub struct Announcement {
    #[serde(flatten)]
    pub info: DeviceInfo,
    pub announce: bool,
}

/// Metadata for one file inside a transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMeta {
    pub id: String,
    pub file_name: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Body of `POST /prepare-upload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareUploadRequest {
    pub info: DeviceInfo,
    pub files: HashMap<String, FileMeta>,
}

/// Response to `POST /prepare-upload`: a session id plus one token per file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUploadResponse {
    pub session_id: String,
    pub files: HashMap<String, String>,
}

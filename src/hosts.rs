//! Remembered machines: `zapsend trust` stores an address, a TLS fingerprint and
//! optionally a PIN under a name, so an unattended `send`/`pull` needs no flags.
//!
//! The file is JSON (serde is already here) and is written 0600 on unix because it
//! may hold a PIN. `ZAPSEND_CONFIG` overrides the path, which is what the tests
//! use so they never touch the real one.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::protocol::{DeviceInfo, Peer, PROTOCOL_VERSION};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub ip: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
}

fn default_port() -> u16 {
    53317
}

pub type Map = BTreeMap<String, Entry>;

/// The key a trust-on-first-use entry is stored under: the address itself,
/// `ip:port`. A name is for humans; an address nobody named yet still needs
/// somewhere to keep the fingerprint it announced.
pub fn address_key(addr: IpAddr, port: u16) -> String {
    // Bracket an IPv6 address, or `::1:53317` would not parse back.
    if addr.is_ipv6() {
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    }
}

pub fn path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("ZAPSEND_CONFIG") {
        return Ok(PathBuf::from(p));
    }
    let dir = dirs::config_dir().context("cannot find a config directory")?;
    Ok(dir.join("zapsend").join("hosts.json"))
}

pub fn load() -> Result<Map> {
    load_from(&path()?)
}

pub fn load_from(path: &Path) -> Result<Map> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        // No file is the normal state on a fresh machine, not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    if raw.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(Map::new());
    }
    serde_json::from_slice(&raw).with_context(|| {
        format!(
            "{} is not a valid hosts file — fix or delete it",
            path.display()
        )
    })
}

pub fn save(map: &Map) -> Result<PathBuf> {
    let path = path()?;
    save_to(&path, map)?;
    Ok(path)
}

pub fn save_to(path: &Path, map: &Map) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let mut body = serde_json::to_vec_pretty(map)?;
    body.push(b'\n');

    // Write then rename, so an interrupted save never leaves half a file that
    // would make every later command fail to parse it.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &body).with_context(|| format!("cannot write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot restrict {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

/// A peer built from the hosts file. The fingerprint, when present, is what
/// `peer_client` pins, so this connection is verified even though nothing was
/// discovered.
pub async fn peer_for(name: &str, entry: &Entry) -> Result<Peer> {
    let ip: IpAddr = entry
        .ip
        .parse()
        .with_context(|| format!("hosts file: \"{name}\" has an invalid ip {:?}", entry.ip))?;
    let mut peer = Peer {
        info: DeviceInfo {
            zapsend_resume: false,
            alias: name.to_string(),
            version: PROTOCOL_VERSION.to_string(),
            device_model: None,
            device_type: None,
            fingerprint: entry.fingerprint.clone().unwrap_or_default(),
            port: entry.port,
            protocol: "https".to_string(),
            download: false,
        },
        ip,
    };

    // Ask the machine what it is: this fills in the real scheme, port and
    // capabilities. A machine that is down is not a reason to refuse to run —
    // the caller reports the connection error in its own words.
    if let Ok(info) = crate::client::fetch_info(&peer).await {
        peer.info.zapsend_resume = info.zapsend_resume;
        peer.info.download = info.download;
        peer.info.protocol = info.protocol;
        // Port stays as given: it is the one that answered.
        if !info.alias.is_empty() {
            peer.info.alias = info.alias;
        }
    }
    Ok(peer)
}

/// The remembered machine called `name`, if there is one.
pub async fn peer(name: &str) -> Result<Option<Peer>> {
    let map = load()?;
    let Some(entry) = map.get(name) else {
        return Ok(None);
    };
    Ok(Some(peer_for(name, entry).await?))
}

/// `--pin` beats `ZAPSEND_PIN` beats the stored PIN. The env var is there so a
/// fleet can inject the secret without writing it to disk.
pub fn resolve_pin(flag: Option<String>, name: Option<&str>) -> Option<String> {
    flag.or_else(|| {
        std::env::var("ZAPSEND_PIN")
            .ok()
            .filter(|v| !v.is_empty())
    })
    .or_else(|| {
        name.and_then(|n| load().ok()?.get(n)?.pin.clone())
    })
}

/// Store a machine. `fingerprint` must be a full 64-hex value; a short prefix
/// would pin nothing.
pub fn remember(
    name: &str,
    ip: &str,
    port: u16,
    fingerprint: Option<String>,
    pin: Option<String>,
) -> Result<PathBuf> {
    if name.trim().is_empty() {
        bail!("the name cannot be empty");
    }
    if name.contains(char::is_whitespace) {
        bail!("the name cannot contain spaces — it is used as one word after --to");
    }
    if let Some(fp) = fingerprint.as_deref() {
        if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("a fingerprint is 64 hex characters, got {}", fp.len());
        }
    }

    let mut map = load()?;
    map.insert(
        name.to_string(),
        Entry {
            ip: ip.to_string(),
            port,
            fingerprint: fingerprint.map(|f| f.to_ascii_lowercase()),
            pin,
        },
    );
    save(&map)
}

pub fn forget(name: &str) -> Result<bool> {
    let mut map = load()?;
    let removed = map.remove(name).is_some();
    if removed {
        save(&map)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    #[test]
    fn address_key_is_ip_colon_port() {
        assert_eq!(
            address_key("127.0.0.1".parse().unwrap(), 53400),
            "127.0.0.1:53400"
        );
        assert_eq!(
            address_key("::1".parse().unwrap(), 53317),
            "[::1]:53317"
        );
    }

    use super::*;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("zapsend-hosts-{name}.json"))
    }

    #[test]
    fn round_trips_and_omits_empty_secrets() {
        let path = temp("roundtrip");
        let _ = std::fs::remove_file(&path);

        let mut map = Map::new();
        map.insert(
            "gpu-box".into(),
            Entry {
                ip: "100.64.0.7".into(),
                port: 53317,
                fingerprint: Some("ab".repeat(32)),
                pin: None,
            },
        );
        save_to(&path, &map).unwrap();

        let back = load_from(&path).unwrap();
        assert_eq!(back["gpu-box"].ip, "100.64.0.7");
        assert_eq!(back["gpu-box"].port, 53317);
        assert_eq!(back["gpu-box"].pin, None);

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("pin"), "an absent pin must not be written: {raw}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the hosts file holds a PIN, keep it private");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_file_is_an_empty_map_and_a_broken_one_is_an_error() {
        let path = temp("broken");
        let _ = std::fs::remove_file(&path);
        assert!(load_from(&path).unwrap().is_empty());

        std::fs::write(&path, "{not json").unwrap();
        assert!(load_from(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn port_defaults_when_the_file_omits_it() {
        let path = temp("noport");
        std::fs::write(&path, r#"{"box":{"ip":"10.0.0.2"}}"#).unwrap();
        assert_eq!(load_from(&path).unwrap()["box"].port, 53317);
        let _ = std::fs::remove_file(&path);
    }
}

//! Multicast discovery: announce ourselves, listen for everyone else.
//!
//! LocalSend's discovery has two halves:
//!   1. UDP multicast on 224.0.0.167:53317 (the default path)
//!   2. A unicast `POST /register` handshake against each peer
//!
//! We do both: the multicast socket here, and the register endpoint lives in
//! `server.rs`. Whichever path a peer uses, it lands in the same registry.

use crate::protocol::{Announcement, DeviceInfo, Peer, DEFAULT_PORT, MULTICAST_IP, MULTICAST_PORT};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Shared list of discovered devices, keyed by fingerprint.
pub type Registry = Arc<Mutex<HashMap<String, Peer>>>;

pub fn new_registry() -> Registry {
    Arc::new(Mutex::new(HashMap::new()))
}

pub fn multicast_group() -> Ipv4Addr {
    Ipv4Addr::new(
        MULTICAST_IP[0],
        MULTICAST_IP[1],
        MULTICAST_IP[2],
        MULTICAST_IP[3],
    )
}

/// Bind a UDP socket that can both send to and receive from the multicast group.
pub fn bind_multicast() -> Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("creating UDP socket")?;
    sock.set_reuse_address(true)?;
    // No SO_REUSEPORT on purpose: on Linux it load-balances multicast datagrams
    // between sockets bound to the same port, so a `send` running next to a
    // `receive` steals each other's announcements and discovery goes quiet.
    // SO_REUSEADDR alone lets both bind and both receive the group traffic.
    sock.set_nonblocking(true)?;

    let addr: SocketAddr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, MULTICAST_PORT));
    sock.bind(&addr.into())
        .with_context(|| format!("binding UDP {MULTICAST_PORT}"))?;

    let std_sock: std::net::UdpSocket = sock.into();
    let socket = UdpSocket::from_std(std_sock)?;

    socket
        .join_multicast_v4(multicast_group(), Ipv4Addr::UNSPECIFIED)
        .context("joining multicast group")?;

    Ok(socket)
}

/// Send an announcement asking every peer on the LAN to identify itself.
pub async fn announce(sock: &UdpSocket, me: &DeviceInfo) -> Result<()> {
    let msg = serde_json::to_vec(&Announcement {
        info: me.clone(),
        announce: true,
    })?;
    let dest = SocketAddr::from((multicast_group(), MULTICAST_PORT));
    crate::verbose::dump("→", "multicast announce", &msg);
    sock.send_to(&msg, dest)
        .await
        .context("sending multicast announcement")?;
    Ok(())
}

/// Read multicast traffic forever and record every device we see.
pub async fn listen(sock: Arc<UdpSocket>, registry: Registry, me: DeviceInfo) {
    let mut buf = vec![0u8; 16 * 1024];

    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            // A malformed packet should never kill discovery.
            Err(_) => continue,
        };

        let Ok(info) = serde_json::from_slice::<DeviceInfo>(&buf[..n]) else {
            // A peer whose announcement we cannot parse is the single most
            // likely reason discovery silently finds nothing.
            crate::verbose::dump("←", "multicast (unparsed)", &buf[..n]);
            continue;
        };

        // Empty fingerprint means it is not a real peer. Our own echo carries
        // both our fingerprint *and* our alias: two instances on one machine
        // share a certificate (identity is per-port), so matching on the
        // fingerprint alone would hide a legitimate local peer.
        if info.fingerprint.is_empty()
            || (info.fingerprint == me.fingerprint && info.alias == me.alias)
        {
            continue;
        }

        registry
            .lock()
            .unwrap()
            .insert(info.fingerprint.clone(), Peer { info, ip: src.ip() });
    }
}

/// Multicast is the first thing guest Wi-Fi, a corporate AP or a phone hotspot
/// silently drops, so fall back to the spec's legacy discovery: unicast
/// `POST /register` to every host on our own /24 and keep whoever answers.
///
/// Returns how many peers were added to the registry.
pub async fn sweep(registry: &Registry, me: &DeviceInfo, quiet: bool) -> Result<usize> {
    let Some(local) = local_ipv4().await else {
        return Ok(0);
    };
    let hosts = subnet_hosts(local);
    let o = local.octets();
    if !quiet {
        eprintln!(
            "! no multicast answers — sweeping {}.{}.{}.0/24",
            o[0], o[1], o[2]
        );
    }

    let http = reqwest::Client::builder()
        // Every device self-signs; identity is proven later by fingerprint
        // pinning, never by the CA chain, so an untrusted cert is expected here.
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(400))
        .build()?;
    let body = serde_json::to_vec(me)?;

    let mut added = 0;
    for chunk in hosts.chunks(96) {
        let mut tasks = Vec::with_capacity(chunk.len());
        for ip in chunk {
            tasks.push(probe(http.clone(), body.clone(), *ip));
        }
        for hit in futures_util::future::join_all(tasks).await.into_iter().flatten() {
            let (ip, info) = hit;
            // Our own listener answers too when we hold the port.
            if info.fingerprint == me.fingerprint {
                continue;
            }
            registry
                .lock()
                .unwrap()
                .insert(info.fingerprint.clone(), Peer { info, ip: IpAddr::V4(ip) });
            added += 1;
        }
    }
    Ok(added)
}

/// Ask one host to register us. Phones answer over http, desktops over https.
async fn probe(http: reqwest::Client, body: Vec<u8>, ip: Ipv4Addr) -> Option<(Ipv4Addr, DeviceInfo)> {
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{ip}:{DEFAULT_PORT}/api/localsend/v2/register");
        let Ok(resp) = http
            .post(&url)
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await
        else {
            continue;
        };
        if let Ok(info) = resp.json::<DeviceInfo>().await {
            return Some((ip, info));
        }
    }
    None
}

/// Every address in our own /24 except our own — the legacy discovery range.
fn subnet_hosts(local: Ipv4Addr) -> Vec<Ipv4Addr> {
    let o = local.octets();
    (1..=254u8)
        .map(|h| Ipv4Addr::new(o[0], o[1], o[2], h))
        .filter(|ip| *ip != local)
        .collect()
}

/// Our address on the interface that owns the default route. The UDP connect
/// only consults the routing table — nothing is sent.
async fn local_ipv4() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect("8.8.8.8:80").await.ok()?;
    match sock.local_addr().ok()? {
        SocketAddr::V4(a) => Some(*a.ip()),
        SocketAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_covers_its_own_slash_24_without_itself() {
        let hosts = subnet_hosts(Ipv4Addr::new(10, 118, 41, 215));
        assert_eq!(hosts.len(), 253);
        assert!(hosts.contains(&Ipv4Addr::new(10, 118, 41, 1)));
        assert!(hosts.contains(&Ipv4Addr::new(10, 118, 41, 254)));
        assert!(!hosts.contains(&Ipv4Addr::new(10, 118, 41, 215)));
        assert!(hosts.iter().all(|ip| ip.octets()[..3] == [10, 118, 41]));
    }
}

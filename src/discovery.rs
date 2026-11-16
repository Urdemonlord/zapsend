//! Multicast discovery: announce ourselves, listen for everyone else.
//!
//! LocalSend's discovery has two halves:
//!   1. UDP multicast on 224.0.0.167:53317 (the default path)
//!   2. A unicast `POST /register` handshake against each peer
//!
//! We do both: the multicast socket here, and the register endpoint lives in
//! `server.rs`. Whichever path a peer uses, it lands in the same registry.

use crate::protocol::{Announcement, DeviceInfo, Peer, MULTICAST_IP, MULTICAST_PORT};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
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

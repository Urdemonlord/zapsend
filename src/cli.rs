use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "zapsend",
    version,
    about = "Headless, LocalSend-compatible file transfer over your local network",
    long_about = "Send files from your terminal to any device running LocalSend.\n\n\
                  Zapsend speaks the LocalSend protocol, so the other side needs no install."
)]
pub struct Cli {
    /// Name other devices will see
    #[arg(long, global = true, default_value_t = default_alias())]
    pub alias: String,

    /// Port for the file-transfer API.
    ///
    /// Multicast discovery always stays on 53317 (that is what the protocol
    /// expects). Changing this lets you run a second instance on one machine.
    #[arg(long, global = true, default_value_t = 53317)]
    pub port: u16,

    /// Dump the raw JSON exchanged with peers, for protocol debugging
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// Machine-readable output: one JSON object on stdout, human progress on
    /// stderr. Exit code still carries the verdict.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Remember a machine under a name, so later commands need no --ip,
    /// --fingerprint or --pin
    Trust {
        /// The name to use later with --to
        name: String,

        /// Address of the machine (`100.64.0.7` or `100.64.0.7:53317`)
        #[arg(long)]
        ip: String,

        /// Pin its certificate to this fingerprint (64 hex characters).
        ///
        /// Without it the fingerprint is taken from the machine on first sight:
        /// compare it with what that machine prints when it starts.
        #[arg(long)]
        fingerprint: Option<String>,

        /// PIN to remember for this machine
        #[arg(long)]
        pin: Option<String>,

        /// The peer serves plain HTTP (a `receive --plain` receiver on a
        /// private network). Without it, trust refuses a peer that announces
        /// no certificate fingerprint. Plain mode sends the PIN and the files
        /// in the clear, so only ever use it where the link itself is already
        /// encrypted (Tailscale, WireGuard) — never on the open internet.
        #[arg(long)]
        plain: bool,
    },

    /// List remembered machines
    Hosts,

    /// Forget a remembered machine
    Forget {
        /// Name to remove
        name: String,
    },

    /// Find devices on the local network
    Discover {
        /// How long to listen, in seconds
        #[arg(long, default_value_t = 5)]
        wait: u64,
    },

    /// Send one or more files to a device
    Send {
        /// Files to send
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// Target: alias or fingerprint prefix (from `zapsend discover`).
        ///
        /// A comma-separated list (`--to gpu-box,edge-1,edge-2`) sends the same
        /// files to each host in parallel (at most four at a time) and reports
        /// one summary. Every name must already be in the hosts file.
        #[arg(long)]
        to: Option<String>,

        /// Skip discovery and connect straight to this address
        /// (`192.168.1.42` or `192.168.1.42:53400`)
        #[arg(long, conflicts_with = "to")]
        ip: Option<String>,

        /// Pin the peer's certificate fingerprint (64 hex chars).
        ///
        /// Discovery already supplies this. It is required if you want a
        /// verified connection while using --ip on an untrusted network.
        #[arg(long)]
        fingerprint: Option<String>,

        /// Trust this address on first sight: take the fingerprint it announces
        /// and save it, so the next command verifies against it. Only on a
        /// network you trust — the first connection is exactly when an
        /// impostor could answer instead of the real machine.
        #[arg(long)]
        tofu: bool,

        /// PIN required by the receiving device, if it has one
        #[arg(long)]
        pin: Option<String>,

        /// Discovery scan duration in seconds (ignored with --ip)
        #[arg(long, default_value_t = 4)]
        scan: u64,

        /// How many times to retry a file whose connection drops. zapsend
        /// receivers resume from the bytes they already have; other peers
        /// restart the file.
        #[arg(long, default_value_t = 3)]
        retry: u32,

        /// The peer serves plain HTTP (`receive --plain` on a private
        /// network). Skips the TLS probe, so the connection never attempts a
        /// handshake the peer cannot answer. Plain mode only changes the
        /// transport, never the target — and it sends the PIN and the files
        /// in the clear, so only ever use it where the link itself is already
        /// encrypted (Tailscale, WireGuard), never on the open internet.
        #[arg(long)]
        plain: bool,
    },

    /// Accept incoming files and keep running
    Receive {
        /// Where to save incoming files
        #[arg(long, default_value = "./zapsend-received")]
        dir: PathBuf,

        /// Require a PIN for incoming transfers.
        ///
        /// Omit the value to generate a random 6-digit PIN and print it.
        #[arg(long, num_args = 0..=1, default_missing_value = "", value_name = "PIN")]
        pin: Option<String>,

        /// Ask before accepting each transfer instead of accepting silently
        #[arg(long)]
        ask: bool,

        /// Also offer this directory through the Download API, so a peer can
        /// pull files from you (`zapsend pull`). Off by default.
        #[arg(long, value_name = "DIR")]
        share: Option<PathBuf>,

        /// Serve plain HTTP with no TLS, for a private network only.
        ///
        /// The link to the other machine must already be encrypted
        /// (Tailscale, WireGuard): plain mode sends the PIN and the files in
        /// the clear, so it must never face the open internet. TLS stays the
        /// default everywhere; this flag only opts this one receiver out.
        #[arg(long)]
        plain: bool,
    },

    /// Pull files from a device that shares a folder (Download API)
    Pull {
        /// Source: alias or fingerprint prefix (from `zapsend discover`).
        ///
        /// A comma-separated list (`--to a,b`) or `all` pulls from each trusted
        /// host in turn, into its own subdirectory of --dir.
        #[arg(long)]
        to: Option<String>,

        /// Skip discovery and connect straight to this address
        /// (`192.168.1.42` or `192.168.1.42:53400`)
        #[arg(long, conflicts_with = "to")]
        ip: Option<String>,

        /// Pin the peer's certificate fingerprint (64 hex chars)
        #[arg(long)]
        fingerprint: Option<String>,

        /// Trust this address on first sight: take the fingerprint it announces
        /// and save it, so the next command verifies against it. Only on a
        /// network you trust — the first connection is exactly when an
        /// impostor could answer instead of the real machine.
        #[arg(long)]
        tofu: bool,

        /// PIN the sharing device requires
        #[arg(long)]
        pin: Option<String>,

        /// Where to save the pulled files
        #[arg(long, default_value = "./zapsend-pulled")]
        dir: PathBuf,

        /// Only pull files whose path or name contains this text (repeatable)
        #[arg(long = "file")]
        file: Vec<String>,

        /// Discovery scan duration in seconds (ignored with --ip)
        #[arg(long, default_value_t = 4)]
        scan: u64,

        /// Retry a broken download this many times, continuing where it stopped
        #[arg(long, default_value_t = 3)]
        retry: u32,

        /// The peer serves plain HTTP (`receive --plain` on a private
        /// network). Skips the TLS probe, so the connection never attempts a
        /// handshake the peer cannot answer. Plain mode only changes the
        /// transport, never the target — and it sends the PIN and the files
        /// in the clear, so only ever use it where the link itself is already
        /// encrypted (Tailscale, WireGuard), never on the open internet.
        #[arg(long)]
        plain: bool,
    },

    /// Check why discovery or sending is not working
    Doctor {
        /// Also test reachability of this device (alias or fingerprint prefix)
        #[arg(long)]
        to: Option<String>,

        /// Test this address instead of looking a device up
        #[arg(long, conflicts_with = "to")]
        ip: Option<String>,

        /// Seconds to listen for multicast answers
        #[arg(long, default_value_t = 4)]
        scan: u64,

        /// Directory a receiver would write into
        #[arg(long, default_value = "./zapsend-received")]
        dir: PathBuf,

        /// The peer serves plain HTTP (`receive --plain` on a private
        /// network). Skips the TLS probe, so the connection never attempts a
        /// handshake the peer cannot answer. Plain mode only changes the
        /// transport, never the target — and it sends the PIN and the files
        /// in the clear, so only ever use it where the link itself is already
        /// encrypted (Tailscale, WireGuard), never on the open internet.
        #[arg(long)]
        plain: bool,
    },

    /// Send only the files the other side does not already have
    Sync {
        /// Folder to sync (relative paths are kept)
        dir: PathBuf,

        /// Target: a name from the hosts file
        #[arg(long)]
        to: Option<String>,

        /// Skip the hosts file and connect straight to this address
        #[arg(long)]
        ip: Option<String>,

        /// Pin the peer's certificate to this fingerprint
        #[arg(long)]
        fingerprint: Option<String>,

        /// Trust this address on first sight: take the fingerprint it announces
        /// and save it, so the next command verifies against it. Only on a
        /// network you trust — the first connection is exactly when an
        /// impostor could answer instead of the real machine.
        #[arg(long)]
        tofu: bool,

        /// PIN the peer asks for
        #[arg(long)]
        pin: Option<String>,

        /// Say what would be sent and send nothing
        #[arg(long)]
        dry_run: bool,

        /// Replace files the peer already holds with different content.
        /// Without it those are conflicts and the run fails. The new bytes
        /// are hash-verified before the old file is touched, and the old
        /// file is only deleted once the new one is in place.
        #[arg(long)]
        replace: bool,

        /// Attempts per upload before giving up on it
        #[arg(long, default_value_t = 3)]
        retries: u32,

        /// The peer serves plain HTTP (`receive --plain` on a private
        /// network). Skips the TLS probe, so the connection never attempts a
        /// handshake the peer cannot answer. Plain mode only changes the
        /// transport, never the target — and it sends the PIN and the files
        /// in the clear, so only ever use it where the link itself is already
        /// encrypted (Tailscale, WireGuard), never on the open internet.
        #[arg(long)]
        plain: bool,
    },

    /// Watch a folder and send whatever appears in it
    Daemon {
        /// Folder to watch
        #[arg(long, default_value = "./zapsend-outbox")]
        dir: PathBuf,

        /// Target: alias or fingerprint prefix (from `zapsend discover`).
        ///
        /// A comma-separated list (`--to a,b`) or `all` pushes each file to
        /// every named host, and only moves it to .sent once all of them have it.
        #[arg(long)]
        to: Option<String>,

        /// Skip discovery and connect straight to this address
        /// (`192.168.1.42` or `192.168.1.42:53400`)
        #[arg(long, conflicts_with = "to")]
        ip: Option<String>,

        /// Pin the peer's certificate fingerprint (64 hex chars)
        #[arg(long)]
        fingerprint: Option<String>,

        /// Trust this address on first sight: take the fingerprint it announces
        /// and save it, so the next command verifies against it. Only on a
        /// network you trust — the first connection is exactly when an
        /// impostor could answer instead of the real machine.
        #[arg(long)]
        tofu: bool,

        /// PIN required by the receiving device, if it has one
        #[arg(long)]
        pin: Option<String>,

        /// Seconds between folder scans
        #[arg(long, default_value_t = 2)]
        interval: u64,

        /// Seconds a file must stay untouched before it is sent
        /// (default: twice --interval, at least 3)
        #[arg(long)]
        settle: Option<u64>,

        /// Leave delivered files in the folder instead of moving them to .sent
        #[arg(long)]
        keep: bool,

        /// Discovery scan duration in seconds (ignored with --ip)
        #[arg(long, default_value_t = 4)]
        scan: u64,

        /// The peer serves plain HTTP (`receive --plain` on a private
        /// network). Skips the TLS probe, so the connection never attempts a
        /// handshake the peer cannot answer. Plain mode only changes the
        /// transport, never the target — and it sends the PIN and the files
        /// in the clear, so only ever use it where the link itself is already
        /// encrypted (Tailscale, WireGuard), never on the open internet.
        #[arg(long)]
        plain: bool,
    },

    /// Browse devices and send from a local web page
    Ui {
        /// Where to save incoming files
        #[arg(long, default_value = "./zapsend-received")]
        dir: PathBuf,

        /// Require a PIN for incoming transfers (omit the value to generate one)
        #[arg(long, num_args = 0..=1, default_missing_value = "", value_name = "PIN")]
        pin: Option<String>,

        /// Loopback port for the page itself
        #[arg(long, default_value_t = 53318)]
        ui_port: u16,

        /// Do not open the browser automatically
        #[arg(long)]
        no_open: bool,
    },
}

fn default_alias() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "zapsend".to_string())
}

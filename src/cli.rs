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

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
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

        /// Target: alias or fingerprint prefix (from `zapsend discover`)
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

        /// PIN required by the receiving device, if it has one
        #[arg(long)]
        pin: Option<String>,

        /// Discovery scan duration in seconds (ignored with --ip)
        #[arg(long, default_value_t = 4)]
        scan: u64,
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
    },

    /// Watch a folder and send whatever appears in it
    Daemon {
        /// Folder to watch
        #[arg(long, default_value = "./zapsend-outbox")]
        dir: PathBuf,

        /// Target: alias or fingerprint prefix (from `zapsend discover`)
        #[arg(long)]
        to: Option<String>,

        /// Skip discovery and connect straight to this address
        /// (`192.168.1.42` or `192.168.1.42:53400`)
        #[arg(long, conflicts_with = "to")]
        ip: Option<String>,

        /// Pin the peer's certificate fingerprint (64 hex chars)
        #[arg(long)]
        fingerprint: Option<String>,

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

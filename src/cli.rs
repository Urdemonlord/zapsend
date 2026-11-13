use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "zap",
    version,
    about = "Headless, LocalSend-compatible file transfer over your local network",
    long_about = "Send files from your terminal to any device running LocalSend.\n\n\
                  Zap speaks the LocalSend protocol, so the other side needs no install."
)]
pub struct Cli {
    /// Name other devices will see
    #[arg(long, global = true, default_value_t = default_alias())]
    pub alias: String,

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

    /// Send a file to a device
    Send {
        /// File to send
        file: PathBuf,

        /// Target: alias or fingerprint prefix (from `zap discover`)
        #[arg(long)]
        to: Option<String>,

        /// Skip discovery and connect straight to this IP
        #[arg(long, conflicts_with = "to")]
        ip: Option<String>,

        /// Discovery scan duration in seconds (ignored with --ip)
        #[arg(long, default_value_t = 4)]
        scan: u64,
    },

    /// Accept incoming files and keep running
    Receive {
        /// Where to save incoming files
        #[arg(long, default_value = "./zap-received")]
        dir: PathBuf,
    },
}

fn default_alias() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "zap".to_string())
}

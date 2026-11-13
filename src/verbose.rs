//! `--verbose` payload dumps.
//!
//! Interop debugging needs the exact bytes a peer sent. A deserialised struct
//! hides precisely the fields we failed to model, which are usually the ones
//! causing the mismatch.

use std::sync::atomic::{AtomicBool, Ordering};

static ON: AtomicBool = AtomicBool::new(false);

pub fn set(on: bool) {
    ON.store(on, Ordering::Relaxed);
}

pub fn on() -> bool {
    ON.load(Ordering::Relaxed)
}

/// `direction` is "←" for something we received, "→" for something we sent.
pub fn dump(direction: &str, label: &str, bytes: &[u8]) {
    if !on() {
        return;
    }
    let body = match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_default(),
        // Not JSON at all: this is exactly the case worth seeing raw.
        Err(_) => String::from_utf8_lossy(bytes).to_string(),
    };
    eprintln!("{direction} {label}\n{body}\n");
}

//! Plain HTTP end to end: a `receive --plain` receiver on loopback, then
//! `trust --plain`, `send --plain`, `pull --plain` and `doctor --plain`
//! against it, with the bytes checked both ways. Plus the two guardrails:
//! `trust --plain` against a TLS receiver must fail (never silently
//! downgrade), and `trust` without `--plain` against a plain receiver must
//! fail. TLS itself is covered by the last test, so a regression that breaks
//! the default is caught here too.
//!
//! Everything runs on loopback, which is a private network by definition —
//! plain mode is only ever for links that are already encrypted (Tailscale,
//! WireGuard), never the open internet.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zapsend"))
}

/// A receiver that is killed when the test ends, even on panic.
struct Receiver {
    child: Option<Child>,
    dir: PathBuf,
}

impl Receiver {
    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.kill();
    }
}

fn start_receiver(work: &Path, name: &str, port: u16, plain: bool, share: Option<&Path>) -> Receiver {
    let dir = work.join(format!("recv-{name}"));
    fs::create_dir_all(&dir).unwrap();
    let log_path = work.join(format!("recv-{name}.log"));
    let log = fs::File::create(&log_path).unwrap();
    let mut cmd = Command::new(bin());
    cmd.args([
        "receive",
        "--port",
        &port.to_string(),
        "--alias",
        name,
        "--dir",
        dir.to_str().unwrap(),
        "--pin",
        "123456",
    ]);
    if plain {
        cmd.arg("--plain");
    }
    if let Some(shared) = share {
        cmd.arg("--share").arg(shared.to_str().unwrap());
    }
    let mut child = cmd
        .env("ZAPSEND_CONFIG", work.join("hosts.json"))
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();

    // The receiver prints `listening   :<port>` in the startup banner; poll
    // the log for it instead of sleeping a fixed amount.
    let want = format!("listening   :{port}");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut text = String::new();
        if let Ok(mut f) = fs::File::open(&log_path) {
            let _ = f.read_to_string(&mut text);
        }
        if text.contains(&want) {
            break;
        }
        if Instant::now() > deadline {
            // The child is still a local here, not a Receiver yet, so its
            // Drop would never run: kill and reap it before panicking, or
            // the receiver keeps running after the test dies.
            let _ = child.kill();
            let _ = child.wait();
            panic!("receiver {name} on :{port} never printed its banner:\n{text}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Receiver {
        child: Some(child),
        dir,
    }
}

fn run(work: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env("ZAPSEND_CONFIG", work.join("hosts.json"))
        .output()
        .unwrap()
}

fn assert_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn assert_fails(out: &Output, what: &str) {
    assert!(
        !out.status.success(),
        "{what} must fail: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Poll a receiver log until it contains `needle`. The banner prints
/// `listening` before the lines that follow it, so a caller that needs one
/// of those lines must wait for it instead of reading right after the
/// receiver starts.
fn wait_log_contains(work: &Path, name: &str, needle: &str) {
    let log_path = work.join(format!("recv-{name}.log"));
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(text) = fs::read_to_string(&log_path) {
            if text.contains(needle) {
                return;
            }
        }
        if Instant::now() > deadline {
            panic!("receiver {name} log never contained {needle:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn plain_mode_sends_pulls_and_doctors() {
    let work = std::env::temp_dir().join(format!("zapsend-plain-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).unwrap();

    // Deterministic payloads: 1 MiB up, 64 KiB back down.
    let payload = work.join("payload.bin");
    let up: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    fs::write(&payload, &up).unwrap();
    let share_dir = work.join("share");
    fs::create_dir_all(&share_dir).unwrap();
    let down: Vec<u8> = (0..64 * 1024).map(|i| (i % 241) as u8).collect();
    fs::write(share_dir.join("shared.bin"), &down).unwrap();

    let mut plain = start_receiver(&work, "plain1", 53520, true, Some(&share_dir));

    // Trusting a plain peer without --plain must fail: there is no
    // fingerprint to pin, and the refusal has to say so.
    let out = run(
        &work,
        &["trust", "plain1", "--ip", "127.0.0.1:53520", "--pin", "123456"],
    );
    assert_fails(&out, "trust without --plain against a plain receiver");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--plain"),
        "the refusal must point at --plain: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Trust with --plain stores the peer with no fingerprint.
    let out = run(
        &work,
        &["trust", "plain1", "--ip", "127.0.0.1:53520", "--pin", "123456", "--plain"],
    );
    assert_ok(&out, "trust --plain");
    let hosts = fs::read_to_string(work.join("hosts.json")).unwrap();
    assert!(
        !hosts.contains("fingerprint"),
        "a plain entry must not carry a fingerprint: {hosts}"
    );

    // Send over plain HTTP, PIN and all, and check the exact bytes land.
    let out = run(
        &work,
        &[
            "send",
            payload.to_str().unwrap(),
            "--to",
            "plain1",
            "--plain",
            "--pin",
            "123456",
        ],
    );
    assert_ok(&out, "send --plain --to plain1");
    let got = fs::read(plain.dir.join("payload.bin")).unwrap();
    assert_eq!(got, up, "plain receiver got different bytes");

    // The same send without --plain also works: the client probes TLS, fails
    // fast, and falls back to plain HTTP on its own.
    fs::remove_file(plain.dir.join("payload.bin")).unwrap();
    let out = run(
        &work,
        &["send", payload.to_str().unwrap(), "--to", "plain1", "--pin", "123456"],
    );
    assert_ok(&out, "send --to plain1 without --plain (auto fallback)");
    let got = fs::read(plain.dir.join("payload.bin")).unwrap();
    assert_eq!(got, up, "plain receiver got different bytes on fallback send");

    // --ip --tofu without --plain must refuse a plain receiver: trust on
    // first sight is about the certificate, not the transport, and the PIN
    // and the files must not go over cleartext without the caller saying so.
    let out = run(
        &work,
        &[
            "send",
            payload.to_str().unwrap(),
            "--ip",
            "127.0.0.1:53520",
            "--tofu",
            "--pin",
            "123456",
        ],
    );
    assert_fails(&out, "send --ip --tofu without --plain to a plain receiver");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--plain"),
        "the refusal must point at --plain: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The same send with --plain reaches the receiver.
    fs::remove_file(plain.dir.join("payload.bin")).unwrap();
    let out = run(
        &work,
        &[
            "send",
            payload.to_str().unwrap(),
            "--ip",
            "127.0.0.1:53520",
            "--tofu",
            "--plain",
            "--pin",
            "123456",
        ],
    );
    assert_ok(&out, "send --ip --tofu --plain to a plain receiver");
    let got = fs::read(plain.dir.join("payload.bin")).unwrap();
    assert_eq!(got, up, "plain receiver got different bytes on --ip --tofu --plain send");

    // Pull the shared file back down over plain HTTP.
    let pulled_dir = work.join("pulled");
    let out = run(
        &work,
        &[
            "pull",
            "--to",
            "plain1",
            "--plain",
            "--pin",
            "123456",
            "--dir",
            pulled_dir.to_str().unwrap(),
        ],
    );
    assert_ok(&out, "pull --plain");
    let got = fs::read(pulled_dir.join("shared.bin")).unwrap();
    assert_eq!(got, down, "pulled file differs from the shared original");

    // Doctor against the plain receiver over plain HTTP.
    let out = run(
        &work,
        &["doctor", "--plain", "--ip", "127.0.0.1:53520"],
    );
    assert_ok(&out, "doctor --plain");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no problems found")
            || String::from_utf8_lossy(&out.stderr).contains("no problems found"),
        "doctor must report no problems: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // --plain and --fingerprint contradict each other.
    let out = run(
        &work,
        &[
            "send",
            payload.to_str().unwrap(),
            "--ip",
            "127.0.0.1:53520",
            "--plain",
            "--fingerprint",
            &"ab".repeat(32),
            "--pin",
            "123456",
        ],
    );
    assert_fails(&out, "send --plain --fingerprint");

    plain.kill();
    let _ = fs::remove_dir_all(&work);
}

#[test]
fn plain_flag_never_downgrades_a_tls_peer_and_tls_still_works() {
    let work = std::env::temp_dir().join(format!("zapsend-plain-tls-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).unwrap();

    let payload = work.join("payload.bin");
    let bytes: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    fs::write(&payload, &bytes).unwrap();

    // Plain TLS receiver (no --plain): read its fingerprint from the banner.
    // The banner prints `listening` before `fingerprint`, so wait for the
    // fingerprint line instead of reading the log right after the receiver
    // starts.
    let log_path = work.join("recv-tls1.log");
    let mut tls = start_receiver(&work, "tls1", 53521, false, None);
    wait_log_contains(&work, "tls1", "fingerprint ");
    let log = fs::read_to_string(&log_path).unwrap();
    let at = log.find("fingerprint ").expect("TLS banner prints a fingerprint")
        + "fingerprint ".len();
    let fingerprint: String = log[at..].chars().take(64).collect();
    assert_eq!(fingerprint.len(), 64, "banner fingerprint must be 64 hex chars");

    // trust --plain against a TLS receiver must fail: the peer serves HTTPS,
    // and --plain must never silently downgrade it.
    let out = run(
        &work,
        &["trust", "tls1", "--ip", "127.0.0.1:53521", "--pin", "123456", "--plain"],
    );
    assert_fails(&out, "trust --plain against a TLS receiver");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("HTTPS"),
        "the refusal must say the peer serves HTTPS: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The normal TLS path still works end to end.
    let out = run(
        &work,
        &["trust", "tls1", "--ip", "127.0.0.1:53521", "--pin", "123456"],
    );
    assert_ok(&out, "trust a TLS receiver");
    let out = run(
        &work,
        &["send", payload.to_str().unwrap(), "--to", "tls1", "--pin", "123456"],
    );
    assert_ok(&out, "send to a TLS receiver");
    let got = fs::read(tls.dir.join("payload.bin")).unwrap();
    assert_eq!(got, bytes, "TLS receiver got different bytes");

    tls.kill();
    let _ = fs::remove_dir_all(&work);
}

#[test]
fn fanout_refuses_a_plain_entry_that_now_serves_https() {
    let work = std::env::temp_dir().join(format!("zapsend-plain-fanout-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).unwrap();

    let payload = work.join("payload.bin");
    let bytes: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    fs::write(&payload, &bytes).unwrap();

    // Trust the plain receiver, then restart the same port as TLS: the entry
    // now points at a machine whose certificate nobody pinned.
    let mut plain = start_receiver(&work, "plain2", 53522, true, None);
    let out = run(
        &work,
        &["trust", "plain2", "--ip", "127.0.0.1:53522", "--pin", "123456", "--plain"],
    );
    assert_ok(&out, "trust --plain");
    plain.kill();

    let mut tls = start_receiver(&work, "tls2", 53522, false, None);
    let out = run(
        &work,
        &["send", payload.to_str().unwrap(), "--to", "all", "--pin", "123456"],
    );
    assert_fails(&out, "fan-out send to a plain entry that now serves HTTPS");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("fingerprint"),
        "the refusal must be about the missing fingerprint: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    tls.kill();
    let _ = fs::remove_dir_all(&work);
}

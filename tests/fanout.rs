//! Fan-out end to end: one `send --to r1,r2,r3` against three real receivers
//! on loopback, then the same send with one receiver dead.
//!
//! The timing proof that the sends overlap lives in the unit tests for
//! `run_bounded` (a wall-clock assert on sleeping jobs) and in the 1 GiB
//! benchmark in the PR description — not here, where a loaded CI machine
//! would make any timing bound flaky. This test pins the behaviour contract
//! instead: every live host gets the exact bytes, a dead host fails the run
//! without costing the others their delivery, and the per-host report names
//! each host.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zapsend"))
}

/// A receiver that is killed when the test ends, even on panic.
struct Receiver {
    child: Option<Child>,
    dir: PathBuf,
    fingerprint: String,
    port: u16,
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

fn start_receiver(work: &Path, name: &str, port: u16) -> Receiver {
    let dir = work.join(format!("recv-{name}"));
    fs::create_dir_all(&dir).unwrap();
    let log_path = work.join(format!("recv-{name}.log"));
    let log = fs::File::create(&log_path).unwrap();
    let child = Command::new(bin())
        .args([
            "receive",
            "--port",
            &port.to_string(),
            "--alias",
            name,
            "--dir",
            dir.to_str().unwrap(),
        ])
        .env("ZAPSEND_CONFIG", work.join("hosts.json"))
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();

    // The receiver prints its fingerprint in the startup banner; poll the
    // log for it instead of sleeping a fixed amount.
    let deadline = Instant::now() + Duration::from_secs(20);
    let fingerprint = loop {
        let mut text = String::new();
        if let Ok(mut f) = fs::File::open(&log_path) {
            let _ = f.read_to_string(&mut text);
        }
        if let Some(fp) = parse_fingerprint(&text) {
            break fp;
        }
        if Instant::now() > deadline {
            panic!("receiver {name} on :{port} never printed a fingerprint:\n{text}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    Receiver {
        child: Some(child),
        dir,
        fingerprint,
        port,
    }
}

fn parse_fingerprint(log: &str) -> Option<String> {
    let at = log.find("fingerprint ")? + "fingerprint ".len();
    let fp: String = log[at..].chars().take(64).collect();
    if fp.len() == 64 && fp.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(fp)
    } else {
        None
    }
}

fn send(work: &Path, payload: &Path, to: &str) -> std::process::Output {
    Command::new(bin())
        .args(["send", payload.to_str().unwrap(), "--to", to])
        .env("ZAPSEND_CONFIG", work.join("hosts.json"))
        .output()
        .unwrap()
}

#[test]
fn fan_out_delivers_to_all_and_survives_a_dead_host() {
    let work = std::env::temp_dir().join(format!("zapsend-fanout-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).unwrap();

    // Deterministic payload: 4 MiB, big enough to be a real transfer.
    let payload = work.join("payload.bin");
    let bytes: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    fs::write(&payload, &bytes).unwrap();

    let mut receivers: Vec<Receiver> = ["r1", "r2", "r3"]
        .iter()
        .enumerate()
        .map(|(i, name)| start_receiver(&work, name, 53510 + i as u16))
        .collect();

    // The hosts file the sender resolves `--to` names from. All three
    // receivers share the machine identity, so the fingerprints match, but
    // each entry is still written from its own receiver's banner.
    let hosts = receivers
        .iter()
        .enumerate()
        .map(|(i, r)| {
            format!(
                "\"r{}\": {{\"ip\": \"127.0.0.1\", \"port\": {}, \"fingerprint\": \"{}\"}}",
                i + 1,
                r.port,
                r.fingerprint
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    fs::write(work.join("hosts.json"), format!("{{{hosts}}}")).unwrap();

    let out = send(&work, &payload, "r1,r2,r3");
    assert!(
        out.status.success(),
        "fan-out to 3 live hosts must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("3 of 3 peer(s)"),
        "summary must name all three hosts: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    for r in &receivers {
        let got = fs::read(r.dir.join("payload.bin")).unwrap();
        assert_eq!(got, bytes, "receiver on :{} got different bytes", r.port);
    }

    // One host dead: the other two still get the file, the run still fails,
    // and the report names the dead host.
    receivers[2].kill();
    for r in &receivers[..2] {
        fs::remove_file(r.dir.join("payload.bin")).unwrap();
    }
    let out = send(&work, &payload, "r1,r2,r3");
    assert!(
        !out.status.success(),
        "a fan-out with a dead host must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stderr.contains("✓ r1"),
        "live host r1 must be reported ok: {stderr}"
    );
    assert!(
        stderr.contains("✓ r2"),
        "live host r2 must be reported ok: {stderr}"
    );
    assert!(
        stderr.contains("✗ r3"),
        "dead host r3 must be reported failed: {stderr}"
    );
    assert!(
        stdout.contains("2 of 3 peer(s)"),
        "summary must count 2 of 3: {stdout}"
    );
    for r in &receivers[..2] {
        let got = fs::read(r.dir.join("payload.bin")).unwrap();
        assert_eq!(got, bytes, "receiver on :{} got different bytes", r.port);
    }

    for r in &mut receivers {
        r.kill();
    }
    let _ = fs::remove_dir_all(&work);
}

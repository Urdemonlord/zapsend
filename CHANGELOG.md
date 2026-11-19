# Changelog

All notable changes to zapsend. The format follows Keep a Changelog;
versions follow Semantic Versioning (in 0.x, a minor bump may break
compatibility).

## Unreleased

### Added
- Speed: parallel SHA-256 hashing across files, an on-disk hash cache
  (`~/.cache/zapsend/hashes.json`), up to 4 concurrent file uploads, and
  256 KiB transfer chunks. 1 GiB loopback: 33.9 s -> 10.1 s with a warm
  cache (~101 MB/s). (PR #1)
- Security: `--ip` without a fingerprint is now refused; use
  `zapsend trust NAME`, `--fingerprint`, or `--tofu` to pin a peer on
  first use. (PR #2)
- Sync: `sync --replace` replaces a changed file on the receiver, backing
  the old file up first and verifying the hash afterwards. Without the
  flag, a conflict still aborts the run. (PR #2)
- Distribution: GitHub Release workflow (Linux x86_64 + aarch64, Windows
  x86_64) and an `install.sh` one-line installer with SHA-256 verification.

### Fixed
- Resume: a resumed upload used to overwrite the stored prefix from
  position 0 and silently restart from scratch. It now seeks to the stored
  offset. (PR #1)

## 0.0.24 - 2026-11-18

- First crates.io release: LocalSend-compatible send/receive, resume,
  folders, fan-out/fan-in, watched folder, sync, browser share page,
  `doctor`, JSON output.

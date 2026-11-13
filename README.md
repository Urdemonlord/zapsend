# zapsend

**Headless, LocalSend-compatible file transfer over your local network.**

Send files from your terminal to any device running [LocalSend](https://localsend.org) —
no app to install on the other side, no account, no cloud, no size limit.

```
$ zapsend send film.mkv --to pixel
sending film.mkv to "pixel" (192.168.1.42:53317)
film.mkv [============>               ] 1.2 GiB/4.1 GiB (12s)
✓ done
```

> **Status: v0.0.1 — early.** Send and receive work. Resume, folders and a
> daemon mode are not implemented yet. See [roadmap](#roadmap).

---

## Why

LocalSend already exists, and it is good. But it is a GUI app: there is no
official way to send a file *from a server*, over SSH, from a cron job, or from
a box with no display.

The LocalSend protocol even reserves `deviceType: "headless"` for exactly this.
Nobody filled that slot. Zapsend does.

Because zapsend speaks the real protocol, **the receiving device does not need
zapsend**. Anything that runs LocalSend — Android, iOS, Windows, macOS, Linux —
can talk to it.

## Install

```sh
cargo install --git https://github.com/YOURNAME/zapsend
```

Or build locally:

```sh
git clone https://github.com/YOURNAME/zapsend
cd zapsend && cargo build --release
./target/release/zapsend --help
```

Single static binary. No runtime dependencies. Runs on x86_64 and aarch64,
including a Raspberry Pi.

## Try it in 30 seconds

`demo.sh` runs both ends on one machine and verifies the result:

```sh
./demo.sh
```

```
▸ starting receiver on :53400
▸ discovering devices
ALIAS                    ADDRESS              TYPE       FINGERPRINT
nas                      192.168.1.77:53400   headless   ab9628b1…
▸ sending 8MB over discovery
✓ done
▸ verifying
  source 8c20157ca2d240088dbd4ecd69f0eb2d41820d6271942f5fd7e390fc762cc25f
  dest   8c20157ca2d240088dbd4ecd69f0eb2d41820d6271942f5fd7e390fc762cc25f
✓ byte-identical (8MB)
```

If your network blocks multicast (guest wifi, corporate VLAN, many VMs), the
script detects that and falls back to `--ip`, printing why.

## Usage

### Find devices

```sh
$ zapsend discover
scanning for 5s…

ALIAS                    ADDRESS              TYPE       FINGERPRINT
pixel                    192.168.1.42:53317   mobile     9f2c1ab4…
thinkpad                 192.168.1.10:53317   desktop    c41e77d0…
```

### Send a file

```sh
zapsend send report.pdf --to pixel

# or skip discovery entirely, including a non-default port
zapsend send report.pdf --ip 192.168.1.42
zapsend send report.pdf --ip 192.168.1.42:53400
```

The receiver shows a normal LocalSend prompt — accept it there and the file lands.

### Receive files

```sh
zapsend receive --dir ~/Downloads
```

Keeps running, announces itself on the network, and accepts incoming transfers.
Now every phone on your LAN can push files to your NAS.

### Run two instances on one machine

The protocol keeps multicast on `53317` but lets the API live elsewhere, so:

```sh
zapsend receive --port 53400 --alias nas --dir ./inbox
zapsend discover            # finds "nas" on :53400
```

## How it works

Zapsend implements [LocalSend protocol v2](https://github.com/localsend/protocol):

| Piece | What zapsend does |
|---|---|
| Discovery | UDP multicast to `224.0.0.167:53317`, plus the `POST /register` handshake |
| Identity | Self-signed cert, SHA-256 fingerprint pinned by the peer |
| Transfer | `POST /prepare-upload` for metadata, then `POST /upload` streamed |
| Ports | Multicast always `53317`; API port configurable via `--port` |

Everything is streamed — a 40 GB file does not touch RAM. Incoming file names
are sanitized, and existing files are never overwritten (`a.txt` → `a (1).txt`).

## Roadmap

- [x] Multicast discovery + `discover`
- [x] `register` handshake over HTTPS
- [x] Send a single file
- [x] Receive into a directory
- [x] Configurable API port (two instances per machine)
- [ ] Multiple files per transfer
- [ ] Folder transfer
- [ ] Resume interrupted transfers
- [ ] PIN-protected receiving
- [ ] `zapsend daemon` with a watch folder
- [ ] Fingerprint verification on send (currently accepts any cert)
- [ ] Download API (reverse transfer: pull files *from* a peer)
- [ ] mDNS fallback for networks that block multicast

## Known limitations

- **v0.0.1 accepts any TLS certificate** when sending. Fingerprint pinning is
  on the roadmap; until then, only send to networks you trust.
- Files are hashed (SHA-256) before upload, which costs an extra read pass.
- No resume yet: a dropped connection means starting over.
- **Interop with the real LocalSend app is not verified yet.** The wire format
  follows the spec and has been tested zapsend↔zapsend, but until someone
  round-trips against LocalSend on a phone, treat that path as untested.

## Troubleshooting

**No devices found.** Most likely the network blocks multicast — common on
guest wifi, corporate networks and some university APs. Use `--ip <address>`.

**"API server on :53317 unavailable".** Another LocalSend or zapsend already
holds the port. The operation continues; pass `--port` to run alongside it.

**Receiver rejects the transfer.** Some LocalSend configurations require
accepting manually. Check the screen of the receiving device.

## License

MIT — see [LICENSE](LICENSE).

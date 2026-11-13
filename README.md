# zap

**Headless, LocalSend-compatible file transfer over your local network.**

Send files from your terminal to any device running [LocalSend](https://localsend.org) —
no app to install on the other side, no account, no cloud, no size limit.

```
$ zap send film.mkv --to pixel
sending film.mkv to "pixel" (192.168.1.42)
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
Nobody filled that slot. Zap does.

Because zap speaks the real protocol, **the receiving device does not need zap**.
Anything that runs LocalSend — Android, iOS, Windows, macOS, Linux — can talk to it.

## Install

```sh
cargo install --git https://github.com/YOURNAME/zap
```

Or build locally:

```sh
git clone https://github.com/YOURNAME/zap
cd zap && cargo build --release
./target/release/zap --help
```

Single static binary. No runtime dependencies. Runs on x86_64 and aarch64,
including a Raspberry Pi.

## Usage

### Find devices

```sh
$ zap discover
scanning for 5s…

ALIAS                    ADDRESS              TYPE       FINGERPRINT
pixel                    192.168.1.42:53317   mobile     9f2c1ab4…
thinkpad                 192.168.1.10:53317   desktop    c41e77d0…
```

### Send a file

```sh
zap send report.pdf --to pixel

# or skip discovery entirely
zap send report.pdf --ip 192.168.1.42
```

The receiver shows a normal LocalSend prompt — accept it there and the file lands.

### Receive files

```sh
zap receive --dir ~/Downloads
```

Keeps running, announces itself on the network, and accepts incoming transfers.
Now every phone on your LAN can push files to your NAS.

## How it works

Zap implements [LocalSend protocol v2](https://github.com/localsend/protocol):

| Piece | What zap does |
|---|---|
| Discovery | UDP multicast to `224.0.0.167:53317`, plus the `POST /register` handshake |
| Identity | Self-signed cert, SHA-256 fingerprint pinned by the peer |
| Transfer | `POST /prepare-upload` for metadata, then `POST /upload` streamed |
| Ports | `53317` for both UDP and TCP, as per spec |

Everything is streamed — a 40 GB file does not touch RAM.

## Roadmap

- [x] Multicast discovery + `discover`
- [x] `register` handshake over HTTPS
- [x] Send a single file
- [x] Receive into a directory
- [ ] Multiple files per transfer
- [ ] Folder transfer
- [ ] Resume interrupted transfers
- [ ] PIN-protected receiving
- [ ] `zap daemon` with a watch folder
- [ ] Fingerprint verification on send (currently accepts any cert)
- [ ] Download API (reverse transfer: pull files *from* a peer)
- [ ] mDNS fallback for networks that block multicast

## Known limitations

- **v0.0.1 accepts any TLS certificate** when sending. Fingerprint pinning is
  on the roadmap; until then, only send to networks you trust.
- **One instance per machine.** Both the UDP and TCP side bind `53317`.
- Files are hashed (SHA-256) before upload, which costs an extra read pass.
- No resume yet: a dropped connection means starting over.

## Troubleshooting

**No devices found.** Most likely the network blocks multicast — common on
guest wifi, corporate networks and some university APs. Use `--ip <address>`.

**"Address already in use".** Another LocalSend (or another zap) is running on
this machine.

**Receiver rejects the transfer.** Some LocalSend configurations require
accepting manually. Check the screen of the receiving device.

## License

MIT — see [LICENSE](LICENSE).

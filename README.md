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
cargo install --git https://github.com/Urdemonlord/zapsend
```

Or build locally:

```sh
git clone https://github.com/Urdemonlord/zapsend
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
  peer fingerprint ab9628b112df49e2…
▸ discovering devices
ALIAS                    ADDRESS              TYPE       FINGERPRINT
nas                      192.168.1.77:53400   headless   ab9628b1…
▸ sending 3 files over discovery (fingerprint pinned automatically)
sending 3 file(s), 13.3 MiB to "nas" (192.168.1.77:53400)
  pinned to ab9628b1
✓ done
▸ verifying
✓ photo.jpg  0ee1cf51e902ff3f…
✓ notes.pdf  2d75bb88795c4827…
✓ clip.mp4   7d99e9346049726a…
▸ rejecting a wrong fingerprint
✓ wrong fingerprint was refused
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

### Send files

```sh
zapsend send report.pdf --to pixel
zapsend send photo.jpg notes.pdf clip.mp4 --to pixel

# or skip discovery entirely, including a non-default port
zapsend send report.pdf --ip 192.168.1.42
zapsend send report.pdf --ip 192.168.1.42:53400
```

The receiver shows a normal LocalSend prompt — accept it there and the files land.

### Receive files

```sh
zapsend receive --dir ~/Downloads

# require a PIN — omit the value and one is generated for you
zapsend receive --dir ~/Downloads --pin
zapsend receive --dir ~/Downloads --pin 424242

# confirm each transfer instead of accepting silently
zapsend receive --dir ~/Downloads --ask
```

```
  +--------------------------------------------+
  | zapsend 0.0.1                              |
  | headless file transfer, LocalSend protocol |
  +--------------------------------------------+

  listening   :53317
  alias       thinkpad
  fingerprint ab9628b112df49e2cafce94d17bb062a
  pin         none — anyone on this network can send to you
  saving to   /home/you/Downloads
  mode        accept automatically

  ctrl-c to stop
```

Keeps running, announces itself on the network, and accepts incoming transfers.
Now every phone on your LAN can push files to your NAS.

Silent acceptance is the right default for a NAS or a server: nothing to approve,
nothing to click. On a laptop you probably want `--ask` instead, which shows the
sender and the file list and waits for `y`. It refuses to start if stdin is not a
terminal, so it cannot hang under systemd.

Printing the PIN is deliberate: it goes to your terminal, not to the network.
Peers find out a PIN is required only when they get a `401`.

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
| Identity | Self-signed cert; the sender pins the peer's SHA-256 fingerprint |
| Transfer | `POST /prepare-upload` for metadata, then `POST /upload` streamed |
| Ports | Multicast always `53317`; API port configurable via `--port` |

Everything is streamed — a 40 GB file does not touch RAM. Incoming file names
are sanitized, and existing files are never overwritten (`a.txt` → `a (1).txt`).

### Security model

LocalSend uses self-signed certificates, so there is no CA to trust. Trust comes
from pinning instead:

1. Discovery tells you the peer's fingerprint — the SHA-256 of its certificate.
2. When connecting, zapsend accepts **only** the certificate hashing to that
   exact value. Anything else fails the handshake before a byte is sent.

That means a machine-in-the-middle on the LAN cannot impersonate a peer, even
though the certificate is self-signed. It also means the fingerprint is the
whole security story: if you pass `--fingerprint` by hand, get it from
`zapsend discover` on the same network, not from a chat message.

Pinning proves *who* you are talking to. A PIN proves *whether you are allowed*.
They solve different problems, and the receiver needs the PIN because sending
requires no confirmation on its side:

- Wrong or missing PIN → `401`, and the sender is told to retry with `--pin`
- Five wrong attempts → `429`, locked for 60 seconds

That throttle is what makes a 6-digit PIN meaningful; without it, 10^6 guesses
over a LAN is an afternoon script.

## Roadmap

- [x] Multicast discovery + `discover`
- [x] `register` handshake over HTTPS
- [x] Send a single file
- [x] Receive into a directory
- [x] Configurable API port (two instances per machine)
- [x] Multiple files per transfer
- [x] Fingerprint pinning on send
- [ ] Folder transfer
- [ ] Resume interrupted transfers
- [x] PIN-protected receiving
- [x] Interactive accept prompt (`--ask`)
- [x] `--verbose` payload dumps for protocol debugging
- [ ] `zapsend daemon` with a watch folder
- [ ] Download API (reverse transfer: pull files *from* a peer)
- [ ] mDNS fallback for networks that block multicast

## Known limitations

- **PIN throttling is global, not per-peer.** Five wrong attempts lock the
  receiver for everyone for a minute, so someone on the network can briefly
  deny service to legitimate senders. Per-address throttling is on the roadmap.
- **`--ip` without `--fingerprint` is unverified.** Sending to a raw address
  skips discovery, so there is no fingerprint to pin against; zapsend warns
  and accepts whatever certificate answers. Pass `--fingerprint` (get it from
  `zapsend discover`) to close that hole. Discovery-based sends are always pinned.
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

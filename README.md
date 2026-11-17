<p align="center">
  <img src="assets/logo.svg" alt="ZapSend" width="360">
</p>

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

If your network blocks multicast (guest wifi, corporate VLAN, many VMs, a phone
hotspot), the script detects that and falls back to `--ip`, printing why.

`discover` and `send --to` do the same thing automatically: when nothing answers
multicast, they unicast `POST /register` to every host on their own `/24` (the
spec's legacy discovery), which gets through where multicast does not. If the
default port is already held — usually by a running `receive` — they announce a
free port instead of going blind.

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

A folder argument is walked recursively and arrives with its tree intact:
`zapsend send ./holiday --to pixel` lands as `holiday/2024/img.jpg` on the other
side. Folders and single files mix freely in one command. Empty folders are not
recreated — the protocol has no way to express a directory without files.

The receiver shows a normal LocalSend prompt — accept it there and the files land.

### Browse and send from a browser

```sh
zapsend ui --dir ~/Downloads
```

<img src="docs/ui.png" alt="ZapSend web UI: device list, drop zone, send button" width="640">

Starts the normal receiver plus a page on `http://127.0.0.1:53318/` (plain
HTTP on loopback, so no certificate warning; peers still get HTTPS on 53317).
The page lists discovered devices, takes drag & drop or absolute paths, and
sends. Dropped files are staged to a temp dir first — browsers hand over bytes,
never a path — so drop a folder as a path if you want its tree preserved.

```sh
zapsend ui --ui-port 8080 --no-open    # different page port, don't launch a browser
```

### Watch a folder and send automatically

```sh
zapsend daemon --dir ./outbox --to "Pixel"
```

Anything that lands in `./outbox` is sent to that device, then moved to
`./outbox/.sent` so it is not sent twice. Folders are sent as a tree, same as
`zapsend send`.

```sh
zapsend daemon --dir ~/Pictures --ip 192.168.1.42 --keep
zapsend daemon --dir ./outbox --to "Pixel" --settle 10   # big slow copies
```

- **Polling, not inotify** — one directory read per `--interval` (default 2s).
- **A file is only sent once it has stopped changing.** A tree has to sit
  untouched for `--settle` seconds (default: twice `--interval`, at least 3), so
  a copy in progress is never shipped half-finished.
- **Delivery survives the other device being away.** If the send fails the file
  stays put and is retried on the next tick; the error is printed once, not
  every tick. The target is re-discovered each time, because addresses move.
- **Ignored names:** dotfiles, `~$*` (Office locks), and `*.tmp`, `*.part`,
  `*.partial`, `*.crdownload`, `*.download`, `*.swp`, `*.filepart`.
- **`--keep`** leaves files in place instead of moving them, remembering what it
  already delivered for as long as the daemon runs.
- The daemon runs the normal API server so peers can see it, which means it can
  also receive: anything pushed to it lands in `<dir>/.incoming`.

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
| Discovery | UDP multicast to `224.0.0.167:53317`, plus the `POST /register` handshake; `/24` unicast sweep when multicast is blocked |
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
- [x] Folder transfer
- [ ] Resume interrupted transfers
- [x] PIN-protected receiving
- [x] Interactive accept prompt (`--ask`)
- [x] `--verbose` payload dumps for protocol debugging
- [x] Local web UI (`zapsend ui`)
- [x] `zapsend daemon` with a watch folder
- [ ] Download API (reverse transfer: pull files *from* a peer)
- [x] `/24` unicast sweep for networks that block multicast (covers the mDNS case)

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
- **Interop is verified against LocalSend on Android only.** Both directions
  round-trip (phone→PC receive, PC→phone send) and the two see each other in
  discovery. iOS, macOS and the LocalSend desktop builds are untested; the wire
  format follows the spec but nobody has run them.

## Troubleshooting

**No devices found.** Most likely the network blocks multicast — common on
guest wifi, corporate networks and some university APs. Use `--ip <address>`.

**`:53317` is already in use.** Another LocalSend or zapsend holds it. `receive`
stops with an error on purpose — a receiver that cannot listen is useless. Send
and discover announce a free port instead and keep working.

**Receiver rejects the transfer.** Some LocalSend configurations require
accepting manually. Check the screen of the receiving device.

## Brand

The mark is a Z built from two arrows — one leaving, one arriving — with speed
dashes for the "zap". All of it is vector, and the wordmark is outlines rather
than live text, so the logo renders identically with no font installed.

| File | Use |
| --- | --- |
| `assets/logo.svg` | Lockup on a dark card (README, slides) |
| `assets/logo-mark.svg` | Icon only, transparent — UI, favicon, docs |
| `assets/wordmark.svg` | Wordmark only, transparent |
| `assets/app-icon-dark.svg` / `-light.svg` | App icon, dark and light |
| `assets/monochrome-dark.svg` / `-light.svg` | One-ink versions |
| `assets/avatar.svg` | Circular GitHub avatar |
| `assets/*.png` | 1024 px raster exports of the above |

Palette: `#20E889` primary, `#087F68` secondary, `#F8FAFC` text, `#0B0F10`
background. The mark's gradient runs from primary at the top-right arrowhead to
secondary at the bottom-left. The light app icon deliberately uses flat
background ink on primary green instead of the gradient — a mint gradient on a
mint tile would disappear.

`zapsend ui` serves the icon at `/favicon.svg`; the terminal banner uses the
brand colours when stdout is a terminal and `NO_COLOR` is unset.

## License

MIT — see [LICENSE](LICENSE).

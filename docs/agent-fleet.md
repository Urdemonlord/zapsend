# Running zapsend across a fleet of machines

This is the setup zapsend was built for: a few servers running agents, plus your
laptop, and data that has to move between them without going through somebody
else's cloud.

The idea is one small piece of plumbing per machine:

- every machine runs **one long-lived `zapsend receive`** — its mailbox
- **`--dir`** is where other machines put things (`inbox/`)
- **`--share`** is what other machines may pull (`outbox/`)
- **`--pin`** is that machine's shared secret
- agents never speak the network: they write into `outbox/` and read from
  `inbox/`, and moving the bytes is somebody else's job

Everything below was run for real on a Linux VPS with the released `v0.0.13`
binary, except where it says otherwise.

## Networking: put the machines on a private network

LocalSend discovers peers with multicast, which does not cross subnets — so
between two VPSes, or a VPS and a laptop on home Wi-Fi, there is no discovery.
You connect with `--ip` instead.

Do **not** open 53317 to the internet to make that work. The certificate is
self-signed and the only authentication is a PIN; a public port is a public
mailbox. Put the machines on Tailscale (or WireGuard) instead: each gets a
stable address, nothing is exposed, and zapsend just talks to `100.x.y.z:53317`
over that private link.

> Tailscale itself was not exercised here — the checks below used loopback. What
> is verified is that zapsend needs nothing but a reachable `host:port`.

## Linux: run the mailbox as a service

```ini
# /etc/systemd/system/zapsend.service
[Unit]
Description=zapsend receiver (agent inbox/outbox)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=meowlabs
ExecStart=/usr/local/bin/zapsend receive \
    --dir /home/meowlabs/zap/inbox \
    --share /home/meowlabs/zap/outbox \
    --port 53317 --pin 4021
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

```sh
sudo cp zapsend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zapsend
systemctl is-active zapsend          # active
curl -sk 'https://127.0.0.1:53317/api/localsend/v2/info?pin=4021'
```

Verified behaviour of that unit:

- `systemctl is-active` → `active`, `is-enabled` → `enabled`
- `/info` reports `"zapsendResume":true,"download":true` (the `--share` flag is
  what turns the download API on)
- `systemctl kill --signal=KILL zapsend` → the PID changed (`2420120` →
  `2420677`) and the next `pull` still worked, so a crashed mailbox comes back on
  its own
- journal shows the fingerprint, which is what you pin from the other side:

```
  fingerprint ab9628b112df49e2cafce94d17bb062ad4cdaa115bfa009d761e2789444d7b60
  pin         4021  (required for incoming transfers)
  sharing     /home/meowlabs/zap/outbox (Download API on)
```

Run it as a dedicated user if the agent does not need to share a UID with it; the
only thing that matters is that `--dir` and `--share` are writable/readable by
that user.

## Windows: a scheduled task at logon

Not verified here (no Windows machine in this environment) — treat it as a
recipe, not as tested output.

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\Users\click\zapsend.exe" `
  -Argument 'receive --dir C:\Users\click\zap\inbox --share C:\Users\click\zap\outbox --port 53317 --pin 4021'
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName zapsend -Action $action -Trigger $trigger `
  -Description "zapsend mailbox" -RunLevel Limited
```

Or, if you would rather not keep a task around, the same command in a hidden
window from a startup shortcut. For a machine that must serve without anybody
logged in, use "Run whether user is logged on or not", which needs stored
credentials and a working network at boot — check `zapsend doctor` afterwards,
it is the quickest way to see whether the port actually came up.

## Teach each machine about the others, once

Every other machine gets one `trust` entry — address, port, fingerprint and PIN —
and after that nothing needs a flag:

```sh
zapsend trust gpu-box --ip 100.64.0.7 --pin 4021
```

`trust` reaches the machine, records its certificate fingerprint, and pins it, so
the connection is verified even though discovery never ran. If you would rather
check the fingerprint yourself, read it from the receiver's startup line
(`journalctl -u zapsend` on Linux, the console on Windows) or from `/info`, then:

```sh
zapsend trust gpu-box --ip 100.64.0.7 --pin 4021 \
  --fingerprint ab9628b112df49e2cafce94d17bb062ad4cdaa115bfa009d761e2789444d7b60
```

A fingerprint that does not match the machine is refused and nothing is written.
`zapsend hosts` lists what you have; `zapsend forget <name>` removes one.

`--pin` on the command line beats `ZAPSEND_PIN` beats the stored PIN, so you can
keep the secret in the service environment instead of the file.

## Recipes

**Pull a result off a server** (agent wrote it into `outbox/`):

```sh
zapsend pull --to gpu-box --dir ./results
```

**Push a dataset to a server** (it lands in that machine's `inbox/`):

```sh
zapsend send ./dataset --to agent-b
```

**Server to server, no laptop in the middle:** run `pull --to agent-b` on A. The
bytes never leave your private network, and no third party sees them.

**Let the machine send by itself:** `zapsend daemon --dir ./outbox --to agent-b`
watches a folder, waits for files to settle, sends them, and renames them to
`.sent`. That is the "agent drops output, plumbing delivers it" pattern — the
agent does not need to know zapsend exists.

**Health check before you blame the tool:**

```sh
zapsend doctor --to gpu-box
```

Naming a machine also means a quiet multicast bus is no longer counted as a
failure — on a VPN nothing is supposed to answer discovery.

## Security, plainly

- TLS protects the bytes in transit; `--fingerprint` is what proves the machine
  at the other end is the one you meant. Without it you are trusting the network.
- The PIN is per-address rate limited: five wrong guesses lock that address out
  for a minute, and a correct PIN from another address is unaffected.
- `--share` exposes **everything** in that directory to anyone who has the PIN.
  Dotfiles are skipped and symlinks are not followed, and paths cannot escape the
  shared directory — but there is no per-file permission model.
- So: an `outbox/` is a mailbox, not a vault. Do not park secrets there.

## Limits

- `pull` does not resume yet — a broken pull restarts the file (`send` does resume).
- No JSON output yet — use exit codes, or parse the human text.
- Discovery does not cross subnets, by design of the protocol; that is what
  `trust` is for.
- Files are never overwritten: a second `report.txt` becomes `report (1).txt`.
- `trust` checks the machine's fingerprint, but nothing stops you from typing
  `--fingerprint` for a machine that is down: it is stored unverified, and it is
  on you to have copied the right value.

The first two are the next things on the list.

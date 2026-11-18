# Contributing

Small tool, small rules. The bar is not "does it work on my machine" — it is
"can the next person see why it works".

## Build and test

```sh
cargo build --release
cargo test --release      # unit tests
./demo.sh                 # two processes on one machine, verifies the result
```

`BIN=./target/release/zapsend ./demo.sh` runs the demo against the release
binary. `SIZE_MB=64` uses a bigger payload.

If you change anything on the wire — request shapes, discovery, the Download
API — run the interop script too. It drives a second implementation of the same
protocol against ours:

```sh
LSQ=/path/to/lsq ./tests/interop-lsq.sh ./target/release/zapsend
```

## What a good pull request looks like

- **One change.** A page fix and a protocol fix in one PR take twice as long to
  review and half as long to trust.
- **It says what was observed, not what was intended.** "The arrow sat at a
  different x per row because a glyph shared a right-aligned run with numbers"
  beats "improved spacing".
- **Behaviour changes come with a check.** A new branch in `sync` gets a line in
  the matching test script; a new page element gets a grep check in
  `tests/page`-style scripts. Tests here are shell scripts and `cargo test`, not
  a framework — keep it that way.
- **No new dependency** for something stdlib or an already-present crate does.
  Every crate you add is a build someone else has to reproduce on a machine with
  no internet.
- **Nothing is claimed that was not run.** If you tested on Windows via wine,
  say wine. If a page was only checked with `curl`, say so.

## Reporting a bug

Include the version (`zapsend --version`), the exact command, the peer it talked
to (zapsend, LocalSend app + version + OS), and the output with `ZAPSEND_JSON=1`
if the failure is in a script. "It did not work" costs a round trip; the four
facts above usually make the bug obvious.

## Scope

In scope: headless transfers, the fleet commands, the share page, and anything
that makes a machine with nobody in front of it easier to move data from.

Out of scope: a GUI, a cloud relay, an account system, and anything that needs a
service running somewhere other than the two endpoints.

## License

MIT. By opening a pull request you agree your contribution is licensed the same
way.

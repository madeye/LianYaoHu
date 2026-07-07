# LianYaoHu

LianYaoHu is a Rust CLI/TUI launcher for running Claude Code, Codex, or another
code agent inside a constrained macOS process sandbox while forcing agent TCP/UDP
traffic through a selected VPN `utun` interface.

Run directly during development:

```sh
cargo run -p lianyaohu -- --vpn utun5 -- claude
cargo run -p lianyaohu -- --vpn utun5 -- codex
```

By default it:

- prompts for a VPN `utun` interface at startup;
- requires the default IPv4 route to use the selected `utun`;
- runs the agent through `sandbox-exec` with read/write access to `$HOME`,
  `$PWD`, and an isolated temporary directory;
- removes host-identifying environment variables and sets `TZ=UTC`;
- denies raw/system sockets, socket ioctls, inbound sockets, socket binding, and
  broad `sysctl` reads in the process sandbox;
- installs a temporary PF anchor under `com.apple/lianyaohu-$uid` to block LAN
  destinations, route IPv4 TCP/UDP to the selected point-to-point `utun` peer,
  and block non-`utun` TCP/UDP egress for the current user while the agent runs.

## Root Helper

PF enforcement requires root. LianYaoHu first tries a root LaunchDaemon helper at
`/var/run/lianyaohu-helper.sock`; if it is not installed, it falls back to
`sudo pfctl`.

Install the helper once:

```sh
scripts/install-helper.sh
```

Remove it:

```sh
scripts/uninstall-helper.sh
```

The helper authenticates requests with `getpeereid`, generates PF rules for the
peer UID, validates that the requested interface is an active `utun`, and only
supports `install`, `uninstall`, and `status` operations.

For inspection without applying PF:

```sh
cargo run -p lianyaohu -- --vpn utun5 --print-profile
cargo run -p lianyaohu -- --vpn utun5 --print-pf
cargo run -p lianyaohu -- --vpn utun5 --no-pf -- claude
```

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The tests validate policy generation, environment filtering, PF token parsing,
route-output parsing, and selected runtime sandbox denials. They do not install
PF rules or launch a real agent.

## License

LianYaoHu is licensed under the MIT License.

Copyright (c) 2026 Max Lv.

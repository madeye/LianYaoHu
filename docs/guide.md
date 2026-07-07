# Getting Started

LianYaoHu is a Rust CLI/TUI launcher for running Claude Code, Codex, or
another code agent inside a constrained macOS process sandbox while forcing
agent TCP/UDP traffic through a selected VPN `utun` interface.

## Run

```sh
cargo run -p lianyaohu -- --vpn utun5 -- claude
cargo run -p lianyaohu -- --vpn utun5 -- codex
```

By default it:

- prompts for a VPN `utun` interface at startup;
- requires the default IPv4 route to use the selected `utun`;
- asks the root helper to run the agent as the caller's UID with the dedicated
  `_lianyaohu` effective GID, then applies `sandbox-exec`;
- removes host-identifying environment variables and sets `TZ=UTC`;
- exposes the caller's `$HOME` as read-only, while `--cwd` and a per-launch
  temporary directory are writable;
- denies raw/system sockets, socket ioctls, inbound sockets, socket binding,
  and broad `sysctl` reads in the process sandbox;
- installs a temporary PF anchor under `com.apple/lianyaohu-$uid` to match the
  `_lianyaohu` group, block LAN destinations, route IPv4 TCP/UDP to the
  selected point-to-point `utun` peer, and block non-`utun` TCP/UDP egress for
  only that sandboxed agent tree.

## Root helper

PF enforcement and dedicated-group isolation require root. LianYaoHu uses a
root LaunchDaemon helper at `/var/run/lianyaohu-helper.sock` to create/validate
the hidden `_lianyaohu` group, install group-scoped PF rules, drop the child to
`uid=caller_uid,gid=_lianyaohu` while keeping the caller's normal supplementary
groups, and launch `sandbox-exec` with the caller's stdio.

Install the helper once:

```sh
scripts/install-helper.sh
```

Remove it:

```sh
scripts/uninstall-helper.sh
```

The helper authenticates requests with `getpeereid`, validates that the
requested interface is an active `utun`, and supports the default session run
path plus `install`, `uninstall`, and `status` for the current-UID fallback.

Because the child keeps the caller's UID, normal owner-based access to `$HOME`,
the working tree, keychain, and TCC state behaves like the desktop user. The
sandbox profile still does not grant write access to `$HOME` except for the
selected working directory when it lives under `$HOME`.

## Options

```text
usage:
  lianyaohu [options] [-- agent [args...]]

options:
  --vpn NAME                  Select a utun interface without prompting.
  --cwd PATH                  Working directory exposed to the agent.
  --env NAME=VALUE            Add an environment variable unless it is privacy-blocked.
  --no-pf                     Do not install the PF guard. Intended for tests and debugging.
  --shared-user-pf            Use current-UID PF rules instead of helper-managed group isolation.
  --allow-non-default-route   Do not require the system default route to use the selected utun.
  --helper-status             Query the root PF helper status for this user.
  --print-profile             Print the generated sandbox-exec profile and exit.
  --print-pf                  Print the generated PF anchor rules and exit.

default command:
  claude
```

For inspection without applying PF:

```sh
cargo run -p lianyaohu -- --vpn utun5 --print-profile
cargo run -p lianyaohu -- --vpn utun5 --print-pf
cargo run -p lianyaohu -- --vpn utun5 --no-pf -- claude
cargo run -p lianyaohu -- --vpn utun5 --shared-user-pf -- claude
```

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The tests validate policy generation, environment filtering, PF token
parsing, route-output parsing, and selected runtime sandbox denials. They do
not install PF rules or launch a real agent. For the full-stack test in a VM,
see [End-to-End Testing](/e2e-testing).

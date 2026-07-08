# Getting Started

LianYaoHu is a Rust CLI/TUI launcher for running Claude Code, Codex, or
another code agent with a sanitized environment and a helper-managed network
guard while forcing agent traffic through a selected VPN interface. macOS uses
`sandbox-exec` plus PF on `utun*`; Linux uses Landlock/seccomp plus
owner-scoped iptables/ip6tables rules on `tun*` or `wg*`.

## Run

```sh
cargo run -p lianyaohu-app -- --vpn utun5 -- claude
cargo run -p lianyaohu-app -- --vpn utun5 -- codex
cargo run -p lianyaohu-app -- --vpn tun0 -- codex
```

By default it:

- prompts for a supported VPN interface at startup;
- requires the default IPv4 route to use the selected VPN interface;
- on macOS, applies `sandbox-exec` and a PF anchor scoped to the launched
  process group;
- on Linux, applies a Landlock/seccomp sandbox and iptables/ip6tables OUTPUT
  chains scoped to the launched process group;
- asks the root helper to run the agent as the caller's UID with the dedicated
  `_lianyaohu` effective GID;
- removes host-identifying environment variables and sets `TZ=UTC`;
- exposes the caller's `$HOME`, `--cwd`, and a per-launch temporary directory
  as writable, so agents can maintain their own state under `$HOME`;
- denies raw/system sockets, socket ioctls or kernel APIs, inbound sockets, and
  socket binding in the process sandbox (on macOS, loopback-only listeners are
  allowed so OAuth login callbacks and local dev servers work);
- blocks LAN destinations and non-selected-interface egress for only the
  guarded agent tree.

## Root helper

Firewall enforcement and dedicated-group isolation require root. LianYaoHu uses
a root helper at `/var/run/lianyaohu-helper.sock` to create/validate the hidden
`_lianyaohu` group, install group-scoped firewall rules, drop the child to
`uid=caller_uid,gid=_lianyaohu` while keeping the caller's normal supplementary
groups, and launch the agent with the caller's stdio. On macOS the agent is
spawned through `launchctl asuser` so it joins the caller's security session
and keychain-backed credentials (Claude Code, `gh`, git credential helpers)
keep working. The helper is installed as
a LaunchDaemon on macOS and a systemd service on Linux.

Install the helper once:

```sh
scripts/install-helper.sh
```

Remove it:

```sh
scripts/uninstall-helper.sh
```

The helper authenticates requests with kernel peer credentials, validates that
the requested interface is an active supported VPN interface, and supports the
default session run path plus `install`, `uninstall`, and `status` for the
current-UID fallback.

Because the child keeps the caller's UID, normal owner-based access to `$HOME`,
the working tree, keychain, and TCC state behaves like the desktop user. The
sandbox policy grants write access to `$HOME` so agent CLIs can maintain
their own configuration and credential state.

## Options

```text
usage:
  lianyaohu [options] [-- agent [args...]]

options:
  --vpn NAME                  Select a VPN interface without prompting
                              (macOS: utun*, Linux: tun* or wg*).
  --cwd PATH                  Working directory exposed to the agent.
  --env NAME=VALUE            Add an environment variable unless it is privacy-blocked.
  --no-firewall               Do not install the firewall guard. Alias: --no-pf.
  --shared-user-firewall      Use current-UID firewall rules. Alias: --shared-user-pf.
  --allow-non-default-route   Do not require the default route to use the selected VPN.
  --helper-status             Query the root firewall helper status for this user.
  --print-profile             Print the generated sandbox profile/summary and exit.
  --print-firewall            Print generated firewall rules and exit. Alias: --print-pf.

default command:
  claude
```

For inspection without applying the firewall:

```sh
cargo run -p lianyaohu-app -- --vpn utun5 --print-profile
cargo run -p lianyaohu-app -- --vpn tun0 --print-profile
cargo run -p lianyaohu-app -- --vpn utun5 --print-firewall
cargo run -p lianyaohu-app -- --vpn tun0 --print-firewall
cargo run -p lianyaohu-app -- --vpn utun5 --no-pf -- claude
cargo run -p lianyaohu-app -- --vpn tun0 --shared-user-firewall -- claude
```

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
scripts/e2e-linux-tart.sh
```

The unit tests validate policy generation, environment filtering, PF token
parsing, route-output parsing, and selected runtime sandbox denials. The Linux
Tart e2e boots an Ubuntu VM, installs the helper, creates a temporary `tun0`,
and verifies group-scoped firewall, filesystem, and process-syscall
enforcement around a real launched process.
For the full-stack tests in VMs, see [End-to-End Testing](/e2e-testing).

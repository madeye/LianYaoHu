# LianYaoHu

Documentation: <https://lyh.maxlv.net/>

LianYaoHu is a Rust CLI/TUI launcher for running Claude Code, Codex, or another
code agent with a sanitized environment and a helper-managed network guard while
forcing agent traffic through a selected VPN interface. macOS uses
`sandbox-exec` plus PF on `utun*`; Linux uses Landlock/seccomp plus
owner-scoped iptables/ip6tables rules on `tun*` or `wg*`.

## Install

One line downloads the latest release for your platform, verifies its
SHA-256, installs the `lianyaohu` and `lyh` binaries into `/usr/local/bin`,
and installs the root firewall helper:

```sh
curl -fsSL https://lyh.maxlv.net/install.sh | bash
```

The checksum guards integrity only. If `cosign` is installed, the installer
requires the release's Sigstore signature to verify against this repository's
release-workflow identity and refuses the install otherwise; without `cosign`
it warns and trust rests on GitHub's release infrastructure (set
`LIANYAOHU_REQUIRE_SIGNATURE=1` to make a missing `cosign` a hard failure).
See [the security model](https://lyh.maxlv.net/security-model) for the full
supply-chain trust model.

Prebuilt releases cover Apple Silicon macOS (`aarch64-apple-darwin`) and
x86-64 Linux (`x86_64-unknown-linux-gnu`); on other platforms the installer
tells you to build from source. Pass options after `bash -s --`, for example
to skip the root helper or pin a version:

```sh
curl -fsSL https://lyh.maxlv.net/install.sh | bash -s -- --no-helper
curl -fsSL https://lyh.maxlv.net/install.sh | bash -s -- --version v0.1.3
```

Uninstall (removes the root helper, the hidden `_lianyaohu` group, and the
binaries):

```sh
curl -fsSL https://lyh.maxlv.net/uninstall.sh | bash
```

Run directly during development:

```sh
cargo run -p lianyaohu-app -- --vpn utun5 -- claude
cargo run -p lianyaohu-app -- --vpn utun5 -- codex
cargo run -p lianyaohu-app -- --vpn tun0 -- codex
```

The same binary is also built under the short alias `lyh`, so once installed
(`cargo install --path crates/lianyaohu-app` or by copying `bin/lianyaohu`/`bin/lyh`
into your `PATH`) you can invoke it either way:

```sh
lianyaohu --vpn utun5 -- claude
lyh --vpn utun5 -- claude
```

By default it:

- prompts for a supported VPN interface at startup;
- requires the selected VPN interface to carry all IPv4 egress (the routes for
  `0.0.0.0/1` and `128.0.0.0/1` must both resolve to it);
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
  allowed so OAuth login callbacks and local dev servers work; on Linux all
  binds, including loopback, are denied);
- blocks LAN destinations and non-selected-interface egress for only the
  guarded agent tree.

### Proxy-only mode (no VPN)

The interface picker also offers `none` (equivalently `--vpn none` or
`vpn_interface = "none"` in the config): no VPN at all. The firewall then
blocks every direct destination — loopback is the only way out — and the
launcher ensures the agent's environment carries a local proxy
(`HTTPS_PROXY`/`ALL_PROXY` and friends), prompting for one
(e.g. `http://127.0.0.1:7890`) when the config does not provide it. All
outbound traffic flows through that local proxy or not at all.

## Background Sessions

`lyh run` launches the agent in a background session on its own PTY, so
several agents can run side by side — each in its own sandbox — and survive
closing the terminal:

```sh
lyh run -- claude              # start a session (named after the directory) and attach
lyh run --name api -- codex    # explicit name
lyh run --detached -- claude   # start without attaching
lyh ls                         # list running sessions
lyh attach api                 # reattach (no name: most recent session)
lyh kill api                   # terminate a session's agent
```

While attached, `Ctrl-\ d` detaches, `Ctrl-\ n` / `Ctrl-\ p` switch between
running sessions without dropping to the shell, and `Ctrl-\ Ctrl-\` sends a
literal `Ctrl-\` to the agent. On attach the recent output is replayed and a
resize nudge makes full-screen agents repaint. Session sockets live under
`~/.local/state/lianyaohu/sessions` (owner-only), one small daemon per
session; per-session logs sit next to the sockets.

## Configuration

Everything persists, so a configured machine launches with plain
`lyh -- claude`. A guided full-screen TUI edits the layered TOML config —
VPN interface with live status, destination allow/deny lists and LAN
exceptions, extra writable/read-only paths, sensitive-path denials
(`~/.ssh`, `~/.aws`, …), and a narrow-home mode:

```sh
lyh config        # guided editor (alias: lyh setup)
lyh config show   # merged effective config with per-key provenance
```

Two files layer under the command line
(`CLI flags > ./.lianyaohu.toml > ~/.config/lianyaohu/config.toml`). A
project `.lianyaohu.toml` arrives with the checkout, so it is trusted like
direnv: restrictions apply automatically, while anything that widens the
sandbox needs a hash-pinned `lyh config trust`. Custom policies are
re-validated by the root helper — see the
[security model](https://lyh.maxlv.net/security-model) and the
[configuration guide](https://lyh.maxlv.net/guide) for details.

## Root Helper

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

The helper authenticates requests with `getpeereid`, validates that the
requested interface is an active `utun`, and supports the default session run
path plus `install`, `uninstall`, and `status` for the current-UID fallback.

Because the child keeps the caller's UID, normal owner-based access to `$HOME`,
the working tree, keychain, and TCC state behaves like the desktop user. The
sandbox policy grants write access to `$HOME` so agent CLIs can maintain
their own configuration and credential state.

For inspection without applying PF:

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
scripts/lint-shell.sh
scripts/tests/run.sh
scripts/e2e-linux-tart.sh
```

The unit tests validate policy generation, environment filtering, PF token
parsing, route-output parsing, and selected runtime sandbox denials. The Linux
Tart e2e boots an Ubuntu VM, installs the helper, creates a temporary `tun0`,
and verifies group-scoped firewall, filesystem, and process-syscall
enforcement around a real launched process.

`scripts/lint-shell.sh` runs `bash -n` plus `shellcheck` over every shell
script in the repository. `scripts/tests/run.sh` runs the shell test suites in
`scripts/tests/`: they exercise `install.sh` (checksum and Sigstore signature
enforcement, including that a present-but-invalid signature aborts the
install), `uninstall.sh` (prefer the shipped teardown script, pin the remote
fetch to a release tag, never fall back to a branch), the release tag guard,
and the CI sign→verify round trip. They use stubs and temporary directories
only — nothing is installed, and no network call is made.

## Releases

Pushing a tag like `v0.1.0` runs the release workflow. It verifies formatting,
clippy, and tests, builds `lianyaohu`, creates a
`lianyaohu-<version>-<target>.tar.gz` package, and attaches that package plus a
SHA-256 checksum and a Sigstore signature bundle (`cosign sign-blob`, keyless,
bound to the workflow's OIDC identity) to the GitHub Release for the tag.

## License

LianYaoHu is licensed under the MIT License.

Copyright (c) 2026 Max Lv.

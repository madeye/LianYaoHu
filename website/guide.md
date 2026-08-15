# Getting Started

LianYaoHu is a Rust CLI/TUI launcher for running Claude Code, Codex, or
another code agent with a sanitized environment and a helper-managed network
guard while forcing agent traffic through a selected VPN interface. macOS uses
`sandbox-exec` plus PF on `utun*`; Linux uses Landlock/seccomp plus
owner-scoped iptables/ip6tables rules on `tun*` or `wg*`.

## Install

One line downloads the latest release for your platform, verifies its
SHA-256, installs the `lianyaohu` and `lyh` binaries into `/usr/local/bin`,
and installs the root firewall helper:

```sh
curl -fsSL https://lyh.maxlv.net/install.sh | bash
```

Prebuilt releases cover Apple Silicon macOS (`aarch64-apple-darwin`) and
x86-64 Linux (`x86_64-unknown-linux-gnu`); on other platforms the installer
tells you to build from source. Pass options after `bash -s --` to skip the
root helper (`--no-helper`), pin a version (`--version v0.1.3`), or change the
install directory (`--bin-dir ~/.local/bin`).

Uninstall — removes the root helper, the hidden `_lianyaohu` group, and the
binaries:

```sh
curl -fsSL https://lyh.maxlv.net/uninstall.sh | bash
```

## Run

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

## Configuration

Everything you can pass as a flag (and the sandbox policy below) can be
persisted, so a configured machine launches with plain `lyh -- claude`.
Two TOML files layer together, and command-line flags win over both:

```
CLI flags  >  ./.lianyaohu.toml (project)  >  ~/.config/lianyaohu/config.toml (global)  >  built-ins
```

The guided TUI edits both files — pick the VPN interface with a live status
pane, manage network rules and path grants, and toggle sensitive-path
denials, then save from the Review screen:

```sh
lyh config        # full-screen editor (lyh setup is an alias)
lyh config show   # print the merged effective config with per-key provenance
lyh config path   # print the config file locations
```

The interactive interface picker also offers `s` to save the chosen
interface as the default, so the prompt disappears from the next run.

The full schema (`$XDG_CONFIG_HOME` is honored for the global file):

```toml
[defaults]                # global file only; rejected in project files
vpn_interface = "utun5"
firewall = true
shared_user_firewall = false
allow_non_default_route = false
command = ["claude"]

[env]                     # extra environment; the sanitize block-lists still apply
MY_AGENT_FLAG = "1"

[network]
default = "allow"         # "deny" = only allow-listed destinations may leave
allow = ["140.82.112.0/20", "151.101.0.1:443"]
deny = ["169.254.169.254", "10.99.0.0/16:8000-8100"]
lan_allow = ["192.168.1.10:22"]   # holes in the LAN block; must stay inside it

[paths]
writable = ["/Volumes/DATA/models"]
read_only = ["/Volumes/DATA/reference"]
deny = ["~/.ssh", "~/.aws"]        # seatbelt-enforced; best-effort warning on Linux
narrow_home = false
agent_state_dirs = [".claude", ".claude.json", ".codex", ".config", ".cache"]
```

Destination rules are typed `ADDR[/PREFIX][:PORT[-PORT]]` — IPv6 with a port
needs brackets (`[2606:50c0::]:443`), and DNS hostnames are rejected by
design. `narrow_home = true` replaces the blanket writable `$HOME` with just
the agent state dirs, the working directory, and the launch tmpdir; `$HOME`
stays readable.

**Proxy-or-nothing**: combine `default = "deny"` with the standard proxy
variables in `[env]` (`lyh config` → HTTP proxy, or `p` on Network rules).
Tools that honor `HTTP(S)_PROXY`/`ALL_PROXY` reach the proxy —
loopback is always passed, so a local proxy needs no allow entry (a remote
one needs `allow = ["ip:port"]`) — and anything that ignores them and dials
out directly is blocked by the firewall.

### Project files and trust

`.lianyaohu.toml` is discovered by walking up from `--cwd` (stopping at
`$HOME`), which means it arrives with a repository checkout — so it is
treated like `direnv`: anything that **tightens** the sandbox
(`network.deny`, `paths.deny`, `narrow_home`, `default = "deny"`) applies
automatically, while anything that **widens** it (`network.allow`,
`lan_allow`, `paths.writable`, `paths.read_only`, `agent_state_dirs`,
`[env]`) needs a hash-pinned approval:

```sh
lyh config trust    # approve the discovered project file (re-run after edits)
lyh config revoke   # withdraw the approval
```

On a terminal, an unapproved file prompts once; in scripts the widenings are
stripped with a loud warning — a run is never silently widened and never
blocked on a prompt. Saving a project file from `lyh config` records the
approval automatically. Approvals live in
`~/.config/lianyaohu/trusted.toml`, keyed by directory and content hash, so
any edit to the file invalidates them.

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
  lianyaohu config [show|path|trust [DIR]|revoke [DIR]]

subcommands:
  config                      Open the guided configuration TUI (alias: setup).
  config show                 Print the merged effective config with provenance.
  config path                 Print the config file paths.
  config trust / revoke       Manage project-file approvals.

options:
  --vpn NAME                  Select a VPN interface without prompting
                              (macOS: utun*, Linux: tun* or wg*).
  --cwd PATH                  Working directory exposed to the agent.
  --env NAME=VALUE            Add an environment variable unless it is privacy-blocked.
  --config PATH               Use PATH as the global config file.
  --no-config                 Ignore all configuration files for this run.
  --trust-project             Approve the discovered project file without prompting.
  --no-tui                    Use the plain numbered prompt instead of the picker.
  --allow-dest RULE           Allow a destination; repeatable. With [network]
                              default = "deny", only allowed destinations pass.
  --deny-dest RULE            Block a destination; repeatable.
  --lan-allow RULE            Open a hole in the LAN block; repeatable.
  --writable PATH             Extra writable path; repeatable.
  --read-only PATH            Extra read-only path; repeatable.
  --deny-path PATH            Deny access to PATH (macOS-enforced); repeatable.
  --narrow-home               Writable $HOME becomes agent state dirs only.
  --no-firewall               Do not install the firewall guard. Alias: --no-pf.
  --shared-user-firewall      Use current-UID firewall rules. Alias: --shared-user-pf.
  --allow-non-default-route   Do not require the default route to use the selected VPN.
  --helper-status             Query the root firewall helper status for this user.
  --print-profile             Print the generated sandbox profile/summary and exit.
  --print-firewall            Print generated firewall rules and exit. Alias: --print-pf.

default command:
  claude (or [defaults] command from the config file)
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

## Troubleshooting

**The agent asks to log in even though the host is already authenticated.**
On macOS the helper launches agents through `launchctl asuser` so they join
your login session and can read keychain-backed credentials (Claude Code,
`gh`, git credential helpers). If an agent still prompts, the installed helper
is probably older than v0.1.2 — helper changes only take effect after
reinstalling the LaunchDaemon:

```sh
scripts/install-helper.sh
shasum /usr/local/libexec/lianyaohu target/release/lianyaohu  # should match
```

**OAuth login fails with "Failed to start server. Is port 0 in use?"**
The login flow binds an ephemeral localhost port for its OAuth callback.
Profiles generated before v0.1.2 denied all socket binding, which surfaces as
this misleading port error; current profiles allow loopback-only listeners.
Rebuild and reinstall the CLI, or use the manual paste-the-code fallback.

**The agent aborts, or a tool fails with "Operation not permitted".**
Under the deny-default sandbox this usually means a missing profile
allowance, not firewall or helper logic. Inspect the active policy with
`--print-profile`, and bisect by re-running the failing command with
`--no-pf` (skips the helper) or under plain `sandbox-exec -f <profile>` to
separate sandbox denials from network-guard effects.

**Upgrading.** The CLI and the helper are the same binary but installed in two
places: `cargo install --path crates/lianyaohu-app` updates the CLI;
`scripts/install-helper.sh` updates the LaunchDaemon / systemd service. After
an upgrade, run both.

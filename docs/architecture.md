# Architecture

LianYaoHu launches a code agent (Claude Code, Codex, …) with a sanitized
environment and a helper-managed network guard that forces traffic through a
user-selected VPN interface. macOS uses `sandbox-exec` plus PF on `utun*`;
Linux uses Landlock/seccomp plus owner-scoped iptables/ip6tables chains on
`tun*` or `wg*`. This document describes how the pieces fit together; the policy rationale lives in
[security-model.md](security-model.md), and the end-to-end validation setup in
[e2e-testing.md](e2e-testing.md).

## Crates

```text
crates/
├── lianyaohu          single binary: CLI launcher (user-facing) plus the
│                      `lianyaohu helper` root daemon subcommand that applies
│                      firewall rules and launches dedicated-group sessions
└── lianyaohu-core     shared library: policy generation + system probes
```

### `lianyaohu-core`

Everything policy-related is generated in one place and shared by the
launcher and the helper, so both sides always render identical rules:

| Module | Responsibility |
|---|---|
| `interfaces` | Enumerate interfaces via `getifaddrs`, collect IPv4/IPv6 and point-to-point peer addresses; supported VPN interfaces are `utun*` on macOS and `tun*`/`wg*` on Linux. |
| `route` | Ask the platform route tool which interface would carry `1.1.1.1` (`/sbin/route -n get` on macOS, `ip route get` on Linux). |
| `sandbox_profile` | macOS: render the `sandbox-exec` SBPL profile (deny-default; writable access to `$HOME`, `$PWD`, and a per-launch tmpdir; deny raw/system sockets, socket ioctls, inbound, bind, broad sysctl; allow outbound TCP/UDP and the mDNSResponder socket). |
| `linux_sandbox` | Linux: build and apply the child sandbox (`PR_SET_NO_NEW_PRIVS`, Landlock filesystem rules, and seccomp-BPF syscall filtering). Launch fails if Landlock is unavailable. |
| `env_policy` | Sanitize the child environment: allowlist of operational variables and agent credentials (`ANTHROPIC_*`, `OPENAI_*`, `GIT_*`, …), blocklist of host-identity surfaces (`SSH_*`, `XPC_*`, hostname/MAC/serial/timezone markers); forces `TZ=UTC` and sets `LIANYAOHU_SANDBOX=1`. |
| `launch` | Serialize the helper launch spec: argv, cwd, sanitized environment, and the rendered sandbox profile/summary field. |
| `pf` | macOS: `PFRuleSet` renders the PF anchor rules for a `(utun, socket owner)` pair; the default helper path matches the `_lianyaohu` group, while the fallback path matches the caller UID. `PFGuard` installs fallback rules via the helper or sudo and uninstalls on `Drop`. |
| `linux_firewall` | Linux: `LinuxFirewallRuleSet` renders and installs iptables/ip6tables OUTPUT chains for a `(tun/wg, socket owner)` pair; the default helper path matches `_lianyaohu`, while the fallback path matches the caller UID. |
| `helper` | Client for the helper daemon's protocol over `/var/run/lianyaohu-helper.sock`; the default `run <utun> <spec>` request passes stdio FDs with `SCM_RIGHTS`, while `install <utun>`, `uninstall`, and `status` remain for the current-UID fallback. |

### `lianyaohu` (launcher)

`run()` is a straight pipeline; every step must pass before the agent starts:

1. Parse options (`--vpn`, `--cwd`, `--env`, `--no-pf`, `--shared-user-pf`,
   `--allow-non-default-route`, print/inspect modes).
2. Select the VPN interface — from `--vpn` or an interactive prompt — and
   validate it for the current platform.
3. Sanitize the environment, then build the platform sandbox from `$HOME`, the
   canonicalized working directory, and a fresh per-launch tmpdir.
4. Build the default group-scoped firewall rules for helper launches, or the
   current-UID rules when `--shared-user-firewall` is selected. macOS includes
   the utun's point-to-point IPv4 peer (if any) as the PF `route-to` gateway.
5. Route preflight: refuse to launch unless the default IPv4 route uses the
   selected VPN interface (unless `--allow-non-default-route`).
6. Sanitize the environment (`env_policy::sanitize`).
7. By default, write a launch spec and ask the helper to install group-scoped
   firewall rules, drop to `uid=caller_uid,gid=_lianyaohu` with the caller's
   normal supplementary groups, and launch the agent. macOS execs
   `/usr/bin/sandbox-exec`; Linux applies `PR_SET_NO_NEW_PRIVS`, Landlock, and
   seccomp in the child before execing the requested command.
8. With `--shared-user-firewall`, install the current-UID firewall guard and
   launch directly from the CLI.
9. On agent exit, uninstall the firewall guard.

### `lianyaohu helper` (root daemon)

The same binary run with the `helper` subcommand as a minimal root
LaunchDaemon on macOS or systemd service on Linux
(`io.github.madeye.lianyaohu.helper`, installed by `scripts/install-helper.sh`)
that owns the privileged half of firewall enforcement:

- Listens on `/var/run/lianyaohu-helper.sock` (mode `0666`; authentication is
  per-request, not per-connection).
- Authenticates each request with kernel peer credentials (`getpeereid` on
  macOS, `SO_PEERCRED` on Linux) — peer uid/gid are taken from the kernel,
  never from the request payload.
- Creates or validates the hidden `_lianyaohu` group with fixed gid `2000000`.
- Accepts `run <interface> <spec_path>` for the default path. The client sends
  stdin/stdout/stderr FDs with the request; the helper reads the launch spec,
  installs firewall rules matching the `_lianyaohu` group in the caller's
  anchor/chain, and runs the command as the caller UID with `_lianyaohu` as the
  effective GID and the caller's normal supplementary groups.
- Also accepts `install <interface>`, `uninstall`, and `status` for the
  `--shared-user-firewall` fallback. In that path generated rules are scoped
  to the peer UID.
- The interface name must be supported for the platform and must be live and
  addressed at install time.
- On macOS, writes rules to `/var/run/lianyaohu/rules-<uid>-<utun>.pf` (mode
  `0600`), vets them with `pfctl -n`, enables PF with `pfctl -E` (tracking the
  enable token per uid), and loads the anchor.
- On Linux, creates `LYH-<uid>` iptables/ip6tables chains and inserts an
  OUTPUT owner jump matching either gid `2000000` or the caller uid.
- `uninstall` flushes the caller's anchor/chain and releases tracked state.
  SIGINT/SIGTERM unlink the socket on the way out.

## PF anchor

Rules load into `com.apple/lianyaohu-<uid>`, which macOS' default
`/etc/pf.conf` evaluates through its `anchor "com.apple/*"` point — no edits
to system PF configuration. For caller uid `U`, socket owner `O`, and
interface `utunN` the generated policy is, in order:

1. `pass` loopback TCP/UDP for owner `O`.
2. `block return` TCP/UDP from owner `O` to RFC1918/link-local/CGN/multicast
   IPv4 and to loopback/link-local/ULA/multicast IPv6 (LAN lockout).
3. `pass ... route-to (utunN <peer>)` — owner `O` IPv4 TCP/UDP leaving any other
   interface is steered into the utun (only when the utun has a
   point-to-point peer).
4. `block return` owner `O` TCP/UDP on any interface other than `utunN`.
5. `pass` owner `O` TCP/UDP on `utunN`.

The default helper path uses `group 2000000` for `O`, so other processes owned
by the same desktop UID are untouched. `--shared-user-firewall` uses `user U`
for the fallback path. System daemons, including mDNSResponder, are untouched in
both paths.

## Linux firewall chains

Linux rules use `iptables -m owner` and `ip6tables -m owner` from the OUTPUT
hook. For caller uid `U`, socket owner `O`, and interface `tun0`/`wg0`, the
generated `LYH-U` policy is:

1. Return immediately for loopback.
2. Reject LAN, carrier-grade NAT, link-local, multicast, and IPv6
   unique-local/link-local/multicast destinations.
3. Return for traffic already leaving the selected VPN interface.
4. Reject everything else from owner `O`.

The default helper path matches `--gid-owner 2000000`, so other processes owned
by the same desktop UID are untouched. `--shared-user-firewall` matches
`--uid-owner U` and can affect other sockets opened by that user while active.

## Privilege and fallback

Firewall changes require root; the launcher runs unprivileged. The default path
requires an updated helper daemon because the helper must both install firewall
rules and drop the child to the dedicated effective GID before the child opens
sockets. The `--shared-user-firewall` fallback installs current-UID rules
directly from the CLI through `sudo`. On macOS the fallback asks the helper
first and then falls back to `sudo pfctl` if the helper is unavailable.

## Enforcement layers

The same escape has to defeat several independent mechanisms:

| Layer | Mechanism | Stops |
|---|---|---|
| Process sandbox | macOS: `sandbox-exec` SBPL profile; Linux: Landlock + seccomp-BPF | raw/system sockets, socket ioctls or kernel APIs, bind/inbound, filesystem and sysctl probing |
| Packet filter | macOS: group-scoped PF anchor; Linux: group-scoped iptables/ip6tables chains | LAN egress, egress on any non-selected interface |
| Route preflight | default-route check at launch | starting the agent while traffic would bypass the VPN |
| Environment | `env_policy::sanitize` | host/session identity leaking into the agent process |

# Architecture

LianYaoHu launches a code agent (Claude Code, Codex, …) inside a constrained
macOS sandbox and forces its TCP/UDP traffic through a user-selected VPN
`utun` interface. This document describes how the pieces fit together; the
policy rationale lives in [security-model.md](security-model.md), and the
end-to-end validation setup in [e2e-testing.md](e2e-testing.md).

## Crates

```text
crates/
├── lianyaohu          single binary: CLI launcher (user-facing) plus the
│                      `lianyaohu helper` root LaunchDaemon subcommand that
│                      applies PF rules and launches dedicated-group sandboxes
└── lianyaohu-core     shared library: policy generation + system probes
```

### `lianyaohu-core`

Everything policy-related is generated in one place and shared by the
launcher and the helper, so both sides always render identical rules:

| Module | Responsibility |
|---|---|
| `interfaces` | Enumerate interfaces via `getifaddrs`, collect IPv4/IPv6 and point-to-point peer addresses; `validate_utun` requires a `utun*` name that is up, running, and addressed. |
| `route` | Ask `/sbin/route -n get 1.1.1.1` which interface holds the default IPv4 route. |
| `sandbox_profile` | Render the `sandbox-exec` SBPL profile (deny-default; writable access to `$HOME`, `$PWD`, and a per-launch tmpdir; deny raw/system sockets, socket ioctls, inbound, bind, broad sysctl; allow outbound TCP/UDP and the mDNSResponder socket). |
| `env_policy` | Sanitize the child environment: allowlist of operational variables and agent credentials (`ANTHROPIC_*`, `OPENAI_*`, `GIT_*`, …), blocklist of host-identity surfaces (`SSH_*`, `XPC_*`, hostname/MAC/serial/timezone markers); forces `TZ=UTC` and sets `LIANYAOHU_SANDBOX=1`. |
| `launch` | Serialize the helper launch spec: argv, cwd, sanitized environment, and rendered sandbox profile. |
| `pf` | `PFRuleSet` renders the PF anchor rules for a `(utun, socket owner)` pair; the default helper path matches the `_lianyaohu` group, while the fallback path matches the caller UID. `PFGuard` installs fallback rules via the helper or sudo and uninstalls on `Drop`. |
| `helper` | Client for the helper daemon's protocol over `/var/run/lianyaohu-helper.sock`; the default `run <utun> <spec>` request passes stdio FDs with `SCM_RIGHTS`, while `install <utun>`, `uninstall`, and `status` remain for the current-UID fallback. |

### `lianyaohu` (launcher)

`run()` is a straight pipeline; every step must pass before the agent starts:

1. Parse options (`--vpn`, `--cwd`, `--env`, `--no-pf`, `--shared-user-pf`,
   `--allow-non-default-route`, print/inspect modes).
2. Select the `utun` interface — from `--vpn` or an interactive prompt — and
   validate it (`validate_utun`).
3. Build the sandbox profile from `$HOME`, the canonicalized working
   directory, and a fresh per-launch tmpdir.
4. Build the default group-scoped `PFRuleSet` for helper launches, or the
   current-UID `PFRuleSet` when `--shared-user-pf` is selected, using the
   utun's point-to-point IPv4 peer (if any) as the `route-to` gateway.
5. Route preflight: refuse to launch unless the default IPv4 route uses the
   selected utun (unless `--allow-non-default-route`).
6. Sanitize the environment (`env_policy::sanitize`).
7. By default, write a launch spec and ask the helper to install group-scoped
   PF rules, drop to `uid=caller_uid,gid=_lianyaohu` with the caller's normal
   supplementary groups, and exec
   `/usr/bin/sandbox-exec -f /var/run/lianyaohu/profile-<uid>-<pid>.sb`.
8. With `--shared-user-pf`, install the current-UID PF guard and launch
   `sandbox-exec` directly from the CLI.
9. On agent exit, uninstall the PF guard.

### `lianyaohu helper` (root daemon)

The same binary run with the `helper` subcommand as a minimal root
LaunchDaemon (`io.github.madeye.lianyaohu.helper`, installed by
`scripts/install-helper.sh`) that owns the privileged half of PF
enforcement:

- Listens on `/var/run/lianyaohu-helper.sock` (mode `0666`; authentication is
  per-request, not per-connection).
- Authenticates each request with `getpeereid` — peer uid/gid are taken from
  the kernel, never from the request payload.
- Creates or validates the hidden `_lianyaohu` group with fixed gid `2000000`.
- Accepts `run <utunN> <spec_path>` for the default path. The client sends
  stdin/stdout/stderr FDs with the request; the helper reads the launch spec,
  installs PF rules matching the `_lianyaohu` group in the caller's anchor, and
  runs `sandbox-exec` as the caller UID with `_lianyaohu` as the effective GID
  and the caller's normal supplementary groups.
- Also accepts `install <utunN>`, `uninstall`, and `status` for the
  `--shared-user-pf` fallback. In that path generated rules are scoped to the
  peer UID.
- The interface name must match `utun[0-9]+` and must be a live, addressed
  utun (`validate_utun`) at install time.
- Writes rules to `/var/run/lianyaohu/rules-<uid>-<utun>.pf` (mode `0600`),
  vets them with `pfctl -n`, enables PF with `pfctl -E` (tracking the enable
  token per uid), and loads the anchor.
- `uninstall` flushes the caller's anchor and releases that uid's enable
  token. SIGINT/SIGTERM unlink the socket on the way out.

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
by the same desktop UID are untouched. `--shared-user-pf` uses `user U` for the
fallback path. System daemons, including mDNSResponder, are untouched in both
paths.

## Privilege and fallback

PF requires root; the launcher runs unprivileged. The default path requires an
updated helper daemon because the helper must both install PF and drop the
child to the dedicated effective GID before the child opens sockets.
`--shared-user-pf` uses `PFGuard::install`: it first asks the helper daemon,
then falls back to `sudo pfctl` only if the helper socket is absent or refuses
the connection. In both PF paths the guard remembers the PF enable token and
returns PF to its prior state on teardown.

## Enforcement layers

The same escape has to defeat several independent mechanisms:

| Layer | Mechanism | Stops |
|---|---|---|
| Process sandbox | `sandbox-exec` SBPL profile | raw/system sockets, socket ioctls, bind/inbound, filesystem and sysctl probing |
| Packet filter | group-scoped PF anchor (root-installed) | LAN egress, egress on any non-utun interface |
| Route preflight | default-route check at launch | starting the agent while traffic would bypass the VPN |
| Environment | `env_policy::sanitize` | host/session identity leaking into the agent process |

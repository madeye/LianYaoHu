# Architecture

LianYaoHu launches a code agent (Claude Code, Codex, …) inside a constrained
macOS sandbox and forces its TCP/UDP traffic through a user-selected VPN
`utun` interface. This document describes how the pieces fit together; the
policy rationale lives in [security-model.md](security-model.md), and the
end-to-end validation setup in [e2e-testing.md](e2e-testing.md).

## Crates

```text
crates/
├── lianyaohu          CLI launcher (user-facing binary)
├── lianyaohu-core     shared library: policy generation + system probes
└── lianyaohu-helper   root LaunchDaemon that applies PF rules
```

### `lianyaohu-core`

Everything policy-related is generated in one place and shared by the
launcher and the helper, so both sides always render identical rules:

| Module | Responsibility |
|---|---|
| `interfaces` | Enumerate interfaces via `getifaddrs`, collect IPv4/IPv6 and point-to-point peer addresses; `validate_utun` requires a `utun*` name that is up, running, and addressed. |
| `route` | Ask `/sbin/route -n get 1.1.1.1` which interface holds the default IPv4 route. |
| `sandbox_profile` | Render the `sandbox-exec` SBPL profile (deny-default; rw access to `$HOME`, `$PWD`, and a per-launch tmpdir; deny raw/system sockets, socket ioctls, inbound, bind, broad sysctl; allow outbound TCP/UDP and the mDNSResponder socket). |
| `env_policy` | Sanitize the child environment: allowlist of operational variables and agent credentials (`ANTHROPIC_*`, `OPENAI_*`, `GIT_*`, …), blocklist of host-identity surfaces (`SSH_*`, `XPC_*`, hostname/MAC/serial/timezone markers); forces `TZ=UTC` and sets `LIANYAOHU_SANDBOX=1`. |
| `pf` | `PFRuleSet` renders the PF anchor rules for a `(utun, uid)` pair; `PFGuard` installs them via the helper or the sudo fallback and uninstalls on `Drop`. |
| `helper` | Client for the helper daemon's line protocol over `/var/run/lianyaohu-helper.sock` (`install <utun>`, `uninstall`, `status` → `ok …` / `error …`). |

### `lianyaohu` (launcher)

`run()` is a straight pipeline; every step must pass before the agent starts:

1. Parse options (`--vpn`, `--cwd`, `--env`, `--no-pf`,
   `--allow-non-default-route`, print/inspect modes).
2. Select the `utun` interface — from `--vpn` or an interactive prompt — and
   validate it (`validate_utun`).
3. Build the sandbox profile from `$HOME`, the canonicalized working
   directory, and a fresh per-launch tmpdir.
4. Build the `PFRuleSet` for the current uid, using the utun's
   point-to-point IPv4 peer (if any) as the `route-to` gateway.
5. Route preflight: refuse to launch unless the default IPv4 route uses the
   selected utun (unless `--allow-non-default-route`).
6. Sanitize the environment (`env_policy::sanitize`).
7. Install the PF guard (unless `--no-pf`).
8. Write the profile to the tmpdir and exec the agent under
   `/usr/bin/sandbox-exec -f`, with a cleared-then-sanitized environment.
9. On agent exit, uninstall the PF guard (also on `Drop`, so early errors
   still clean up).

### `lianyaohu-helper` (root daemon)

A minimal root LaunchDaemon (`io.github.madeye.lianyaohu.helper`, installed
by `scripts/install-helper.sh`) that owns the privileged half of PF
enforcement:

- Listens on `/var/run/lianyaohu-helper.sock` (mode `0666`; authentication is
  per-request, not per-connection).
- Authenticates each request with `getpeereid` — the peer uid is taken from
  the kernel, never from the request payload, and the generated rules are
  scoped to that uid.
- Accepts only `install <utunN>`, `uninstall`, and `status`. The interface
  name must match `utun[0-9]+` and must be a live, addressed utun
  (`validate_utun`) at install time.
- Writes rules to `/var/run/lianyaohu/rules-<uid>-<utun>.pf` (mode `0600`),
  vets them with `pfctl -n`, enables PF with `pfctl -E` (tracking the enable
  token per uid), and loads the anchor.
- `uninstall` flushes the caller's anchor and releases that uid's enable
  token. SIGINT/SIGTERM unlink the socket on the way out.

## PF anchor

Rules load into `com.apple/lianyaohu-<uid>`, which macOS' default
`/etc/pf.conf` evaluates through its `anchor "com.apple/*"` point — no edits
to system PF configuration. For uid `U` and interface `utunN` the generated
policy is, in order:

1. `pass` loopback TCP/UDP for uid `U`.
2. `block return` TCP/UDP from uid `U` to RFC1918/link-local/CGN/multicast
   IPv4 and to loopback/link-local/ULA/multicast IPv6 (LAN lockout).
3. `pass … route-to (utunN <peer>)` — uid `U` IPv4 TCP/UDP leaving any other
   interface is steered into the utun (only when the utun has a
   point-to-point peer).
4. `block return` uid `U` TCP/UDP on any interface other than `utunN`.
5. `pass` uid `U` TCP/UDP on `utunN`.

All rules are `user`-scoped, so other users and system daemons (including
mDNSResponder, which performs DNS on the agent's behalf) are untouched.

## Privilege and fallback

PF requires root; the launcher runs unprivileged. `PFGuard::install` first
asks the helper daemon. Only if the socket is absent or refuses the
connection (helper not installed) does it fall back to `sudo pfctl` with the
same rendered rules; a helper that answers with an error is treated as a
refusal, not a fallback trigger. In both paths the guard remembers the PF
enable token and returns PF to its prior state on teardown.

## Enforcement layers

The same escape has to defeat several independent mechanisms:

| Layer | Mechanism | Stops |
|---|---|---|
| Process sandbox | `sandbox-exec` SBPL profile | raw/system sockets, socket ioctls, bind/inbound, filesystem and sysctl probing |
| Packet filter | per-uid PF anchor (root-installed) | LAN egress, egress on any non-utun interface |
| Route preflight | default-route check at launch | starting the agent while traffic would bypass the VPN |
| Environment | `env_policy::sanitize` | host/session identity leaking into the agent process |

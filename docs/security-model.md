# Security Model

LianYaoHu is intentionally CLI/TUI-only. It uses two macOS mechanisms:

1. A voluntary process sandbox via `sandbox-exec`.
2. A PF firewall anchor evaluated through macOS' default `com.apple/*` PF
   anchor point.

## Filesystem

The agent can read and write the caller's home directory, so agent CLIs can
maintain their own state (`~/.claude`, `~/.codex`, credential and cache files).
Write access covers:

- the caller's home directory;
- the selected working directory;
- a per-launch temporary directory.

Platform and developer tool paths are read-only so shells, interpreters, git,
node, and installed code-agent CLIs can start. `/opt/homebrew` is writable so
agents can `brew install` the tools they need.

`uname(3)` (and therefore `kern.hostname`) is allowed because Homebrew, Ruby,
and many build tools fail hard without it, so the machine name is visible to
the agent; stronger identifiers such as `kern.uuid` remain blocked and
`HOSTNAME` is still stripped from the environment.

Timezone preference files are explicitly denied and the launched environment
sets `TZ=UTC`.

By default the helper runs the sandboxed process with the caller's UID and the
dedicated `_lianyaohu` effective GID. The sandbox profile describes where the
process is allowed to go, but normal POSIX ownership still applies: owner-based
access remains the caller's access, and supplementary groups keep ordinary
group-based project access intact.

## Environment

The launcher passes a small set of operational variables and common code-agent
API credentials. It drops host and session identity variables such as `HOSTNAME`,
`SSH_AUTH_SOCK`, `SSH_CONNECTION`, `TZ`, `XPC_*`, and names containing MAC,
timezone, Wi-Fi, BSSID, serial, or local-IP markers.

## Network

The launcher asks the user to choose a `utun` interface and rejects startup
unless that interface is up, has an address, and is the default IPv4 route.

When PF enforcement is enabled, the launcher asks the root helper to run the
session. The root helper listens on `/var/run/lianyaohu-helper.sock`,
authenticates the caller with `getpeereid`, creates or validates the hidden
`_lianyaohu` group, installs PF rules matching that group, drops the child to
`uid=caller_uid,gid=_lianyaohu`, and validates that the requested interface is
an active `utun`. The helper replaces the inherited LaunchDaemon supplementary
group list with the caller's normal groups before the drop.

The installed PF rules:

- allow loopback TCP/UDP;
- block TCP/UDP to private, carrier-grade NAT, link-local, multicast, and IPv6
  unique-local/link-local/multicast ranges;
- route IPv4 TCP/UDP opened on non-`utun` interfaces to the selected `utun`
  when the interface exposes a point-to-point IPv4 peer;
- block TCP/UDP owned by the `_lianyaohu` effective GID on every interface
  except the selected `utun`;
- allow TCP/UDP owned by the `_lianyaohu` effective GID on the selected `utun`.

The default PF rules are group-scoped because macOS PF cannot match a child
process tree directly. The helper-run path avoids affecting desktop-user
traffic by moving only the sandboxed child tree to the `_lianyaohu` effective
GID before it opens sockets. With `--shared-user-pf`, LianYaoHu uses the older
current-UID PF path; in that mode, the network guard also affects other TCP/UDP
sockets opened by the desktop user while the agent is running.

Raw, route, and system sockets are not allowed by the process sandbox profile.

### DNS resolution

The sandbox profile lets the agent reach the system resolver over the
mDNSResponder unix socket, so name lookups are performed by **mDNSResponder**,
not by the agent process. Because the PF rules match the agent's group, they
do not apply to mDNSResponder: its DNS queries follow the system's routing
table rather than being steered by the agent's `route-to` rule.

In the default configuration this is not a leak — the launcher refuses to start
unless the selected `utun` is already the default IPv4 route, so mDNSResponder's
queries traverse the same `utun`. The confinement of DNS therefore depends on
that default-route invariant:

- With `--allow-non-default-route`, the agent's own connections are still pinned
  to the `utun` by `route-to`, but its DNS lookups can leave over the real
  default interface. Do not use that flag when DNS metadata must stay inside the
  tunnel.
- If the system default route changes while the agent runs, DNS can leave the
  tunnel even though the agent's sockets remain pinned.

## Known Limits

LianYaoHu does not use Apple's App Sandbox entitlement because that would compose
with the child sandbox and prevent the requested default `$HOME` access for
arbitrary code-agent tools. The sandbox boundary for the agent is the generated
`sandbox-exec` profile.

## Linux Port

The Rust workspace keeps the policy model, helper protocol, CLI parsing, and
tests portable. macOS-specific enforcement is currently `sandbox-exec` plus PF.
A Linux backend can add nftables or policy routing in the helper, then combine
that with Linux sandbox primitives such as namespaces, seccomp, and Landlock.

PF enforcement requires administrator authorization. Without PF, the launcher
still validates that the selected `utun` is the default route, but it cannot
force routing by itself.

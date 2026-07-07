# Security Model

LianYaoHu is intentionally CLI/TUI-only. It uses two macOS mechanisms:

1. A voluntary process sandbox via `sandbox-exec`.
2. A PF firewall anchor evaluated through macOS' default `com.apple/*` PF
   anchor point.

## Filesystem

The agent can read and write:

- the user's home directory;
- the selected working directory;
- a per-launch temporary directory.

Platform, developer tool, and Homebrew paths are read-only so shells,
interpreters, git, node, and installed code-agent CLIs can start.

Timezone preference files are explicitly denied and the launched environment
sets `TZ=UTC`.

## Environment

The launcher passes a small set of operational variables and common code-agent
API credentials. It drops host and session identity variables such as `HOSTNAME`,
`SSH_AUTH_SOCK`, `SSH_CONNECTION`, `TZ`, `XPC_*`, and names containing MAC,
timezone, Wi-Fi, BSSID, serial, or local-IP markers.

## Network

The launcher asks the user to choose a `utun` interface and rejects startup
unless that interface is up, has an address, and is the default IPv4 route.

When PF enforcement is enabled, the launcher asks the root helper to install
rules. If the helper is unavailable, it falls back to `sudo pfctl`. The root
helper listens on `/var/run/lianyaohu-helper.sock`, authenticates the caller with
`getpeereid`, generates rules for the peer UID, and validates that the requested
interface is an active `utun`.

The installed PF rules:

- allow loopback TCP/UDP;
- block TCP/UDP to private, carrier-grade NAT, link-local, multicast, and IPv6
  unique-local/link-local/multicast ranges;
- route IPv4 TCP/UDP opened on non-`utun` interfaces to the selected `utun`
  when the interface exposes a point-to-point IPv4 peer;
- block TCP/UDP owned by the current UID on every interface except the selected
  `utun`;
- allow TCP/UDP owned by the current UID on the selected `utun`.

The PF rules are UID-scoped because macOS PF cannot match a child process tree
directly. If the agent runs as the same user as the desktop session, the network
guard also affects other TCP/UDP sockets opened by that user while the agent is
running.

Raw, route, and system sockets are not allowed by the process sandbox profile.

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

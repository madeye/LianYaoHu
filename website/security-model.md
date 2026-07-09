# Security Model

LianYaoHu is intentionally CLI/TUI-only. It combines environment cleanup with a
platform firewall guard:

1. macOS: a voluntary process sandbox via `sandbox-exec` plus a PF firewall
   anchor evaluated through macOS' default `com.apple/*` PF anchor point.
2. Linux: a voluntary process sandbox via Landlock and seccomp-BPF plus
   owner-scoped iptables/ip6tables OUTPUT chains.

## Filesystem

The agent can read and write the caller's home directory, so agent CLIs can
maintain their own state (`~/.claude`, `~/.codex`, credential and cache files).
Write access covers:

- the caller's home directory;
- the selected working directory;
- a per-launch temporary directory.

On macOS, platform and developer tool paths are read-only so shells,
interpreters, git, node, and installed code-agent CLIs can start.
`/opt/homebrew` is writable so agents can `brew install` the tools they need.

On Linux, Landlock applies a deny-default filesystem ruleset. `$HOME`, the
selected working directory, the per-launch tmpdir, `/tmp`, `/var/tmp`,
`/dev/pts`, and `/dev/shm` are writable, plus the individual device files
`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`,
`/dev/tty`, and `/dev/ptmx` (the rest of `/dev` is not granted); `/bin`,
`/sbin`, `/usr`, `/lib`, `/lib64`, `/etc`, `/opt`, and the process' own
`/proc` entries are read-only. If the kernel does not
support Landlock, launch fails instead of silently degrading to firewall-only
mode.

`uname(3)` (and therefore `kern.hostname`) is allowed because Homebrew, Ruby,
and many build tools fail hard without it, so the machine name is visible to
the agent; stronger identifiers such as `kern.uuid` remain blocked and
`HOSTNAME` is still stripped from the environment.

Timezone preference files are explicitly denied and the launched environment
sets `TZ=UTC`.

By default the helper runs the guarded process with the caller's UID and the
dedicated `_lianyaohu` effective GID. On macOS, the sandbox profile describes
where the process is allowed to go, but normal POSIX ownership still applies:
owner-based access remains the caller's access, and supplementary groups keep
ordinary group-based project access intact.

On Linux, the helper drops to the caller UID and `_lianyaohu` effective GID
before applying `PR_SET_NO_NEW_PRIVS`, Landlock, and seccomp in the child.

## Environment

The launcher passes a small set of operational variables and common code-agent
API credentials. It drops host and session identity variables such as `HOSTNAME`,
`SSH_AUTH_SOCK`, `SSH_CONNECTION`, `TZ`, `XPC_*`, and names containing MAC,
timezone, Wi-Fi, BSSID, serial, or local-IP markers.

## Network

The launcher asks the user to choose a supported VPN interface (`utun*` on
macOS, `tun*` or `wg*` on Linux) and rejects startup unless that interface is
up, has an address, and is the default IPv4 route.

When firewall enforcement is enabled, the launcher asks the root helper to run
the session. The root helper listens on `/var/run/lianyaohu-helper.sock`,
authenticates the caller with kernel peer credentials, creates or validates the
hidden `_lianyaohu` group, installs firewall rules matching that group, drops
the child to `uid=caller_uid,gid=_lianyaohu`, and validates that the requested
interface is active. The helper replaces inherited supplementary groups with
the caller's normal groups before the drop. On macOS the child is spawned
through `launchctl asuser`, joining the caller's Mach bootstrap and audit
session before credentials are dropped: keychain search lists and unlock state
are per-session, and without this the agent lands in the system session where
the caller's login keychain is invisible, so keychain-backed logins (Claude
Code, `gh`, git credential helpers) would prompt again.

On macOS, the installed PF rules:

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
traffic by moving only the guarded child tree to the `_lianyaohu` effective GID
before it opens sockets. With `--shared-user-firewall`, LianYaoHu uses the
current-UID PF path; in that mode, the network guard also affects other TCP/UDP
sockets opened by the desktop user while the agent is running.

Raw, route, and system sockets are not allowed by the process sandbox profile.
On macOS, `network-bind` and `network-inbound` are denied except on the
loopback interface, so agents can run localhost-only servers (OAuth login
callbacks such as `claude /login`, local dev servers) that are unreachable
from the network.
On Linux, `bind`/`listen`/`accept` are denied entirely — including loopback —
because seccomp cannot inspect the sockaddr to distinguish a localhost bind
from a network one. This is intentional: OAuth-style localhost callback flows
do not work inside the Linux sandbox; complete such logins outside LianYaoHu
(or on macOS) first.
On Linux, seccomp also denies mount and namespace escapes,
ptrace/process-memory inspection, BPF/perf/userfault/io_uring setup, keyring
APIs, module loading, reboot/accounting/syslog, and other kernel-control
syscalls. `socket(2)` is limited to Unix sockets and IPv4/IPv6 stream or
datagram sockets; the firewall rules then constrain where those network sockets
can send traffic.

On Linux, the installed iptables/ip6tables chains:

- allow loopback traffic to continue through the host firewall;
- reject traffic to private, carrier-grade NAT, link-local, multicast, and IPv6
  unique-local/link-local/multicast ranges;
- allow traffic already leaving the selected VPN interface to continue through
  the host firewall;
- reject other traffic opened by the `_lianyaohu` effective GID.

### DNS resolution

On macOS, the sandbox profile lets the agent reach the system resolver over the
mDNSResponder unix socket, so name lookups are performed by **mDNSResponder**,
not by the agent process. Because the PF rules match the agent's group, they do
not apply to mDNSResponder: its DNS queries follow the system's routing table
rather than being steered by the agent's `route-to` rule.

In the default configuration this is not a leak — the launcher refuses to start
unless the selected VPN is already the default IPv4 route, so resolver queries
traverse the same tunnel. The confinement of DNS therefore depends on that
default-route invariant:

- On macOS with `--allow-non-default-route`, the agent's own connections are
  still pinned to the `utun` by `route-to`, but its DNS lookups can leave over
  the real default interface. Do not use that flag when DNS metadata must stay
  inside the tunnel.
- On Linux with `--allow-non-default-route`, neither DNS nor other traffic is
  route-steered by LianYaoHu; the firewall can block non-selected egress, but it
  cannot make another interface carry the default route.
- If the system default route changes while the agent runs, DNS can leave the
  tunnel even though the agent's sockets remain pinned.

## Known Limits

LianYaoHu does not use Apple's App Sandbox entitlement because that would compose
with the child sandbox and prevent the requested default `$HOME` access for
arbitrary code-agent tools. The sandbox boundary for the agent is the generated
`sandbox-exec` profile.

On Linux, the process sandbox depends on kernel Landlock and seccomp support.
LianYaoHu does not build a private mount namespace or overlay filesystem; it
uses Landlock path rules for filesystem access and seccomp for syscall classes.

macOS has no `PR_SET_NO_NEW_PRIVS`. Instead, Seatbelt refuses to exec
setuid/setgid binaries from inside the generated sandbox profile, so the agent
cannot escalate through setuid-root helpers such as `sudo`; a regression test
pins this behavior. On Linux the helper sets `PR_SET_NO_NEW_PRIVS` in the
child before Landlock and seccomp.

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

### Path customization

The configuration layer can add to — or narrow — the default grants:

- **Extra writable / read-only paths** are widenings, so the helper
  re-validates them like the launch roots: canonicalized against the real
  filesystem, never `/`, and writable extras must be **owned by the caller**
  and outside a protected-prefix denylist (`/etc`, `/usr`, `/System`,
  `/Library`, `/var/db`, …). Read-only extras may not reach into another
  user's home: the helper checks the standard home roots (`/Users`, `/home`,
  `/root`, `/var/root`) resolved through symlinks, plus every regular user's
  home directory from the passwd database, so nonstandard layouts (NFS
  exports, systemd-homed) are covered too.
- **Denied paths** (`paths.deny`, e.g. `~/.ssh`) are rendered as the *final*
  seatbelt rules, so they override every allow — the entries become
  unreadable and unwritable even inside the writable `$HOME`. **Linux cannot
  enforce these**: Landlock has no deny-inside-allow, so the launcher warns
  at startup and `--print-profile` reports them as unenforced. Do not move a
  macOS config to Linux and assume `~/.ssh` is still protected.
- **Narrow-home mode** replaces the blanket writable `$HOME` with per-entry
  grants for the configured agent state locations (plus cwd and the launch
  tmpdir); `$HOME` stays readable so dotfiles and installed tooling keep
  working. The state entries are writable grants, so the helper resolves
  each one against the real filesystem like the writable extras: an entry
  whose canonical path leaves the caller's home, resolves to the home
  itself, or is not owned by the caller is refused — a symlink such as
  `~/.cache -> /` cannot widen narrow-home into its target tree. This mode
  is enforced identically on both platforms and is the strongest filesystem
  posture.

The helper never trusts client-supplied paths: every field of the policy is
re-validated server-side, and the client's rendered profile text is ignored
entirely (see [Architecture](/architecture)).

## Environment

The launcher passes a small set of operational variables and common code-agent
API credentials. It drops host and session identity variables such as `HOSTNAME`,
`SSH_AUTH_SOCK`, `SSH_CONNECTION`, `TZ`, `XPC_*`, and names containing MAC,
timezone, Wi-Fi, BSSID, serial, or local-IP markers.

Loader and language-runtime injection variables are blocked even when passed
explicitly with `--env`: `LD_*`, `DYLD_*`, `PYTHON*`, `PERL5*`, `BASH_FUNC*`,
`GLIBC_*`, `NODE_OPTIONS`, `NODE_PATH`, `RUBYOPT`, `RUBYLIB`, `BASH_ENV`,
`ENV`, `SHELLOPTS`, `ZDOTDIR`, and `IFS`. These change what code every child
process loads at startup, so they are not accepted from the caller.

## Network

The launcher asks the user to choose a supported VPN interface (`utun*` on
macOS, `tun*` or `wg*` on Linux) and rejects startup unless that interface is
up, has an address, and is the default IPv4 route.

When firewall enforcement is enabled, the launcher asks the root helper to run
the session. The root helper listens on `/var/run/lianyaohu-helper.sock`,
authenticates the caller with kernel peer credentials, creates or validates the
hidden `_lianyaohu` group, installs firewall rules matching the caller's UID
together with that group, drops the child to `uid=caller_uid,gid=_lianyaohu`,
and validates that the requested interface is active. The helper replaces
inherited supplementary groups with the caller's normal groups before the
drop.

The helper treats the client-supplied launch spec as untrusted, since any
local user can connect to its socket. The spec file named in the request is
itself opened defensively: symlinks are refused, it must be a regular file
owned by the authenticated peer, and the read is size- and deadline-bounded
so a FIFO or hostile filesystem cannot pin a helper worker. It rebuilds the sandbox profile
server-side from inputs it validates itself — the home directory from the
passwd database for the authenticated peer UID, and a working directory and
temporary directory that must be real directories (the temporary directory
owned by the caller) — and re-sanitizes the launch environment with the same
privacy and injection blocklists the launcher applies. The client's profile
text is never consumed. A custom sandbox policy travels as typed fields in
the versioned launch spec and is re-validated field by field: destination
rules arrive pre-parsed (address, prefix, port range — never free text), the
LAN-exception containment check runs again helper-side, list lengths are
capped, and the path rules go through the ownership checks described under
*Path customization*. Only `Display` of typed values ever reaches the
`pfctl`/iptables rule text, so config strings cannot inject rules. Before
exec on macOS, the `drop-exec` trampoline verifies the credential drop took
effect and cannot be reversed.

**Version negotiation.** An old helper would silently drop spec fields it
does not know — the user would believe `network.deny` is enforced when it is
not. The client therefore probes the helper's capabilities before sending
any non-default policy and hard-errors when the helper predates policy
support; a default policy ships as a legacy spec that old and new helpers
handle identically. The helper likewise rejects specs newer than itself.

Firewall sessions are reference-counted per UID: concurrent launches by the
same user share one set of rules, which are removed only when the last session
ends, so an early-exiting session cannot strip the guard from a running one.
Concurrent sessions for one UID must use the same VPN interface, scope, and
network policy (the rules live under a single anchor/chain per UID); a
mismatching launch is refused rather than silently weakening either session.
The `uninstall` request releases only the user-scoped state that `install`
created: while a helper `run` session is live for that UID, `uninstall` is
refused, so a stray same-UID client writing `uninstall` to the socket cannot
strip a running session's group-scoped rules.
The helper also caps concurrent connections — globally and per UID, so one
user's long-lived sessions cannot occupy every worker slot — and, on
SIGINT/SIGTERM, hands shutdown to a dedicated thread (the signal handler only
writes to a pipe) that removes the socket and uninstalls any remaining
firewall state before exit. On startup, before serving, the helper reaps
firewall state orphaned by a previous instance that exited without cleanup
(SIGKILL, crash, supervisor restart); orphaned rules fail closed — they
over-block rather than open anything — but would otherwise keep blocking a
user whose session is long gone. On macOS the child is spawned
through `launchctl asuser`, joining the caller's Mach bootstrap and audit
session before credentials are dropped: keychain search lists and unlock state
are per-session, and without this the agent lands in the system session where
the caller's login keychain is invisible, so keychain-backed logins (Claude
Code, `gh`, git credential helpers) would prompt again.

The reference count lives in the helper, so it protects helper-managed
sessions. Rules installed through `sudo` instead — Linux
`--shared-user-firewall` always, and macOS `--shared-user-firewall` when the
helper is unreachable — are not reference-counted: two overlapping sudo
sessions for the same UID share one user-scoped chain/anchor, and whichever
exits last removes the shared rules, taking the other session's guard down
with it (last-exit-wins). Sudo user-scoped rules do live under their own
names (`LYH-U-<uid>` on Linux, `com.apple/lianyaohu-user-<uid>` on macOS),
distinct from the helper's group-scoped `LYH-<uid>` /
`com.apple/lianyaohu-<uid>`, so a shared-user launch or exit can never flush
the rules of a live helper-managed session.

On macOS, the installed PF rules:

- allow loopback TCP/UDP;
- block TCP/UDP to private, carrier-grade NAT, link-local, multicast, and IPv6
  unique-local/link-local/multicast ranges;
- route IPv4 TCP/UDP opened on non-`utun` interfaces to the selected `utun`
  when the interface exposes a point-to-point IPv4 peer;
- block TCP/UDP owned by the caller's UID with the `_lianyaohu` effective GID
  on every interface except the selected `utun`;
- allow TCP/UDP owned by the caller's UID with the `_lianyaohu` effective GID
  on the selected `utun`.

The default PF rules match UID and GID together because macOS PF cannot match
a child process tree directly. The `_lianyaohu` effective GID separates the
guarded child tree from the desktop user's other traffic, and the UID match
keeps one user's session rules from capturing another user's agent traffic
when several sessions run at once. With `--shared-user-firewall`, LianYaoHu uses the
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
- reject other traffic opened by the caller's UID with the `_lianyaohu`
  effective GID.

### Network customization

The configuration layer inserts typed rules into both rule sets at fixed
points in the first-match-wins order:

- **LAN exceptions** (`lan_allow`) render *before* the LAN blocks, opening a
  hole for a specific host or subnet (a NAS, a local dev server). Every entry
  must be fully contained in the blocked LAN ranges — this is validated in
  the client, the editor, and again in the helper, because an uncontained
  entry (say `0.0.0.0/0`) would otherwise bypass the VPN-only guarantee
  entirely.
- **Denied destinations** (`network.deny`) render *after* the LAN blocks and
  *before* any pass rule, so they carve holes out of the allows (e.g. a
  cloud metadata address, a port range).
- **Default-deny mode** (`default = "deny"`) replaces the blanket
  on-interface pass with one pass per `network.allow` entry plus a terminal
  block: only allow-listed destinations may leave, and still only on the
  selected interface.

Rules with ports expand to TCP and UDP matches; IPv4 and IPv6 rules go only
to their family's program. Entries are IP literals by design — accepting DNS
names would make the root helper resolve untrusted names, and resolution
itself is a time-of-check race against the firewall.

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
- Only the default **IPv4** route is probed. If the system also has an IPv6
  default route on a physical interface, RDNSS-learned resolvers and AAAA
  transport can leave over it even when the IPv4 default is the tunnel;
  IPv6 confinement of the system resolver is out of scope.

## Configuration Trust

Configuration is layered: a global `~/.config/lianyaohu/config.toml` the user
owns, and an optional `.lianyaohu.toml` discovered upward from the working
directory. The project file arrives with a repository checkout, so it is
attacker-influenced by definition. The trust policy splits its keys:

- **Tightenings** — `network.default = "deny"`, `network.deny`,
  `paths.deny`, `narrow_home` — apply automatically. The worst a hostile
  repository can do with them is restrict its own sandbox.
- **Widenings** — `network.allow`, `lan_allow`, `paths.writable`,
  `paths.read_only`, `agent_state_dirs`, and `[env]` (environment variables
  can redirect credentials, e.g. `ANTHROPIC_BASE_URL`) — require a
  hash-pinned approval in `~/.config/lianyaohu/trusted.toml`, in the style
  of `direnv allow`. Any edit to the file invalidates the approval.

Without an approval, an interactive run prompts once; a non-interactive run
strips the widenings and warns loudly. A run is never silently widened, and
a scripted run is never blocked on a prompt. Unknown keys in any config file
are hard errors — in a security policy, a typo like `narow_home` must not be
a silent no-op. Group- or world-writable config or trust-store files draw a
warning, since a writable trust store would defeat the hash pinning.

## Known Limits

LianYaoHu does not use Apple's App Sandbox entitlement because that would compose
with the child sandbox and prevent the requested default `$HOME` access for
arbitrary code-agent tools. The sandbox boundary for the agent is the generated
`sandbox-exec` profile.

On Linux, the process sandbox depends on kernel Landlock and seccomp support.
LianYaoHu does not build a private mount namespace or overlay filesystem; it
uses Landlock path rules for filesystem access and seccomp for syscall classes.
Landlock rules are attached through `openat2(RESOLVE_NO_SYMLINKS)`: a rule
path that is — or traverses — a symlink receives no grant at all, so a
symlink swapped in after validation cannot redirect a grant to its target
tree (symlinked targets stay reachable only when a real rule covers their
destination, as with the merged-`/usr` `/bin -> usr/bin` layout).

macOS has no `PR_SET_NO_NEW_PRIVS`. Instead, Seatbelt refuses to exec
setuid/setgid binaries from inside the generated sandbox profile, so the agent
cannot escalate through setuid-root helpers such as `sudo`; a regression test
pins this behavior. On Linux the helper sets `PR_SET_NO_NEW_PRIVS` in the
child before Landlock and seccomp.

### Persistence is not contained

The sandbox confines the agent **while it runs**; it does not stop the agent
from persisting code that runs later, outside the sandbox. `$HOME` is writable
by design (agents maintain `~/.claude`, `~/.codex`, credentials, caches), and
on macOS `/opt/homebrew` is writable and executable so agents can
`brew install` tools. A malicious or compromised agent can therefore drop an
executable into a `PATH` directory such as `/opt/homebrew/bin`, or edit shell
startup files (`~/.zshrc`, `~/.config/...`), and that code executes with the
user's full, unsandboxed privileges the next time a shell or command runs.

This is an accepted trade-off of giving agents a usable home directory and
tool installation. If your threat model treats the agent itself as the
adversary, review what it wrote to `$HOME` and the Homebrew prefix before
trusting the machine, or run it against a dedicated user account.

### Supply chain

The `curl | bash` installer verifies the release tarball against a SHA-256
checksum downloaded from the same GitHub release. This protects integrity (a
corrupted download fails), not authenticity: releases are not yet signed, so
trust rests on GitHub's account and release infrastructure. The uninstaller
fetches the helper-teardown script from the repository pinned to a release
tag. Review the scripts before piping them to `bash` if this trust model is
not acceptable for your environment.

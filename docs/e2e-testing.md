# End-to-End Testing in Tart VMs

This documents the e2e setup used to verify that the root PF helper daemon,
the `utun` enforcement, and the process sandbox work together on a real
macOS guest — the acceptance check is `curl ipinfo.io` succeeding *inside*
the sandbox while LAN egress is blocked.

Verified on 2026-07-07 against a macOS 26.4 guest: helper transitioned
not installed → active session anchor → not installed, the PF anchor
`com.apple/lianyaohu-$uid` held group-scoped rules only while the agent ran,
sandboxed `curl ipinfo.io` returned the tunnel exit's identity, and a
sandboxed LAN `curl` never connected.

## Topology

Two [Tart](https://tart.run) VMs on the host's shared NAT network
(`192.168.64.0/24`), with [ShadowVPN](https://github.com/madeye/shadowvpn)
providing a real point-to-point `utun`:

```text
┌────────────────────────── macOS VM ──────────────────────────┐
│ lianyaohu ─ sandbox-exec ─ curl ipinfo.io                    │
│      │            PF anchor com.apple/lianyaohu-501          │
│      └─ root helper (LaunchDaemon, /var/run/…helper.sock)    │
│ shadowvpn-client → utun4  10.9.0.2 ←→ 10.9.0.1               │
└────────────────┬─────────────────────────────────────────────┘
                 │ UDP 8388 (via host relay, see "Fixtures")
┌────────────────┴───────── Ubuntu VM ─────────────────────────┐
│ shadowvpn-server → tun0 10.9.0.1                             │
│ sysctl ip_forward=1, iptables MASQUERADE 10.9.0.0/24         │
└──────────────────────────────────────────────────────────────┘
```

The macOS guest is a clone of a base macOS image; the server VM is a clone of
`ghcr.io/cirruslabs/ubuntu:latest`. Both use the Cirrus Labs default
credentials (`admin`/`admin`, passwordless sudo).

## Building the pieces

On the (Apple Silicon) host:

```sh
# LianYaoHu launcher + root helper (one binary; run in this repo)
cargo build --release -p lianyaohu

# ShadowVPN client for the macOS guest (run in the shadowvpn repo)
cargo build --release --bin shadowvpn-client

# ShadowVPN server for the Ubuntu guest (cargo-zigbuild, no Docker needed)
cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.31 --bin shadowvpn-server
```

macOS guest binaries are host-native (same arch, default deployment target),
so no cross toolchain is needed for them.

## Server VM (Ubuntu)

```sh
sudo install -m755 shadowvpn-server /usr/local/bin/
sudo sysctl -w net.ipv4.ip_forward=1
WAN=$(ip route show default | awk '/default/ {print $5; exit}')
sudo iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$WAN" -j MASQUERADE
sudo iptables -A FORWARD -s 10.9.0.0/24 -j ACCEPT
sudo iptables -A FORWARD -d 10.9.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo shadowvpn-server -c server.json   # 0.0.0.0:8388, tun 10.9.0.1, peer 10.9.0.2
```

## macOS VM

Install the launcher and helper (prebuilt binaries; this mirrors
`scripts/install-helper.sh` without the in-VM cargo build):

```sh
sudo install -m755 lianyaohu shadowvpn-client /usr/local/bin/
sudo install -m755 lianyaohu /usr/local/libexec/lianyaohu
# install /Library/LaunchDaemons/io.github.madeye.lianyaohu.helper.plist
# (same plist as scripts/install-helper.sh; it runs "lianyaohu helper"), then:
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.madeye.lianyaohu.helper.plist
lianyaohu --helper-status   # expect: "not installed" (daemon answered)
```

Bring up the VPN and route the default IPv4 path through it:

```sh
sudo shadowvpn-client -c client.json    # creates utun4: 10.9.0.2 -> 10.9.0.1
sudo route -n add -net 0.0.0.0/1 10.9.0.1
sudo route -n add -net 128.0.0.0/1 10.9.0.1
route -n get 1.1.1.1   # must report interface: utun4
```

## The test

Run detached inside the guest (see "SSH self-cut" below), as the normal user:

```sh
lianyaohu --vpn utun4 -- /bin/sh -c '
  curl -s --max-time 30 ipinfo.io          # must succeed (via utun4)
  curl -s --max-time 8 http://192.168.64.1:18080/   # LAN: must be blocked
'
```

While the agent runs, from a second (detached) context:

```sh
lianyaohu --helper-status                      # expect: installed
ANCHOR=$(sudo pfctl -a com.apple -s Anchors | awk '/com.apple\/lianyaohu-/ {print $1; exit}')
test -n "$ANCHOR"
sudo pfctl -a "$ANCHOR" -sr                    # expect the generated rules
```

After the agent exits, `--helper-status` must report `not installed` and
the temporary `com.apple/lianyaohu-*` anchor must be empty or absent.

Pass criteria:

1. Sandboxed `curl ipinfo.io` exits 0 and prints the ipinfo JSON.
2. Helper status is `installed` only during the run; a temporary
   `com.apple/lianyaohu-*` PF anchor holds rules matching `group 2000000`, not
   the caller's UID.
3. The sandboxed LAN `curl` never connects.
4. Server-side proof the flow used the tunnel: the `iptables` counters on the
   Ubuntu VM (`-t nat -L -v`) advance for the tunnel subnet.
5. The agent environment is sanitized (e.g. `TZ=UTC` inside the sandbox).

## Test-bench fixtures and gotchas

These are properties of the lab network, not of LianYaoHu — but they will eat
your time if you don't know them:

- **Tart NAT isolates guest↔guest traffic** (ARP never resolves between VMs).
  Bridge the ShadowVPN UDP through the host's bridge IP:

  ```sh
  socat -T600 UDP4-LISTEN:8388,bind=192.168.64.1,reuseaddr,fork \
        UDP4:<ubuntu-vm-ip>:8388
  ```

  and point the client's `server` at `192.168.64.1:8388`.

- **The guests' raw uplink may not reach the probe target** (e.g. ipinfo.io
  unreachable from the physical network while the host's own VPN can reach
  it). If so, add a tunnel-exit relay — on the Ubuntu VM:

  ```sh
  sudo iptables -t nat -A PREROUTING -i tun0 -p tcp --dport 80 \
       -j DNAT --to-destination 192.168.64.1:18080
  ```

  and on the host: `socat TCP4-LISTEN:18080,bind=192.168.64.1,reuseaddr,fork
  TCP4:ipinfo.io:80`. The sandbox→PF→utun→VPN→NAT path stays fully genuine;
  only the last hop is relayed.

- **Routes die with the utun.** If the VPN client restarts, the kernel
  silently drops the `/1` routes — re-add them after every client start, or
  traffic silently reverts to `en0`. LianYaoHu's default-route preflight
  refuses to launch in that state, which is exactly the point of the check.

- **Stale cloned routes.** macOS keeps `WASCLONED` per-host routes created
  under the old default route; they can pin a specific destination to `en0`
  even after the `/1` routes exist (`route -n get <ip>` shows `IFSCOPE`
  `WASCLONED` on `en0`; delete with `route -n delete -host <ip>`). The PF
  `block ... on ! utunN` rule still stops that traffic for the agent group —
  defense in depth working as designed.

- **`--shared-user-pf` can cut your own SSH session.** The current default
  dedicated-group path does not match the desktop user's SSH sockets. If you
  explicitly test the current-UID fallback, it blocks LAN TCP for the user's
  UID, and the test user's SSH connection to the VM is exactly that. Run that
  fallback test as a `nohup`-detached script inside the guest writing to a
  result file, and poll the file afterwards.

- **`block return` LAN denials surface as timeouts**, not instant RSTs, in
  this topology; the block is still effective (the connection never
  establishes).

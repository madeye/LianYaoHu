---
layout: home

hero:
  name: LianYaoHu
  text: 炼妖壶
  tagline: >-
    Run Claude Code, Codex, or any code agent inside a constrained macOS
    sandbox — with all of its traffic forced through a VPN utun interface.
  actions:
    - theme: brand
      text: Getting Started
      link: /guide
    - theme: alt
      text: Architecture
      link: /architecture
    - theme: alt
      text: GitHub
      link: https://github.com/madeye/LianYaoHu

features:
  - icon: 📦
    title: Process sandbox
    details: >-
      The agent runs under sandbox-exec with a deny-default profile — read/write
      only in $HOME, the working directory, and an isolated tmpdir; raw sockets,
      inbound connections, socket binding, and broad sysctl reads are denied.
  - icon: 🔒
    title: PF network guard
    details: >-
      A root helper daemon installs a per-uid PF anchor that blocks LAN
      destinations, steers IPv4 TCP/UDP into the selected utun, and blocks
      egress on every other interface while the agent runs.
  - icon: 🕵️
    title: Identity hygiene
    details: >-
      Host-identifying environment variables (hostname, SSH, MAC, serial,
      timezone markers) are stripped, TZ is pinned to UTC, and timezone
      preference files are unreadable from inside the sandbox.
  - icon: 🧪
    title: Verified end to end
    details: >-
      The full stack — sandbox, root helper, PF anchor, utun routing — is
      exercised in a Tart macOS VM against a real ShadowVPN tunnel.
---

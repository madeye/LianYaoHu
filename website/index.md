---
layout: home

hero:
  name: LianYaoHu
  text: 炼妖壶
  tagline: >-
    Run Claude Code, Codex, or any code agent behind a helper-managed VPN
    network guard on macOS or Linux.
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
    title: Platform confinement
    details: >-
      macOS runs the agent under sandbox-exec with a deny-default profile.
      Linux applies Landlock filesystem rules, seccomp syscall filtering, and
      owner-scoped firewall rules.
  - icon: 🔒
    title: Network guard
    details: >-
      A root helper runs each guarded process with the caller UID and a
      dedicated _lianyaohu effective GID, then installs group-scoped PF or
      iptables rules that leave other desktop traffic alone.
  - icon: 🔑
    title: Credentials keep working
    details: >-
      Agents join the caller's login session, so keychain-backed logins
      (Claude Code, gh, git credential helpers) don't prompt again, and
      loopback-only listeners keep OAuth callback flows working inside the
      sandbox.
  - icon: 🕵️
    title: Identity hygiene
    details: >-
      Host-identifying environment variables (hostname, SSH, MAC, serial,
      timezone markers) are stripped, TZ is pinned to UTC, and timezone
      preference files are unreadable from inside the sandbox.
  - icon: 🧪
    title: Verified end to end
    details: >-
      macOS and Linux helper paths are exercised in Tart VMs; Linux verifies
      firewall, filesystem, and process-syscall confinement in Ubuntu.
---

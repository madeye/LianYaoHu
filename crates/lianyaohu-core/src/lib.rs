//! Core library for [LianYaoHu](https://lyh.maxlv.net/) (炼妖壶) — a launcher
//! that runs code agents (Claude Code, Codex, …) inside a sanitized
//! environment with a VPN-only network guard.
//!
//! Everything policy-related lives here and is shared by the unprivileged
//! launcher and the root helper daemon, so both sides always render identical
//! rules:
//!
//! - [`policy`] — the typed [`policy::SandboxPolicy`]: destination
//!   allow/deny rules (parsed, never free text), LAN exceptions, path grants,
//!   and narrow-home mode.
//! - [`config`] — layered TOML configuration (global + per-project) with a
//!   hash-pinned trust store for project files.
//! - `sandbox_profile` (macOS) / `linux_sandbox` (Linux) — the process
//!   sandbox: a `sandbox-exec` SBPL profile, or Landlock + seccomp-BPF.
//!   (Plain code spans: these modules are `cfg`-gated per platform, so
//!   intra-doc links would break on the other one.)
//! - `pf` (macOS) / `linux_firewall` (Linux) — owner-scoped firewall rule
//!   sets pinning agent traffic to the selected VPN interface.
//! - [`env_policy`] — environment sanitization (identity stripping, loader
//!   injection blocking).
//! - [`launch`] / [`helper`] — the versioned launch spec and the root-helper
//!   wire protocol over a Unix socket.
//! - [`interfaces`] / [`route`] — VPN interface enumeration/validation and
//!   the routing-table check that the VPN carries all IPv4 egress.
//!
//! The security model and architecture are documented at
//! <https://lyh.maxlv.net/security-model> and
//! <https://lyh.maxlv.net/architecture>.

pub mod config;
pub mod env_policy;
pub mod helper;
pub mod interfaces;
pub mod launch;
#[cfg(target_os = "linux")]
pub mod linux_firewall;
#[cfg(target_os = "linux")]
pub mod linux_sandbox;
#[cfg(target_os = "macos")]
pub mod pf;
pub mod policy;
pub mod route;
#[cfg(target_os = "macos")]
pub mod sandbox_profile;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

pub fn err(message: impl Into<String>) -> Error {
    message.into().into()
}

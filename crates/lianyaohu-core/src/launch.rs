use crate::policy::SandboxPolicy;
use crate::{Result, err};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const MAX_LAUNCH_SPEC_BYTES: u64 = 1024 * 1024;

/// The newest spec revision this build understands. Legacy specs carry no
/// version field (0); specs with a custom sandbox policy carry 2.
pub const LAUNCH_SPEC_VERSION: u32 = 2;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaunchSpec {
    pub command: Vec<String>,
    pub cwd: String,
    pub environment: BTreeMap<String, String>,
    pub sandbox_profile: String,
    /// 0 for legacy specs. A helper older than the spec must refuse to run it
    /// rather than silently ignore fields it does not understand — silent
    /// partial enforcement is the one failure a security tool cannot have.
    #[serde(default)]
    pub spec_version: u32,
    /// `None` means exactly the built-in policy (today's behavior).
    #[serde(default)]
    pub policy: Option<SandboxPolicy>,
}

impl LaunchSpec {
    pub fn new(
        command: Vec<String>,
        cwd: impl Into<String>,
        environment: BTreeMap<String, String>,
        sandbox_profile: impl Into<String>,
    ) -> Self {
        Self {
            command,
            cwd: cwd.into(),
            environment,
            sandbox_profile: sandbox_profile.into(),
            spec_version: 0,
            policy: None,
        }
    }

    /// Attaches a custom sandbox policy, upgrading the spec to the versioned
    /// format so an older helper rejects it instead of ignoring the policy.
    pub fn with_policy(mut self, policy: SandboxPolicy) -> Self {
        self.spec_version = LAUNCH_SPEC_VERSION;
        self.policy = Some(policy);
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.command.is_empty() {
            return Err(err("launch spec command is empty"));
        }
        if self.cwd.is_empty() {
            return Err(err("launch spec cwd is empty"));
        }
        if self.sandbox_profile.is_empty() {
            return Err(err("launch spec sandbox profile is empty"));
        }
        if self.spec_version > LAUNCH_SPEC_VERSION {
            return Err(err(format!(
                "launch spec version {} is newer than this helper supports ({}); \
                 update the helper with scripts/install-helper.sh",
                self.spec_version, LAUNCH_SPEC_VERSION
            )));
        }
        if let Some(policy) = &self.policy {
            policy.validate()?;
        }
        Ok(())
    }

    // The spec carries the agent's environment (API keys, tokens); create it
    // owner-only so other local users cannot read it out of the temp tree.
    pub fn write_json(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let json = serde_json::to_vec(self)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&json)?;
        Ok(())
    }

    // The path arrives over the helper socket from an untrusted peer and is
    // opened by a root daemon, so it gets the same treatment as every other
    // client-supplied path: no symlink at the final component, a regular file
    // only, owned by the authenticated caller, with a bounded read.
    pub fn read_json(path: &Path, required_owner: u32, timeout: Duration) -> Result<Self> {
        // O_NONBLOCK keeps the open from hanging on a writer-less FIFO;
        // regular-file reads ignore it once the type check below has passed.
        // O_NOFOLLOW refuses a symlink as the final component so the metadata
        // checks apply to the path's own inode.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| err(format!("launch spec {}: {error}", path.display())))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(err("launch spec is not a regular file"));
        }
        if metadata.uid() != required_owner {
            return Err(err(format!(
                "launch spec is not owned by uid {required_owner}"
            )));
        }
        if metadata.len() > MAX_LAUNCH_SPEC_BYTES {
            return Err(err("launch spec is too large"));
        }
        let bytes = read_with_deadline(file, timeout)?;
        if bytes.len() as u64 > MAX_LAUNCH_SPEC_BYTES {
            return Err(err("launch spec is too large"));
        }
        let spec = serde_json::from_slice::<Self>(&bytes)?;
        spec.validate()?;
        Ok(spec)
    }
}

/// Reads the spec on a helper thread and gives up after `timeout`: even a
/// regular file can block a read arbitrarily long (FUSE, network mounts), and
/// the caller must not pin a worker slot on it. On timeout the reader thread
/// is abandoned; it holds only the file descriptor.
fn read_with_deadline(file: File, timeout: Duration) -> Result<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = file
            .take(MAX_LAUNCH_SPEC_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(timeout) {
        Ok(result) => Ok(result?),
        Err(_) => Err(err("timed out reading launch spec")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_spec_round_trips_json() {
        let spec = LaunchSpec::new(
            vec!["/bin/echo".to_string(), "ok".to_string()],
            "/tmp",
            BTreeMap::from([("PATH".to_string(), "/usr/bin".to_string())]),
            "(version 1)",
        );

        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(serde_json::from_str::<LaunchSpec>(&json).unwrap(), spec);
    }

    #[test]
    fn launch_spec_rejects_empty_command() {
        let spec = LaunchSpec::new(Vec::new(), "/tmp", BTreeMap::new(), "(version 1)");

        assert!(spec.validate().is_err());
    }

    fn scratch_dir() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lianyaohu-launch-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_spec() -> LaunchSpec {
        LaunchSpec::new(
            vec!["/bin/echo".to_string(), "ok".to_string()],
            "/tmp",
            BTreeMap::from([("PATH".to_string(), "/usr/bin".to_string())]),
            "(version 1)",
        )
    }

    const READ_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn read_json_round_trips_for_owned_regular_file() {
        let dir = scratch_dir();
        let path = dir.join("launch.json");
        let spec = sample_spec();
        spec.write_json(&path).unwrap();

        let uid = unsafe { libc::getuid() };
        assert_eq!(
            LaunchSpec::read_json(&path, uid, READ_TIMEOUT).unwrap(),
            spec
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_json_rejects_wrong_owner() {
        let dir = scratch_dir();
        let path = dir.join("launch.json");
        sample_spec().write_json(&path).unwrap();

        let other_uid = unsafe { libc::getuid() } + 1;
        let error = LaunchSpec::read_json(&path, other_uid, READ_TIMEOUT).unwrap_err();
        assert!(error.to_string().contains("not owned by uid"), "{error}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // A FIFO spec path must fail closed immediately — without O_NONBLOCK the
    // open alone would hang a root helper worker until a writer showed up.
    #[test]
    fn read_json_rejects_fifo_without_blocking() {
        let dir = scratch_dir();
        let path = dir.join("launch.fifo");
        let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let uid = unsafe { libc::getuid() };
        let started = std::time::Instant::now();
        let error = LaunchSpec::read_json(&path, uid, READ_TIMEOUT).unwrap_err();
        assert!(error.to_string().contains("regular file"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(1));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_json_rejects_symlinked_spec() {
        let dir = scratch_dir();
        let target = dir.join("launch.json");
        sample_spec().write_json(&target).unwrap();
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let uid = unsafe { libc::getuid() };
        assert!(LaunchSpec::read_json(&link, uid, READ_TIMEOUT).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_json_rejects_oversized_spec() {
        let dir = scratch_dir();
        let path = dir.join("huge.json");
        std::fs::write(&path, vec![b' '; (MAX_LAUNCH_SPEC_BYTES + 1) as usize]).unwrap();

        let uid = unsafe { libc::getuid() };
        let error = LaunchSpec::read_json(&path, uid, READ_TIMEOUT).unwrap_err();
        assert!(error.to_string().contains("too large"), "{error}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

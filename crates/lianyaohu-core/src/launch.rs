use crate::policy::SandboxPolicy;
use crate::{Result, err};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

const MAX_LAUNCH_SPEC_BYTES: u64 = 1024 * 1024;

/// Per-uid cap on spec-reader threads abandoned past their deadline that may
/// still be in flight. A hostile filesystem that never returns would
/// otherwise convert each timed-out read into a permanently leaked thread and
/// file descriptor inside the root helper; once this many abandoned readers
/// are outstanding for a uid, that uid's spec reads fail closed until some of
/// them finish.
const MAX_ABANDONED_SPEC_READS: usize = 16;

/// Outstanding abandoned readers keyed by the requesting peer's uid. The cap
/// is enforced per uid — never process-wide — so one user stalling readers on
/// a hostile mount locks out only their own launches, not every other user's.
static ABANDONED_SPEC_READS: AbandonedReads = AbandonedReads::new();

/// One client-visible message for every way a spec file can be rejected.
/// The helper runs as root, so per-cause errors (`ENOENT` vs "not a regular
/// file" vs "not owned by uid N") would let a local user probe existence and
/// ownership of arbitrary paths — including ones under directories they
/// cannot traverse. The per-cause detail is discarded entirely, not logged:
/// the daemon's stderr can be routed to a world-readable log file (launchd
/// does exactly that on macOS), which would reopen the same oracle.
const SPEC_REJECTED: &str = "launch spec rejected: it must be an existing regular file owned by \
                             the calling user (no symlinks), at most 1 MiB";

/// Tracks abandoned spec readers per uid. Increments happen on the caller
/// side when it gives up on a stalled reader; decrements happen on whichever
/// side loses the [`AtomicBool`] handoff race once the reader finally
/// finishes, so the count for a uid can never underflow.
struct AbandonedReads {
    per_uid: Mutex<BTreeMap<u32, usize>>,
}

impl AbandonedReads {
    const fn new() -> Self {
        Self {
            per_uid: Mutex::new(BTreeMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<u32, usize>> {
        // The map holds plain counters mutated one at a time, so a panic in
        // another thread cannot leave a torn invariant; recover rather than
        // poison every future launch.
        self.per_uid
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn is_at_cap(&self, uid: u32) -> bool {
        self.lock().get(&uid).copied().unwrap_or(0) >= MAX_ABANDONED_SPEC_READS
    }

    fn increment(&self, uid: u32) {
        *self.lock().entry(uid).or_insert(0) += 1;
    }

    fn decrement(&self, uid: u32) {
        let mut counts = self.lock();
        match counts.get_mut(&uid) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                counts.remove(&uid);
            }
            // Unreachable — every decrement is preceded by an increment for
            // the same uid — but never underflow if the invariant breaks.
            None => {}
        }
    }
}

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
    // only, owned by the authenticated caller, with a bounded read. The open
    // itself runs on the deadlined reader thread — open() blocks just like
    // read() on a hostile filesystem — and every rejection collapses into one
    // generic client-visible message so the root daemon is not a path oracle.
    // `required_owner` is the authenticated peer uid; it also keys the
    // abandoned-reader cap so one uid's stalled readers cannot block others.
    pub fn read_json(path: &Path, required_owner: u32, timeout: Duration) -> Result<Self> {
        let owned_path = path.to_path_buf();
        let bytes = read_with_deadline(
            move || {
                // The per-cause detail (and the path) is dropped, not merely
                // kept off the socket: the daemon's stderr may land in a
                // world-readable log, which would reopen the path oracle.
                open_and_read_spec(&owned_path, required_owner).map_err(|_| err(SPEC_REJECTED))
            },
            timeout,
            required_owner,
            &ABANDONED_SPEC_READS,
        )?;
        let spec = serde_json::from_slice::<Self>(&bytes)?;
        spec.validate()?;
        Ok(spec)
    }
}

/// Opens and reads the spec file with the defensive checks described on
/// [`LaunchSpec::read_json`]. Runs on the deadlined reader thread: on a
/// hostile filesystem the open can stall exactly like the read.
fn open_and_read_spec(path: &Path, required_owner: u32) -> Result<Vec<u8>> {
    // O_NONBLOCK keeps the open from hanging on a writer-less FIFO;
    // regular-file reads ignore it once the type check below has passed.
    // O_NOFOLLOW refuses a symlink as the final component so the metadata
    // checks apply to the path's own inode.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| err(format!("open: {error}")))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(err("not a regular file"));
    }
    if metadata.uid() != required_owner {
        return Err(err(format!("not owned by uid {required_owner}")));
    }
    if metadata.len() > MAX_LAUNCH_SPEC_BYTES {
        return Err(err("too large"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_LAUNCH_SPEC_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LAUNCH_SPEC_BYTES {
        return Err(err("too large"));
    }
    Ok(bytes)
}

/// Runs `read` on its own reader thread and gives up after `timeout`: open()
/// and read() can both block arbitrarily long (FUSE, network mounts), and the
/// caller must not pin a worker slot on either. On timeout the reader thread
/// is abandoned holding its file descriptor; `abandoned` counts those still
/// in flight per uid, and new reads for `uid` are refused once
/// [`MAX_ABANDONED_SPEC_READS`] are outstanding for it, so a hostile mount
/// cannot leak unbounded threads and fds — and cannot lock out other uids.
fn read_with_deadline<F>(
    read: F,
    timeout: Duration,
    uid: u32,
    abandoned: &'static AbandonedReads,
) -> Result<Vec<u8>>
where
    F: FnOnce() -> Result<Vec<u8>> + Send + 'static,
{
    if abandoned.is_at_cap(uid) {
        return Err(err(
            "too many stalled launch spec readers; refusing new spec reads until they finish",
        ));
    }
    let (sender, receiver) = mpsc::channel();
    // `finished` hands the abandoned count between the two sides without a
    // race: whoever swaps it to true second knows the other side acted first.
    let finished = Arc::new(AtomicBool::new(false));
    let reader_finished = Arc::clone(&finished);
    // Builder, not thread::spawn: a failed spawn must surface as a refused
    // request, never a panic inside the daemon's connection worker.
    thread::Builder::new()
        .name("lianyaohu-spec-read".to_string())
        .spawn(move || {
            let result = read();
            let _ = sender.send(result);
            // If the caller already gave up, this thread was counted as
            // abandoned; release that count now that it has finished.
            if reader_finished.swap(true, Ordering::SeqCst) {
                abandoned.decrement(uid);
            }
        })
        .map_err(|error| err(format!("spawn launch spec reader: {error}")))?;
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Count the abandonment before flagging the handoff: if the
            // reader finished in the window, the swap reports it and the
            // count is taken back, so the counter can never underflow.
            abandoned.increment(uid);
            if finished.swap(true, Ordering::SeqCst) {
                abandoned.decrement(uid);
            }
            Err(err("timed out reading launch spec"))
        }
        // The reader dropped the channel without sending (panicked); it is
        // not stalled, so it is not counted as abandoned.
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(err("launch spec reader failed")),
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
        // The client-visible message is the generic one — per-cause detail
        // would make the root helper an ownership oracle.
        assert_eq!(error.to_string(), SPEC_REJECTED);

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
        assert_eq!(error.to_string(), SPEC_REJECTED);
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
        assert_eq!(error.to_string(), SPEC_REJECTED);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // The one mechanism the availability fix relies on: a filesystem that
    // never delivers data must hit the deadline instead of pinning the
    // caller, and the abandoned reader must be counted against its uid while
    // it is stalled and released once it finally finishes.
    #[test]
    fn stalled_read_times_out_and_counts_the_abandoned_reader() {
        use std::fs::File;
        use std::os::fd::FromRawFd;

        static ABANDONED: AbandonedReads = AbandonedReads::new();
        const UID: u32 = 1001;

        // A pipe with the write end held open but silent: read_to_end blocks
        // indefinitely, like a stalling FUSE mount.
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let reader = unsafe { File::from_raw_fd(fds[0]) };

        let started = std::time::Instant::now();
        let error = read_with_deadline(
            move || {
                let mut file = reader;
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                Ok(bytes)
            },
            Duration::from_millis(100),
            UID,
            &ABANDONED,
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
        // The abandoned reader occupies a slot for its uid while stalled...
        assert_eq!(ABANDONED.lock().get(&UID).copied(), Some(1));

        // ...and releases it once the blocked read completes (EOF on close).
        assert_eq!(unsafe { libc::close(fds[1]) }, 0);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while ABANDONED.lock().get(&UID).is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "abandoned reader slot was never released"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    // The cap is per uid: a uid at the cap is refused before anything is
    // spawned (fail closed, without consuming a slot), while every other uid
    // keeps reading normally — one user's hostile mount must not lock out
    // launches for the rest of the machine.
    #[test]
    fn abandoned_reader_cap_is_enforced_per_uid() {
        static ABANDONED: AbandonedReads = AbandonedReads::new();
        const CAPPED_UID: u32 = 1001;
        const OTHER_UID: u32 = 1002;
        ABANDONED
            .lock()
            .insert(CAPPED_UID, MAX_ABANDONED_SPEC_READS);

        let error = read_with_deadline(
            || Ok(Vec::new()),
            Duration::from_secs(1),
            CAPPED_UID,
            &ABANDONED,
        )
        .unwrap_err();
        assert!(error.to_string().contains("stalled launch spec"), "{error}");

        // The other uid is unaffected by the capped uid's stalled readers.
        let bytes = read_with_deadline(
            || Ok(vec![42]),
            Duration::from_secs(5),
            OTHER_UID,
            &ABANDONED,
        )
        .unwrap();
        assert_eq!(bytes, vec![42]);

        let counts = ABANDONED.lock();
        assert_eq!(
            counts.get(&CAPPED_UID).copied(),
            Some(MAX_ABANDONED_SPEC_READS)
        );
        assert_eq!(counts.get(&OTHER_UID), None);
    }

    // Every rejection must collapse into the one generic message: no probed
    // path and no per-cause detail (existence, type, ownership) may reach the
    // client — or anywhere else — from the root helper.
    #[test]
    fn rejection_message_reveals_neither_path_nor_cause() {
        let dir = scratch_dir();
        let missing = dir.join("no-such-spec.json");
        let uid = unsafe { libc::getuid() };

        let error = LaunchSpec::read_json(&missing, uid, READ_TIMEOUT).unwrap_err();
        let message = error.to_string();
        assert_eq!(message, SPEC_REJECTED);
        assert!(!message.contains(missing.to_str().unwrap()));
        for cause in [
            "No such file",
            "os error",
            "not a regular file",
            "not owned",
        ] {
            assert!(!message.contains(cause), "leaks cause: {message}");
        }

        // Wrong owner collapses into the identical message, so the two causes
        // are indistinguishable to the caller.
        let owned = dir.join("launch.json");
        sample_spec().write_json(&owned).unwrap();
        let error = LaunchSpec::read_json(&owned, uid + 1, READ_TIMEOUT).unwrap_err();
        assert_eq!(error.to_string(), message);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

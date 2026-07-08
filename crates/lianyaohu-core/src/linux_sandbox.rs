use crate::{Result, err};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::mem;
use std::os::fd::RawFd;
use std::path::{Component, Path, PathBuf};
use std::{io, ptr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxSandbox {
    pub home: PathBuf,
    pub cwd: PathBuf,
    pub tmpdir: PathBuf,
}

impl LinuxSandbox {
    pub fn new(
        home: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        tmpdir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            home: home.into(),
            cwd: cwd.into(),
            tmpdir: tmpdir.into(),
        }
    }

    pub fn from_environment(
        cwd: impl Into<PathBuf>,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self> {
        let home = environment
            .get("HOME")
            .ok_or_else(|| err("launch environment is missing HOME"))?;
        let tmpdir = environment
            .get("TMPDIR")
            .ok_or_else(|| err("launch environment is missing TMPDIR"))?;
        Ok(Self::new(home, cwd, tmpdir))
    }

    pub fn apply(&self) -> Result<()> {
        apply_no_new_privs()?;
        apply_landlock(self)?;
        apply_seccomp()
    }

    pub fn render_summary(&self) -> String {
        let writable = writable_paths(self)
            .into_iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "Linux sandbox:\n  writable: {writable}\n  read-only: /bin, /sbin, /usr, /lib, /lib64, /etc, /opt, /proc/self\n  seccomp: deny bind/listen/accept, raw/non-IP sockets, mount/ns/ptrace/bpf/key/kernel APIs\n"
        )
    }
}

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

const LANDLOCK_ABI_2: i32 = 2;
const LANDLOCK_ABI_3: i32 = 3;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

fn apply_no_new_privs() -> Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

fn apply_landlock(sandbox: &LinuxSandbox) -> Result<()> {
    let abi = landlock_abi_version()?;
    if abi < 1 {
        return Err(err("Landlock is not available on this Linux kernel"));
    }

    let handled_access = handled_landlock_access(abi);
    let ruleset_attr = LandlockRulesetAttr {
        handled_access_fs: handled_access,
    };
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &ruleset_attr as *const LandlockRulesetAttr,
            mem::size_of::<LandlockRulesetAttr>(),
            0,
        )
    };
    if ruleset_fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let ruleset_fd = FdGuard(ruleset_fd as RawFd);

    let read_access = read_landlock_access(handled_access);
    let write_access = write_landlock_access(handled_access);

    for path in read_only_paths() {
        add_path_rule(ruleset_fd.0, &path, read_access)?;
    }
    for path in writable_paths(sandbox) {
        add_path_rule(ruleset_fd.0, &path, read_access | write_access)?;
    }

    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd.0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

fn landlock_abi_version() -> Result<i32> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<LandlockRulesetAttr>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc >= 0 {
        Ok(rc as i32)
    } else {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP)) {
            Ok(0)
        } else {
            Err(error.into())
        }
    }
}

fn handled_landlock_access(abi: i32) -> u64 {
    let mut access = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;
    if abi >= LANDLOCK_ABI_2 {
        access |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= LANDLOCK_ABI_3 {
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    access
}

fn read_landlock_access(handled_access: u64) -> u64 {
    handled_access
        & (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
}

fn write_landlock_access(handled_access: u64) -> u64 {
    handled_access
        & (LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM
            | LANDLOCK_ACCESS_FS_REFER
            | LANDLOCK_ACCESS_FS_TRUNCATE)
}

fn read_only_paths() -> Vec<PathBuf> {
    [
        "/bin",
        "/sbin",
        "/usr",
        "/lib",
        "/lib64",
        "/etc",
        "/opt",
        "/proc/self",
        "/proc/thread-self",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

fn writable_paths(sandbox: &LinuxSandbox) -> Vec<PathBuf> {
    let mut paths = [
        sandbox.home.clone(),
        sandbox.cwd.clone(),
        sandbox.tmpdir.clone(),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/dev"),
    ]
    .into_iter()
    .filter_map(safe_writable_path)
    .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

fn safe_writable_path(path: PathBuf) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let normalized = normalize_absolute_path(&path);
    (normalized != Path::new("/")).then_some(normalized)
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(segment) => normalized.push(segment),
            Component::Prefix(_) => {}
        }
    }
    normalized
}

fn add_path_rule(ruleset_fd: RawFd, path: &Path, allowed_access: u64) -> Result<()> {
    let Some(path) = path.to_str() else {
        return Ok(());
    };
    let c_path = CString::new(path)?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if matches!(error.kind(), io::ErrorKind::NotFound) {
            return Ok(());
        }
        return Err(error.into());
    }
    let fd = FdGuard(fd);
    let path_beneath = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: fd.0,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &path_beneath as *const LandlockPathBeneathAttr,
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

struct FdGuard(RawFd);

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARG0_OFFSET: u32 = 16;
const SECCOMP_DATA_ARG1_OFFSET: u32 = 24;
const SOCK_TYPE_MASK: u32 = 0xf;

fn apply_seccomp() -> Result<()> {
    let mut filter = vec![
        stmt(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            SECCOMP_DATA_ARCH_OFFSET,
        ),
        jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            audit_arch(),
            1,
            0,
        ),
        stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            SECCOMP_DATA_NR_OFFSET,
        ),
    ];

    for syscall in denied_syscalls() {
        deny_syscall(&mut filter, syscall);
    }
    restrict_socket_syscall(&mut filter);

    filter.push(stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW));

    let mut program = libc::sock_fprog {
        len: filter
            .len()
            .try_into()
            .map_err(|_| err("seccomp filter is too large"))?,
        filter: filter.as_mut_ptr(),
    };

    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &mut program as *mut libc::sock_fprog,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

fn deny_syscall(filter: &mut Vec<libc::sock_filter>, syscall: libc::c_long) {
    filter.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        syscall as u32,
        0,
        1,
    ));
    filter.push(errno_return(libc::EPERM));
}

fn restrict_socket_syscall(filter: &mut Vec<libc::sock_filter>) {
    let socket_check_index = filter.len();
    filter.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        libc::SYS_socket as u32,
        0,
        0,
    ));
    filter.push(stmt(
        libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
        SECCOMP_DATA_ARG0_OFFSET,
    ));
    filter.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        libc::AF_UNIX as u32,
        0,
        1,
    ));
    filter.push(allow_return());
    filter.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        libc::AF_INET as u32,
        0,
        socket_type_check_len(),
    ));
    allow_stream_or_datagram_socket(filter);
    filter.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        libc::AF_INET6 as u32,
        0,
        socket_type_check_len(),
    ));
    allow_stream_or_datagram_socket(filter);
    filter.push(errno_return(libc::EPERM));

    let non_socket_skip = filter.len() - socket_check_index - 1;
    filter[socket_check_index].jf = non_socket_skip
        .try_into()
        .expect("socket seccomp filter fits in BPF jump offset");
}

fn allow_stream_or_datagram_socket(filter: &mut Vec<libc::sock_filter>) {
    filter.push(stmt(
        libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
        SECCOMP_DATA_ARG1_OFFSET,
    ));
    filter.push(stmt(
        libc::BPF_ALU | libc::BPF_AND | libc::BPF_K,
        SOCK_TYPE_MASK,
    ));
    filter.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        libc::SOCK_STREAM as u32,
        0,
        1,
    ));
    filter.push(allow_return());
    filter.push(jump(
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        libc::SOCK_DGRAM as u32,
        0,
        1,
    ));
    filter.push(allow_return());
    filter.push(errno_return(libc::EPERM));
}

fn socket_type_check_len() -> u8 {
    7
}

fn denied_syscalls() -> Vec<libc::c_long> {
    let syscalls = vec![
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_perf_event_open,
        libc::SYS_bpf,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_open_by_handle_at,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_reboot,
        libc::SYS_acct,
        libc::SYS_syslog,
        libc::SYS_personality,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
    ];
    #[cfg(target_arch = "x86_64")]
    {
        let mut syscalls = syscalls;
        syscalls.push(libc::SYS__sysctl);
        syscalls
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        syscalls
    }
}

fn audit_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        AUDIT_ARCH_X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        AUDIT_ARCH_AARCH64
    }
}

fn errno_return(errno: libc::c_int) -> libc::sock_filter {
    stmt(
        libc::BPF_RET | libc::BPF_K,
        libc::SECCOMP_RET_ERRNO | (errno as u32),
    )
}

fn allow_return() -> libc::sock_filter {
    stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW)
}

fn stmt(code: u32, k: u32) -> libc::sock_filter {
    unsafe { libc::BPF_STMT(code as u16, k) }
}

fn jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    unsafe { libc::BPF_JUMP(code as u16, k, jt, jf) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_names_policy_roots_and_seccomp() {
        let sandbox = LinuxSandbox::new("/home/alice", "/home/alice/project", "/tmp/lyh");
        let summary = sandbox.render_summary();

        assert!(summary.contains("/home/alice"));
        assert!(summary.contains("/home/alice/project"));
        assert!(summary.contains("/tmp/lyh"));
        assert!(summary.contains("read-only: /bin"));
        assert!(summary.contains("seccomp: deny bind/listen/accept"));
    }

    #[test]
    fn writable_policy_never_grants_filesystem_root() {
        let sandbox = LinuxSandbox::new("/", "/var/..", "/tmp/lyh");
        let writable = writable_paths(&sandbox);

        assert!(!writable.iter().any(|path| path == Path::new("/")));
        assert!(!writable.iter().any(|path| path == Path::new("/var/..")));
        assert!(writable.contains(&PathBuf::from("/tmp")));
        assert!(!sandbox.render_summary().contains("writable: /,"));
    }

    #[test]
    fn landlock_access_tracks_abi_versions() {
        assert_eq!(handled_landlock_access(1) & LANDLOCK_ACCESS_FS_REFER, 0);
        assert_ne!(handled_landlock_access(2) & LANDLOCK_ACCESS_FS_REFER, 0);
        assert_ne!(handled_landlock_access(3) & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
    }

    #[test]
    fn seccomp_filter_contains_core_denials() {
        let denied = denied_syscalls();

        assert!(denied.contains(&libc::SYS_bind));
        assert!(denied.contains(&libc::SYS_mount));
        assert!(denied.contains(&libc::SYS_ptrace));
        assert!(denied.contains(&libc::SYS_bpf));
    }
}

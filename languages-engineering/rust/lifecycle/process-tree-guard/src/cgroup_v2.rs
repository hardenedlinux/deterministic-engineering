// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Linux `cgroup v2` unified-hierarchy containment backend (`cgroup.procs` +
//! `cgroup.freeze` + `cgroup.kill`) for `ProcessTreeGuard` (10.154 / `LinuxCgroupV2Supervisor`).
//!
//! When running on Linux with a delegated writable cgroup v2 parent directory
//! (discovered via `/proc/self/cgroup` or explicit `PTREE_CGROUP_ROOT`), every
//! spawned supervisor is moved into a dedicated leaf cgroup inside `pre_exec`
//! BEFORE `exec()` runs (zero-TOCTOU). Because Linux cgroup membership is
//! inherited across `fork`, `clone`, and `setsid`, even an adversarial binary
//! calling `setsid()` and closing `PTREE_WATCHDOG_FD` cannot escape `cgroup.kill`.

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::io::IntoRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{inject_sigkill, target_exists};

/// Optional environment override specifying a delegated writable cgroup v2 parent directory.
pub const CGROUP_ROOT_ENV: &str = "PTREE_CGROUP_ROOT";

/// Active kernel containment strategy attached to a `ProcessTreeGuard`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainmentMode {
    /// Linux `cgroup v2` leaf scope with zero-TOCTOU `pre_exec` attachment and
    /// kernel-atomic `cgroup.kill` (or `cgroup.freeze` + `cgroup.procs` drain).
    CgroupV2Atomic { cgroup_path: PathBuf },
    /// Portable POSIX process-group (`setpgid`/`killpg`) + kernel Pipe-EOF watchdog.
    PgidAndPipeEof,
}

/// Termination primitive executed by `CgroupV2Scope::kill_atomic`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CgroupKillMethod {
    /// Kernel-atomic `cgroup.kill` (Linux >= 5.14) terminated the entire subtree in one write.
    AtomicCgroupKill,
    /// Fallback for older cgroup v2 kernels: froze `cgroup.freeze` and SIGKILL-drained `cgroup.procs`.
    FrozenProcsDrain { killed_pids: usize },
}

/// Owned leaf directory inside a Linux `cgroup v2` unified hierarchy.
#[derive(Debug, Clone)]
pub struct CgroupV2Scope {
    dir: PathBuf,
}

/// Parse the unified cgroup v2 relative path (`0::<rel_path>`) from `/proc/self/cgroup`.
pub fn parse_proc_self_cgroup_v2_path(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("0::") {
            let rel = rest.trim_start_matches('/').trim();
            return Some(rel.to_string());
        }
    }
    None
}

/// Parse newline-separated kernel PIDs from a `cgroup.procs` file.
pub fn parse_cgroup_procs(content: &str) -> Vec<u32> {
    content
        .split_whitespace()
        .filter_map(|tok| tok.parse::<u32>().ok())
        .collect()
}

fn verify_writable_cgroup_parent(parent: &Path) -> bool {
    if !parent.is_dir() || !parent.join("cgroup.procs").exists() {
        return false;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let probe = parent.join(format!(".ptree-probe-{}-{nanos}", std::process::id()));
    match fs::create_dir(&probe) {
        Ok(()) => {
            let _ = fs::remove_dir(&probe);
            true
        }
        Err(_) => false,
    }
}

impl CgroupV2Scope {
    /// Probe whether this process has a writable `cgroup v2` parent directory.
    ///
    /// Checks `PTREE_CGROUP_ROOT` first (on any Unix host for delegated scopes),
    /// then on Linux inspects `/proc/self/cgroup` -> `/sys/fs/cgroup/<rel>`.
    pub fn probe_writable_root() -> Option<PathBuf> {
        if let Ok(explicit) = std::env::var(CGROUP_ROOT_ENV) {
            let p = PathBuf::from(explicit);
            if verify_writable_cgroup_parent(&p) {
                return Some(p);
            }
            return None;
        }

        #[cfg(target_os = "linux")]
        {
            let content = fs::read_to_string("/proc/self/cgroup").ok()?;
            let rel = parse_proc_self_cgroup_v2_path(&content)?;
            let base = Path::new("/sys/fs/cgroup");
            let candidate = if rel.is_empty() {
                base.to_path_buf()
            } else {
                base.join(rel)
            };
            if verify_writable_cgroup_parent(&candidate) {
                return Some(candidate);
            }
        }

        None
    }

    /// Create a fresh leaf cgroup directory `<parent>/<name>`.
    pub fn create_under(parent: &Path, name: &str) -> io::Result<Self> {
        let dir = parent.join(name);
        fs::create_dir(&dir)?;
        Ok(Self { dir })
    }

    /// Path of the owned leaf cgroup directory.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Open `<dir>/cgroup.procs` with `O_WRONLY | O_CLOEXEC` before `fork()` so
    /// `pre_exec` can perform an async-signal-safe `write(fd, "0\n", 2)` with zero TOCTOU.
    pub fn open_procs_fd_for_pre_exec(&self) -> io::Result<i32> {
        let file = OpenOptions::new()
            .write(true)
            .open(self.dir.join("cgroup.procs"))?;
        Ok(file.into_raw_fd())
    }

    /// Freeze all processes and threads inside the leaf cgroup (`cgroup.freeze = 1`).
    pub fn freeze(&self) -> io::Result<()> {
        fs::write(self.dir.join("cgroup.freeze"), b"1\n")
    }

    /// Thaw a previously frozen leaf cgroup (`cgroup.freeze = 0`).
    pub fn unfreeze(&self) -> io::Result<()> {
        fs::write(self.dir.join("cgroup.freeze"), b"0\n")
    }

    /// Read live PIDs currently resident in `<dir>/cgroup.procs`.
    pub fn live_pids(&self) -> io::Result<Vec<u32>> {
        let content = fs::read_to_string(self.dir.join("cgroup.procs"))?;
        Ok(parse_cgroup_procs(&content))
    }

    /// Atomically terminate every process in this cgroup (including `setsid()` escapees).
    ///
    /// Prefers kernel-atomic `cgroup.kill = 1` (Linux >= 5.14); falls back cleanly to
    /// `cgroup.freeze = 1` + iterative `SIGKILL` drain of `cgroup.procs` on older kernels.
    pub fn kill_atomic(&self) -> io::Result<CgroupKillMethod> {
        let kill_file = self.dir.join("cgroup.kill");
        if kill_file.exists() {
            fs::write(&kill_file, b"1\n")?;
            return Ok(CgroupKillMethod::AtomicCgroupKill);
        }

        let _ = self.freeze();
        let mut killed_pids = 0usize;
        for _ in 0..16 {
            let pids = self.live_pids().unwrap_or_default();
            if pids.is_empty() {
                break;
            }
            let mut any_alive = false;
            for pid in pids {
                if target_exists(pid as i32) {
                    any_alive = true;
                    if inject_sigkill(pid).is_ok() {
                        killed_pids += 1;
                    }
                }
            }
            if !any_alive {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = self.unfreeze();
        Ok(CgroupKillMethod::FrozenProcsDrain { killed_pids })
    }

    /// Remove the empty leaf cgroup directory (best-effort after processes are reaped).
    pub fn cleanup(&self) -> io::Result<()> {
        match fs::remove_dir(&self.dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_synthetic_cgroup_parent(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ptree-cgv2-unit-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("cgroup.procs"), b"").unwrap();
        dir
    }

    #[test]
    fn parses_unified_and_hybrid_proc_self_cgroup() {
        assert_eq!(
            parse_proc_self_cgroup_v2_path("0::/user.slice/user-1000.slice/session-1.scope\n"),
            Some("user.slice/user-1000.slice/session-1.scope".to_string())
        );
        assert_eq!(
            parse_proc_self_cgroup_v2_path(
                "12:pids:/kubepods\n11:memory:/kubepods\n0::/system.slice/runner.service\n"
            ),
            Some("system.slice/runner.service".to_string())
        );
        assert_eq!(parse_proc_self_cgroup_v2_path("0::/\n"), Some(String::new()));
        assert_eq!(
            parse_proc_self_cgroup_v2_path("1:name=systemd:/init.scope\n"),
            None
        );
    }

    #[test]
    fn parses_cgroup_procs_pids() {
        assert_eq!(parse_cgroup_procs(""), Vec::<u32>::new());
        assert_eq!(parse_cgroup_procs("101\n202\n  303 \n"), vec![101, 202, 303]);
    }

    #[test]
    fn synthetic_cgroup_v2_prefers_atomic_cgroup_kill_and_cleans_up() {
        let parent = unique_synthetic_cgroup_parent("atomic-kill");
        assert!(verify_writable_cgroup_parent(&parent));

        let scope = CgroupV2Scope::create_under(&parent, "leaf-atomic").unwrap();
        fs::write(scope.path().join("cgroup.procs"), b"").unwrap();
        fs::write(scope.path().join("cgroup.kill"), b"0\n").unwrap();

        let method = scope.kill_atomic().unwrap();
        assert_eq!(method, CgroupKillMethod::AtomicCgroupKill);
        assert_eq!(
            fs::read_to_string(scope.path().join("cgroup.kill")).unwrap(),
            "1\n"
        );

        // Remove synthetic control files so remove_dir succeeds cleanly.
        let _ = fs::remove_file(scope.path().join("cgroup.procs"));
        let _ = fs::remove_file(scope.path().join("cgroup.kill"));
        scope.cleanup().unwrap();
        assert!(!scope.path().exists());
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn synthetic_cgroup_v2_falls_back_to_freeze_and_procs_drain_without_cgroup_kill() {
        let parent = unique_synthetic_cgroup_parent("freeze-drain");
        let scope = CgroupV2Scope::create_under(&parent, "leaf-drain").unwrap();
        fs::write(scope.path().join("cgroup.procs"), b"").unwrap();
        fs::write(scope.path().join("cgroup.freeze"), b"0\n").unwrap();

        let method = scope.kill_atomic().unwrap();
        assert_eq!(method, CgroupKillMethod::FrozenProcsDrain { killed_pids: 0 });
        assert_eq!(
            fs::read_to_string(scope.path().join("cgroup.freeze")).unwrap(),
            "0\n"
        );

        let _ = fs::remove_dir_all(&parent);
    }
}

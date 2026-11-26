// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Cross-platform process-tree containment & bounded graceful escalation guard (10.154).
//!
//! Addresses the real `GatewayGuard::drop` incident where `POST /shutdown` was followed
//! immediately by single-PID `SIGKILL`, stranding grandchildren as orphans:
//! 1. Isolates every spawned supervisor in its own process group (`setpgid(0, 0)`).
//! 2. Attaches a kernel-closed anonymous Pipe-EOF fate-sharing channel (`PTREE_WATCHDOG_FD`)
//!    so even an out-of-band `SIGKILL (9)` to the supervisor or guardian terminates descendants.
//! 3. Enforces bounded graceful escalation (`SIGTERM` -> bounded `grace_period` -> `kill(-pgid, SIGKILL)` -> `waitpid` reap)
//!    both in explicit `shutdown_graceful(self)` and in `Drop::drop` during panic unwinding.
//! 4. Prevents post-reap PID-reuse signaling via explicit `reaped` state tracking.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

pub const WATCHDOG_FD_ENV: &str = "PTREE_WATCHDOG_FD";

const SIGTERM: i32 = 15;
const SIGKILL: i32 = 9;
const F_SETFD: i32 = 2;
const FD_CLOEXEC: i32 = 1;

#[cfg(target_os = "macos")]
const ESRCH: i32 = 3;
#[cfg(target_os = "linux")]
const ESRCH: i32 = 3;

unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn close(fd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn _exit(status: i32) -> !;
}

/// Report returned by explicit graceful shutdown or bounded escalation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    pub pid: u32,
    pub pgid: i32,
    pub escalated_to_pgid_sigkill: bool,
    pub status: Option<ExitStatus>,
}

/// Outcome of cooperative HTTP `POST /shutdown` followed by bounded grace wait
/// and atomic process-group escalation (addresses the `asp_http_e2e` /
/// `forwarding_gateway` `GatewayGuard::drop` premature `SIGKILL` incident).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpShutdownOutcome {
    pub http_status_code: Option<u16>,
    pub report: ShutdownReport,
}

/// Owned supervisor handle enforcing process-group containment, Pipe-EOF fate-sharing,
/// bounded grace escalation, and single-reap PID-reuse protection.
pub struct ProcessTreeGuard {
    child: Child,
    pgid: i32,
    grace_period: Duration,
    /// Write end of the fate-sharing pipe. Closed when the guard finishes or crashes;
    /// kernel closure delivers immediate EOF to all descendants holding the read end.
    watchdog_write_fd: Option<i32>,
    reaped: bool,
}

impl ProcessTreeGuard {
    /// Spawn a contained supervisor process in its own process group with a Pipe-EOF watchdog.
    #[allow(clippy::disallowed_methods)]
    pub fn spawn_contained(mut cmd: Command, grace_period: Duration) -> io::Result<Self> {
        if grace_period.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "grace_period must be positive to avoid premature SIGKILL",
            ));
        }

        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a valid 2-element i32 array for POSIX `pipe`.
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let read_fd = fds[0];
        let write_fd = fds[1];

        // Keep write_fd closed in child processes so only the guardian holds it open.
        // SAFETY: `write_fd` is a valid open file descriptor.
        if unsafe { fcntl(write_fd, F_SETFD, FD_CLOEXEC) } != 0 {
            let err = io::Error::last_os_error();
            unsafe {
                close(read_fd);
                close(write_fd);
            }
            return Err(err);
        }
        // Explicitly allow read_fd to be inherited by supervisor and its descendants.
        // SAFETY: `read_fd` is a valid open file descriptor.
        if unsafe { fcntl(read_fd, F_SETFD, 0) } != 0 {
            let err = io::Error::last_os_error();
            unsafe {
                close(read_fd);
                close(write_fd);
            }
            return Err(err);
        }

        cmd.env(WATCHDOG_FD_ENV, read_fd.to_string());

        // SAFETY: `setpgid(0, 0)` is async-signal-safe per POSIX.1-2017.
        unsafe {
            cmd.pre_exec(|| {
                if setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                unsafe {
                    close(read_fd);
                    close(write_fd);
                }
                return Err(e);
            }
        };

        // Parent closes its copy of read_fd; descendants retain the inherited read_fd.
        // SAFETY: `read_fd` is owned by the parent process here.
        unsafe {
            close(read_fd);
        }

        let pgid = child.id() as i32;
        Ok(Self {
            child,
            pgid,
            grace_period,
            watchdog_write_fd: Some(write_fd),
            reaped: false,
        })
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn pgid(&self) -> i32 {
        self.pgid
    }

    /// Observe the guard's discrete phase matching `ProcessTreeReclamation.qnt`:
    /// `0` = Running, `3` = Reaped.
    pub fn guardian_phase(&self) -> i64 {
        if self.reaped { 3 } else { 0 }
    }

    /// Close the guardian's write end of the fate-sharing pipe, notifying all descendants.
    pub fn close_watchdog_pipe(&mut self) {
        if let Some(fd) = self.watchdog_write_fd.take() {
            // SAFETY: `fd` is owned exclusively by this guard and closed at most once.
            unsafe {
                close(fd);
            }
        }
    }

    /// Explicit cooperative shutdown consuming `self`, waiting up to `grace_period`,
    /// escalating to `kill(-pgid, SIGKILL)` only on expiry, and reaping via `wait()`.
    pub fn shutdown_graceful(mut self) -> io::Result<ShutdownReport> {
        self.teardown_bounded()
    }

    /// Cooperative HTTP `POST <path>` shutdown followed by bounded `grace_period` wait,
    /// NEVER issuing immediate `SIGKILL` upon HTTP 200 OK (`PT-R02`), and escalating to
    /// atomic `kill(-pgid, SIGKILL)` + Pipe-EOF closure only if the gateway hangs past grace.
    pub fn shutdown_http_then_graceful(
        mut self,
        addr: SocketAddr,
        path: &str,
        http_timeout: Duration,
    ) -> io::Result<HttpShutdownOutcome> {
        let pid = self.child.id();
        let pgid = self.pgid;
        if self.reaped {
            return Ok(HttpShutdownOutcome {
                http_status_code: None,
                report: ShutdownReport {
                    pid,
                    pgid,
                    escalated_to_pgid_sigkill: false,
                    status: None,
                },
            });
        }

        // If supervisor already died before HTTP shutdown, reap and close process group cleanly.
        if let Some(status) = self.child.try_wait()? {
            self.close_watchdog_pipe();
            unsafe {
                kill(-pgid, SIGKILL);
            }
            self.reaped = true;
            return Ok(HttpShutdownOutcome {
                http_status_code: None,
                report: ShutdownReport {
                    pid,
                    pgid,
                    escalated_to_pgid_sigkill: false,
                    status: Some(status),
                },
            });
        }

        // Phase 1: Best-effort bounded HTTP POST /shutdown (connection errors never panic).
        let http_status_code = send_http_post_shutdown(addr, path, http_timeout);

        // If HTTP request failed (e.g., gateway not listening / crashed), fall back to SIGTERM.
        if http_status_code.is_none() && self.child.try_wait()?.is_none() {
            unsafe {
                kill(pid as i32, SIGTERM);
            }
        }

        // Phase 2 & 3: Wait bounded grace period for cooperative child drain; escalate ONLY on expiry.
        let report = self.wait_grace_or_escalate(pid, pgid)?;
        Ok(HttpShutdownOutcome {
            http_status_code,
            report,
        })
    }

    fn wait_grace_or_escalate(&mut self, pid: u32, pgid: i32) -> io::Result<ShutdownReport> {
        let deadline = Instant::now() + self.grace_period;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                self.close_watchdog_pipe();
                self.reaped = true;
                return Ok(ShutdownReport {
                    pid,
                    pgid,
                    escalated_to_pgid_sigkill: false,
                    status: Some(status),
                });
            }
            thread::sleep(Duration::from_millis(15));
        }

        // Grace period expired -> atomic process-group SIGKILL + close Pipe-EOF + reap.
        self.close_watchdog_pipe();
        // SAFETY: `pgid` is the isolated process group owned by this guard.
        unsafe {
            kill(-pgid, SIGKILL);
        }
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(ShutdownReport {
            pid,
            pgid,
            escalated_to_pgid_sigkill: true,
            status: Some(status),
        })
    }

    fn teardown_bounded(&mut self) -> io::Result<ShutdownReport> {
        let pid = self.child.id();
        let pgid = self.pgid;
        if self.reaped {
            return Ok(ShutdownReport {
                pid,
                pgid,
                escalated_to_pgid_sigkill: false,
                status: None,
            });
        }

        // Check if supervisor already exited before sending any signal (prevents PID-reuse kill).
        if let Some(status) = self.child.try_wait()? {
            self.close_watchdog_pipe();
            // Ensure no straggler in the process group survives an unexpected supervisor crash.
            unsafe {
                kill(-pgid, SIGKILL);
            }
            self.reaped = true;
            return Ok(ShutdownReport {
                pid,
                pgid,
                escalated_to_pgid_sigkill: false,
                status: Some(status),
            });
        }

        // Phase 1: Cooperative shutdown signal to supervisor (never immediate SIGKILL).
        // SAFETY: supervisor has not been reaped yet (`try_wait` returned `None`).
        unsafe {
            kill(pid as i32, SIGTERM);
        }

        // Phase 2 & 3: Wait bounded grace period, escalating to kill(-pgid, SIGKILL) only on expiry.
        self.wait_grace_or_escalate(pid, pgid)
    }
}

fn send_http_post_shutdown(addr: SocketAddr, path: &str, timeout: Duration) -> Option<u16> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).ok()?;
    let _ = stream.flush();
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    let head = std::str::from_utf8(&buf[..n]).ok()?;
    let first_line = head.lines().next()?;
    let code_str = first_line.split_whitespace().nth(1)?;
    code_str.parse::<u16>().ok()
}

impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.teardown_bounded();
        }
    }
}

/// Send raw `SIGKILL` to a specific PID (intended strictly for `MR06` fault-injection tests).
pub fn inject_sigkill(pid: u32) -> io::Result<()> {
    // SAFETY: Caller supplies a live test target PID.
    if unsafe { kill(pid as i32, SIGKILL) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Check whether a process or process group (`-pgid`) is still alive via `kill(target, 0)`.
pub fn target_exists(target_pid_or_neg_pgid: i32) -> bool {
    // SAFETY: Signal 0 performs existence check only without delivering a signal.
    let rc = unsafe { kill(target_pid_or_neg_pgid, 0) };
    if rc == 0 {
        true
    } else {
        io::Error::last_os_error().raw_os_error() != Some(ESRCH)
    }
}

/// OS Leak Oracle assertion: wait until `kill(-pgid, 0)` returns `ESRCH` (zero surviving processes).
pub fn assert_pgid_reaped(pgid: i32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !target_exists(-pgid) {
            return;
        }
        thread::sleep(Duration::from_millis(15));
    }
    panic!("OS LEAK ORACLE FAILED: process group -{pgid} still has surviving processes after {timeout:?}");
}

/// Install a background Pipe-EOF watchdog thread in any managed child or grandchild.
/// When the guardian/parent dies (even via `SIGKILL`), the kernel closes the pipe write end,
/// `read()` returns `0` (EOF), and this process exits immediately with status 137.
pub fn install_pipe_eof_watchdog() {
    if let Ok(fd_str) = std::env::var(WATCHDOG_FD_ENV) {
        if let Ok(fd) = fd_str.parse::<i32>() {
            let _ = thread::Builder::new()
                .name("ptree-eof-watchdog".to_string())
                .spawn(move || {
                    let mut byte = [0u8; 1];
                    loop {
                        // SAFETY: `fd` is the inherited read end of the guardian's watchdog pipe.
                        let n = unsafe { read(fd, byte.as_mut_ptr(), 1) };
                        if n == 0 {
                            // Guardian/parent closed pipe write end (exit or SIGKILL) -> self-terminate.
                            unsafe { _exit(137) };
                        }
                        if n < 0 {
                            let err = io::Error::last_os_error();
                            if err.kind() == io::ErrorKind::Interrupted {
                                continue;
                            }
                            unsafe { _exit(137) };
                        }
                    }
                });
        }
    }
}

/// Deterministic Rust reference state machine implementing the exact lifecycle contract
/// of `ProcessTreeGuard` and refined against `ProcessTreeReclamation.qnt` via live
/// Quint `--mbt` ITF trace replay (`mbt-itf-edge`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessTreeStateMachine {
    pub guardian: i64,
    pub supervisor: i64,
    pub c1: i64,
    pub c2: i64,
    pub grace_expired: bool,
    pub container_frozen: bool,
    pub container_killed: bool,
    pub premature_kill: bool,
    pub post_reap_signal: bool,
    pub spawn_escaped: bool,
}

impl ProcessTreeStateMachine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn descendants_quiescent(&self) -> bool {
        (self.c1 == 0 || self.c1 == 3) && (self.c2 == 0 || self.c2 == 3)
    }

    pub fn safety_invariant(&self) -> bool {
        !self.premature_kill
            && !self.post_reap_signal
            && !self.spawn_escaped
            && self.c1 != 4
            && self.c2 != 4
            && (self.guardian != 3 || self.descendants_quiescent())
    }

    /// Dispatch a Quint `mbt::actionTaken` onto the Rust `ProcessTreeGuard` state contract.
    pub fn apply_action(&mut self, action: &str) -> Result<(), String> {
        match action {
            "init" => *self = Self::new(),
            "spawnC1" => {
                if self.supervisor == 0
                    && self.c1 == 0
                    && !self.container_frozen
                    && !self.container_killed
                {
                    self.c1 = 1;
                }
            }
            "spawnC2" => {
                if self.c2 == 0
                    && self.supervisor < 3
                    && !self.container_frozen
                    && !self.container_killed
                {
                    self.c2 = 1;
                    self.spawn_escaped =
                        self.spawn_escaped || self.container_frozen || self.container_killed;
                }
            }
            "sendShutdown" => {
                if self.guardian == 0 {
                    self.guardian = 1;
                }
            }
            "supervisorHttpAck" => {
                if self.guardian == 1 && self.supervisor == 0 {
                    self.supervisor = 1;
                }
            }
            "supervisorBeginDrain" => {
                if self.guardian == 1 && (self.supervisor == 0 || self.supervisor == 1) {
                    self.supervisor = 2;
                    if self.c1 == 1 {
                        self.c1 = 2;
                    }
                    if self.c2 == 1 {
                        self.c2 = 2;
                    }
                }
            }
            "childC1Exit" => {
                if self.c1 == 1 || self.c1 == 2 {
                    self.c1 = 3;
                }
            }
            "childC2Exit" => {
                if self.c2 == 1 || self.c2 == 2 {
                    self.c2 = 3;
                }
            }
            "supervisorCleanExit" => {
                if self.supervisor == 2 && self.descendants_quiescent() {
                    self.supervisor = 3;
                }
            }
            "supervisorHang" => {
                if self.guardian == 1 && self.supervisor < 3 {
                    self.supervisor = 5;
                }
            }
            "expireGraceTimer" => {
                if self.guardian == 1 && !self.grace_expired {
                    self.grace_expired = true;
                }
            }
            "freezeContainer" => {
                if self.guardian == 1
                    && (self.grace_expired || self.supervisor == 5)
                    && !self.container_frozen
                {
                    self.container_frozen = true;
                }
            }
            "escalateKill" => {
                let was_hung = self.supervisor == 5;
                if self.guardian == 1 && (self.grace_expired || was_hung) {
                    self.guardian = 2;
                    self.supervisor = 4;
                    self.container_frozen = true;
                    self.container_killed = true;
                    if self.c1 == 1 || self.c1 == 2 {
                        self.c1 = 3;
                    }
                    if self.c2 == 1 || self.c2 == 2 {
                        self.c2 = 3;
                    }
                    self.premature_kill =
                        self.premature_kill || (!self.grace_expired && !was_hung);
                }
            }
            "reapAfterShutdown" => {
                if self.guardian == 1 && self.supervisor == 3 && self.descendants_quiescent() {
                    self.guardian = 3;
                }
            }
            "reapAfterKill" => {
                if self.guardian == 2 && self.container_killed && self.descendants_quiescent() {
                    self.guardian = 3;
                }
            }
            "signalSupervisor" => {
                if (self.guardian == 1 || self.guardian == 3) && self.guardian < 3 {
                    self.post_reap_signal = self.post_reap_signal || self.guardian == 3;
                }
            }
            other => return Err(format!("unknown ProcessTreeReclamation action: {other}")),
        }
        Ok(())
    }
}

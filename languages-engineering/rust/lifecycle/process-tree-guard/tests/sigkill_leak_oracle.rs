// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Four mandatory OS Leak Oracle controls (10.154 / MR06 / PT-R01..PT-R04):
//! 1. Normal graceful shutdown drains grandchild cleanly and leaves 0 orphans.
//! 2. Panic unwinding triggers bounded Drop escalation and leaves 0 orphans.
//! 3. External SIGKILL (137) injected into supervisor terminates grandchild via Pipe-EOF fate-sharing.
//! 4. Hung supervisor + grandchild ignoring SIGTERM escalate to `kill(-pgid, SIGKILL)` with 0 orphans.

use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use process_tree_guard::{
    assert_pgid_reaped, inject_sigkill, target_exists, ProcessTreeGuard,
};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ptree-oracle-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn wait_for_pid_file(path: &Path, timeout: Duration) -> u32 {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                return pid;
            }
        }
        thread::sleep(Duration::from_millis(15));
    }
    panic!("timed out waiting for grandchild pid file {}", path.display());
}

fn mock_tree_cmd(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mock_tree"));
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

#[test]
fn control_1_normal_graceful_shutdown_drains_cleanly_zero_orphans() {
    let dir = unique_temp_dir("graceful");
    let gc_pid_file = dir.join("gc.pid");
    let drain_marker = dir.join("drained.txt");

    let guard = ProcessTreeGuard::spawn_contained(
        mock_tree_cmd(&[
            "supervisor-graceful",
            gc_pid_file.to_str().unwrap(),
            drain_marker.to_str().unwrap(),
        ]),
        Duration::from_secs(2),
    )
    .expect("spawn contained supervisor");

    let pgid = guard.pgid();
    let gc_pid = wait_for_pid_file(&gc_pid_file, Duration::from_secs(5));
    assert!(target_exists(gc_pid as i32), "grandchild must be alive before shutdown");

    let report = guard.shutdown_graceful().expect("graceful shutdown");
    assert!(!report.escalated_to_pgid_sigkill, "graceful drain must not escalate to SIGKILL");
    assert_eq!(report.status.and_then(|s| s.code()), Some(0));
    assert_eq!(fs::read_to_string(&drain_marker).unwrap(), "drained-cleanly");

    assert_pgid_reaped(pgid, Duration::from_secs(5));
    assert!(!target_exists(gc_pid as i32), "grandchild must not survive graceful shutdown");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn control_2_panic_unwinding_drop_uses_bounded_grace_zero_orphans() {
    let dir = unique_temp_dir("panic-drop");
    let gc_pid_file = dir.join("gc.pid");
    let drain_marker = dir.join("drained.txt");

    let gc_pid_holder = std::sync::Mutex::new(0u32);
    let pgid_holder = std::sync::Mutex::new(0i32);

    let unwind = std::panic::catch_unwind(|| {
        let guard = ProcessTreeGuard::spawn_contained(
            mock_tree_cmd(&[
                "supervisor-graceful",
                gc_pid_file.to_str().unwrap(),
                drain_marker.to_str().unwrap(),
            ]),
            Duration::from_secs(5),
        )
        .expect("spawn contained supervisor");

        *pgid_holder.lock().unwrap() = guard.pgid();
        let gc_pid = wait_for_pid_file(&gc_pid_file, Duration::from_secs(5));
        *gc_pid_holder.lock().unwrap() = gc_pid;
        panic!("simulated test failure triggering GatewayGuard::drop");
    });
    assert!(unwind.is_err());

    let pgid = *pgid_holder.lock().unwrap();
    let gc_pid = *gc_pid_holder.lock().unwrap();
    // Bounded Drop allowed cooperative drain to finish rather than immediately SIGKILLing!
    assert_eq!(fs::read_to_string(&drain_marker).unwrap(), "drained-cleanly");
    assert_pgid_reaped(pgid, Duration::from_secs(5));
    assert!(!target_exists(gc_pid as i32), "grandchild must not leak after panic unwinding");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn control_3_external_sigkill_137_to_supervisor_terminates_grandchild_via_fate_sharing() {
    let dir = unique_temp_dir("sigkill-137");
    let gc_pid_file = dir.join("gc.pid");
    let drain_marker = dir.join("drained.txt");

    let mut guard = ProcessTreeGuard::spawn_contained(
        mock_tree_cmd(&[
            "supervisor-graceful",
            gc_pid_file.to_str().unwrap(),
            drain_marker.to_str().unwrap(),
        ]),
        Duration::from_secs(5),
    )
    .expect("spawn contained supervisor");

    let sup_pid = guard.pid();
    let pgid = guard.pgid();
    let gc_pid = wait_for_pid_file(&gc_pid_file, Duration::from_secs(5));
    assert!(target_exists(gc_pid as i32));

    // Inject uncatchable SIGKILL (9) directly to supervisor PID (reproduces GatewayGuard bug).
    inject_sigkill(sup_pid).expect("inject SIGKILL to supervisor");

    // Guardian closes its watchdog pipe (simulating guardian teardown/crash) and reaps.
    guard.close_watchdog_pipe();
    let report = guard.shutdown_graceful().expect("reap after external SIGKILL");
    assert_eq!(report.status.and_then(|s| s.signal()), Some(9), "supervisor exited via SIGKILL (9)");
    assert!(!drain_marker.exists(), "SIGKILL bypasses userspace drain handler");

    // Kernel Pipe-EOF fate-sharing + process-group containment guarantees zero orphaned grandchildren.
    assert_pgid_reaped(pgid, Duration::from_secs(5));
    assert!(!target_exists(gc_pid as i32), "grandchild must be terminated even after supervisor SIGKILL");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn control_4_hung_supervisor_and_grandchild_ignoring_sigterm_escalated_to_pgid_sigkill() {
    let dir = unique_temp_dir("hung-escalate");
    let gc_pid_file = dir.join("gc.pid");

    let guard = ProcessTreeGuard::spawn_contained(
        mock_tree_cmd(&["supervisor-hung", gc_pid_file.to_str().unwrap()]),
        Duration::from_millis(250),
    )
    .expect("spawn hung supervisor");

    let pgid = guard.pgid();
    let gc_pid = wait_for_pid_file(&gc_pid_file, Duration::from_secs(5));
    assert!(target_exists(gc_pid as i32));

    let started = Instant::now();
    let report = guard.shutdown_graceful().expect("escalated shutdown");
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "must wait bounded grace period before escalating to SIGKILL"
    );
    assert!(report.escalated_to_pgid_sigkill, "hung tree must escalate to kill(-pgid, SIGKILL)");
    assert_eq!(report.status.and_then(|s| s.signal()), Some(9));

    assert_pgid_reaped(pgid, Duration::from_secs(5));
    assert!(!target_exists(gc_pid as i32), "hung grandchild ignoring SIGTERM must be killed");
    let _ = fs::remove_dir_all(&dir);
}

// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Real HTTP `POST /shutdown` cooperative drain & escalation E2E tests (10.154).
//! Directly reproduces and resolves the originating `asp_http_e2e` / `forwarding_gateway`
//! `GatewayGuard::drop` incident:
//! 1. `POST /shutdown` returns 200 OK -> bounded grace wait allows gateway to drain grandchild cleanly.
//! 2. Gateway ACKs 200 OK then hangs (`http-ack-not-quiescence`) -> grace expiry escalates to `kill(-pgid, SIGKILL)`.
//! 3. External `SIGKILL (9)` kills gateway before HTTP call -> Pipe-EOF & `-pgid` containment reaps grandchild.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    let dir = std::env::temp_dir().join(format!(
        "ptree-http-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn wait_for_u32_file(path: &Path, timeout: Duration) -> u32 {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(val) = content.trim().parse::<u32>() {
                return val;
            }
        }
        thread::sleep(Duration::from_millis(15));
    }
    panic!("timed out waiting for {}", path.display());
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
fn http_1_post_shutdown_allows_gateway_to_drain_grandchild_cleanly() {
    let dir = unique_temp_dir("graceful");
    let port_file = dir.join("port.txt");
    let gc_pid_file = dir.join("gc.pid");
    let drain_marker = dir.join("drained.txt");

    let guard = ProcessTreeGuard::spawn_contained(
        mock_tree_cmd(&[
            "gateway-http-graceful",
            port_file.to_str().unwrap(),
            gc_pid_file.to_str().unwrap(),
            drain_marker.to_str().unwrap(),
        ]),
        Duration::from_secs(5),
    )
    .expect("spawn http gateway");

    let pgid = guard.pgid();
    let port = wait_for_u32_file(&port_file, Duration::from_secs(5)) as u16;
    let gc_pid = wait_for_u32_file(&gc_pid_file, Duration::from_secs(5));
    assert!(target_exists(gc_pid as i32));

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let outcome = guard
        .shutdown_http_then_graceful(addr, "/shutdown", Duration::from_secs(2))
        .expect("http graceful shutdown");

    assert_eq!(outcome.http_status_code, Some(200));
    assert!(
        !outcome.report.escalated_to_pgid_sigkill,
        "must not prematurely SIGKILL after HTTP 200 OK"
    );
    assert_eq!(outcome.report.status.and_then(|s| s.code()), Some(0));
    assert_eq!(
        fs::read_to_string(&drain_marker).unwrap(),
        "http-drained-cleanly"
    );
    assert_pgid_reaped(pgid, Duration::from_secs(5));
    assert!(!target_exists(gc_pid as i32));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn http_2_gateway_acks_200_then_hangs_escalates_after_grace_zero_orphans() {
    let dir = unique_temp_dir("ack-hang");
    let port_file = dir.join("port.txt");
    let gc_pid_file = dir.join("gc.pid");

    let guard = ProcessTreeGuard::spawn_contained(
        mock_tree_cmd(&[
            "gateway-http-ack-then-hang",
            port_file.to_str().unwrap(),
            gc_pid_file.to_str().unwrap(),
        ]),
        Duration::from_millis(250),
    )
    .expect("spawn hung http gateway");

    let pgid = guard.pgid();
    let port = wait_for_u32_file(&port_file, Duration::from_secs(5)) as u16;
    let gc_pid = wait_for_u32_file(&gc_pid_file, Duration::from_secs(5));
    assert!(target_exists(gc_pid as i32));

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let started = Instant::now();
    let outcome = guard
        .shutdown_http_then_graceful(addr, "/shutdown", Duration::from_secs(2))
        .expect("http escalated shutdown");

    assert_eq!(outcome.http_status_code, Some(200));
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "must wait grace window after HTTP 200 OK before escalating"
    );
    assert!(outcome.report.escalated_to_pgid_sigkill);
    assert_eq!(outcome.report.status.and_then(|s| s.signal()), Some(9));
    assert_pgid_reaped(pgid, Duration::from_secs(5));
    assert!(!target_exists(gc_pid as i32));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn http_3_gateway_sigkill_before_http_shutdown_reaps_grandchild() {
    let dir = unique_temp_dir("pre-crash");
    let port_file = dir.join("port.txt");
    let gc_pid_file = dir.join("gc.pid");
    let drain_marker = dir.join("drained.txt");

    let mut guard = ProcessTreeGuard::spawn_contained(
        mock_tree_cmd(&[
            "gateway-http-graceful",
            port_file.to_str().unwrap(),
            gc_pid_file.to_str().unwrap(),
            drain_marker.to_str().unwrap(),
        ]),
        Duration::from_secs(5),
    )
    .expect("spawn http gateway");

    let sup_pid = guard.pid();
    let pgid = guard.pgid();
    let port = wait_for_u32_file(&port_file, Duration::from_secs(5)) as u16;
    let gc_pid = wait_for_u32_file(&gc_pid_file, Duration::from_secs(5));
    assert!(target_exists(gc_pid as i32));

    // Kill gateway externally BEFORE HTTP shutdown is sent.
    inject_sigkill(sup_pid).expect("inject SIGKILL");
    guard.close_watchdog_pipe();
    // Wait briefly so the kernel finishes marking supervisor exited before shutdown_http_then_graceful.
    thread::sleep(Duration::from_millis(50));

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let outcome = guard
        .shutdown_http_then_graceful(addr, "/shutdown", Duration::from_millis(300))
        .expect("reap after pre-shutdown SIGKILL");

    assert_eq!(outcome.http_status_code, None);
    assert_eq!(outcome.report.status.and_then(|s| s.signal()), Some(9));
    assert!(!drain_marker.exists());
    assert_pgid_reaped(pgid, Duration::from_secs(5));
    assert!(!target_exists(gc_pid as i32));
    let _ = fs::remove_dir_all(&dir);
}

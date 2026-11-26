// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Real 3-tier OS test process binary (`supervisor` -> `grandchild`) used by
//! `sigkill_leak_oracle.rs` to exercise graceful drain, panic drop, external SIGKILL (137),
//! and hung-child escalation controls.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const SIGTERM: i32 = 15;
const SIG_IGN: usize = 1;

static TERM_RECEIVED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
    fn kill(pid: i32, sig: i32) -> i32;
    fn setsid() -> i32;
    fn close(fd: i32) -> i32;
}

extern "C" fn handle_sigterm(_sig: i32) {
    TERM_RECEIVED.store(true, Ordering::SeqCst);
}

#[allow(clippy::disallowed_methods)]
fn spawn_grandchild(mode: &str, grandchild_pid_file: &str) -> std::process::Child {
    let exe = env::current_exe().expect("current_exe");
    Command::new(exe)
        .arg(mode)
        .arg(grandchild_pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn grandchild")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");

    match mode {
        "supervisor-graceful" => {
            let grandchild_pid_file = &args[2];
            let drain_marker_file = &args[3];
            // Install SIGTERM handler so graceful drain runs cleanly.
            unsafe {
                signal(SIGTERM, handle_sigterm as *const () as usize);
            }
            let mut child = spawn_grandchild("grandchild-normal", grandchild_pid_file);
            while !TERM_RECEIVED.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(10));
            }
            // Cooperative drain: forward SIGTERM to grandchild and wait for clean exit.
            unsafe {
                kill(child.id() as i32, SIGTERM);
            }
            let _ = child.wait();
            fs::write(drain_marker_file, "drained-cleanly").expect("write drain marker");
        }
        "supervisor-hung" => {
            let grandchild_pid_file = &args[2];
            // Deliberately ignore SIGTERM in both supervisor and grandchild.
            unsafe {
                signal(SIGTERM, SIG_IGN);
            }
            let mut child = spawn_grandchild("grandchild-ignore-sigterm", grandchild_pid_file);
            let _ = child.wait();
        }
        "grandchild-normal" => {
            let pid_file = &args[2];
            process_tree_guard::install_pipe_eof_watchdog();
            unsafe {
                signal(SIGTERM, handle_sigterm as *const () as usize);
            }
            fs::write(pid_file, std::process::id().to_string()).expect("write grandchild pid");
            while !TERM_RECEIVED.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(10));
            }
        }
        "grandchild-ignore-sigterm" => {
            let pid_file = &args[2];
            process_tree_guard::install_pipe_eof_watchdog();
            unsafe {
                signal(SIGTERM, SIG_IGN);
            }
            fs::write(pid_file, std::process::id().to_string()).expect("write grandchild pid");
            loop {
                thread::sleep(Duration::from_millis(50));
            }
        }
        "gateway-http-graceful" => {
            let port_file = &args[2];
            let grandchild_pid_file = &args[3];
            let drain_marker_file = &args[4];
            let mut child = spawn_grandchild("grandchild-normal", grandchild_pid_file);
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind http gateway");
            let port = listener.local_addr().expect("local_addr").port();
            fs::write(port_file, port.to_string()).expect("write port file");
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = stream.flush();
            }
            // Simulate realistic post-ACK cooperative child drain time (80ms) before reaping grandchild.
            thread::sleep(Duration::from_millis(80));
            unsafe {
                kill(child.id() as i32, SIGTERM);
            }
            let _ = child.wait();
            fs::write(drain_marker_file, "http-drained-cleanly").expect("write drain marker");
        }
        "gateway-http-ack-then-hang" => {
            let port_file = &args[2];
            let grandchild_pid_file = &args[3];
            unsafe {
                signal(SIGTERM, SIG_IGN);
            }
            let mut child = spawn_grandchild("grandchild-ignore-sigterm", grandchild_pid_file);
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind hung http gateway");
            let port = listener.local_addr().expect("local_addr").port();
            fs::write(port_file, port.to_string()).expect("write port file");
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = stream.flush();
            }
            // Reproduces `http-ack-not-quiescence`: ACKed 200 OK then hangs without draining!
            let _ = child.wait();
        }
        "supervisor-setsid-with-watchdog" => {
            let grandchild_pid_file = &args[2];
            unsafe {
                signal(SIGTERM, SIG_IGN);
            }
            let mut child = spawn_grandchild("grandchild-setsid-with-watchdog", grandchild_pid_file);
            let _ = child.wait();
        }
        "grandchild-setsid-with-watchdog" => {
            let pid_file = &args[2];
            // Escape the supervisor's process group via setsid(), AND ignore SIGTERM,
            // while retaining the kernel-inherited Pipe-EOF watchdog FD.
            unsafe {
                setsid();
                signal(SIGTERM, SIG_IGN);
            }
            process_tree_guard::install_pipe_eof_watchdog();
            fs::write(pid_file, std::process::id().to_string()).expect("write escaped pid");
            loop {
                thread::sleep(Duration::from_millis(50));
            }
        }
        "supervisor-setsid-rogue-no-watchdog" => {
            let grandchild_pid_file = &args[2];
            unsafe {
                signal(SIGTERM, SIG_IGN);
            }
            let mut child =
                spawn_grandchild("grandchild-setsid-rogue-no-watchdog", grandchild_pid_file);
            let _ = child.wait();
        }
        "grandchild-setsid-rogue-no-watchdog" => {
            let pid_file = &args[2];
            // Adversarial untrusted binary: escapes PGID via setsid(), ignores SIGTERM,
            // AND deliberately closes PTREE_WATCHDOG_FD without installing watchdog.
            // Demonstrates why Darwin userspace containment cannot stop untrusted setsid()
            // without kernel cgroup v2 (`SpawnPreservesContainer` boundary falsification).
            unsafe {
                setsid();
                signal(SIGTERM, SIG_IGN);
            }
            if let Ok(fd_str) = env::var(process_tree_guard::WATCHDOG_FD_ENV) {
                if let Ok(fd) = fd_str.parse::<i32>() {
                    unsafe {
                        close(fd);
                    }
                }
            }
            fs::write(pid_file, std::process::id().to_string()).expect("write rogue escaped pid");
            loop {
                thread::sleep(Duration::from_millis(50));
            }
        }
        "supervisor-mbt-driver" => {
            // Interactive OS-level MBT supervisor driven step-by-step by live Quint ITF actions.
            let port_file = &args[2];
            let work_dir = &args[3];
            process_tree_guard::install_pipe_eof_watchdog();
            unsafe {
                signal(SIGTERM, handle_sigterm as *const () as usize);
            }
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mbt driver");
            let port = listener.local_addr().expect("local_addr").port();
            fs::write(port_file, port.to_string()).expect("write mbt port file");
            let mut children: HashMap<String, Child> = HashMap::new();
            let mut hung = false;

            if let Ok((stream, _)) = listener.accept() {
                let mut writer = stream.try_clone().expect("clone mbt stream");
                let reader = BufReader::new(stream);
                for line_res in reader.lines() {
                    let Ok(line) = line_res else { break };
                    let cmd = line.trim();
                    if let Some(name) = cmd.strip_prefix("SPAWN ") {
                        let pid_file = format!("{work_dir}/{name}.pid");
                        let child = spawn_grandchild("grandchild-normal", &pid_file);
                        let pid = child.id();
                        children.insert(name.to_string(), child);
                        let _ = writeln!(writer, "PID {pid}");
                        let _ = writer.flush();
                    } else if cmd == "HTTP_ACK" {
                        let _ = writeln!(writer, "ACK 200");
                        let _ = writer.flush();
                    } else if cmd == "BEGIN_DRAIN" {
                        for child in children.values() {
                            unsafe {
                                kill(child.id() as i32, SIGTERM);
                            }
                        }
                        let _ = writeln!(writer, "DRAINING");
                        let _ = writer.flush();
                    } else if let Some(name) = cmd.strip_prefix("EXIT_CHILD ") {
                        if let Some(mut child) = children.remove(name) {
                            unsafe {
                                kill(child.id() as i32, SIGTERM);
                            }
                            let _ = child.wait();
                        }
                        let _ = writeln!(writer, "EXITED {name}");
                        let _ = writer.flush();
                    } else if cmd == "HANG" {
                        hung = true;
                        unsafe {
                            signal(SIGTERM, SIG_IGN);
                        }
                        let _ = writeln!(writer, "HUNG");
                        let _ = writer.flush();
                    } else if cmd == "CLEAN_EXIT" {
                        for (_, mut child) in children.drain() {
                            unsafe {
                                kill(child.id() as i32, SIGTERM);
                            }
                            let _ = child.wait();
                        }
                        let _ = writeln!(writer, "BYE");
                        let _ = writer.flush();
                        return;
                    }
                }
            }
            if hung {
                loop {
                    thread::sleep(Duration::from_millis(50));
                }
            }
            for (_, mut child) in children.drain() {
                unsafe {
                    kill(child.id() as i32, SIGTERM);
                }
                let _ = child.wait();
            }
        }
        other => panic!("unknown mock_tree mode: {other}"),
    }
}

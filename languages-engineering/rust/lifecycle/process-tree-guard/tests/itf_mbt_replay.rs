// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Live Quint `--mbt` ITF Trace -> Rust MBT Replay Harness (`mbt-itf-edge`, 10.154).
//!
//! 1. Consumes live `*.itf.json` traces emitted by `quintTarget` via `PTREE_ITF_TRACE_DIR`
//!    (or generates fresh deterministic traces via `quint run --mbt` when run standalone).
//! 2. Parses every ITF state zero-dependency and asserts step-by-step 10-field state
//!    isomorphism + `safety_invariant()` on `ProcessTreeStateMachine`.
//! 3. Grounds terminal Quint trace scenarios (`reapAfterShutdown`, `reapAfterKill`)
//!    directly onto real OS `ProcessTreeGuard` + `mock_tree` subprocess trees (0 orphans).
//! 4. Negative control: replays the exact same formal traces against a defective
//!    single-PID `GatewayGuard::drop` model and asserts immediate divergence & safety failure.

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use process_tree_guard::{
    assert_pgid_reaped, process_pgid, target_exists, ProcessTreeGuard, ProcessTreeStateMachine,
};

#[derive(Debug, Clone)]
struct ItfStep {
    index: usize,
    action: String,
    state: ProcessTreeStateMachine,
}

/// Minimal zero-dependency parser for Quint `--mbt` ITF JSON trace files.
fn parse_itf_trace(json: &str) -> Result<Vec<ItfStep>, String> {
    let states_marker = "\"states\":[";
    let start = json
        .find(states_marker)
        .ok_or_else(|| "missing \"states\" array in ITF JSON".to_string())?
        + states_marker.len();
    let bytes = json.as_bytes();
    let mut i = start;
    let mut steps = Vec::new();

    while i < bytes.len() {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\n' | b'\r' | b'\t' | b',') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b']' {
            break;
        }
        if bytes[i] != b'{' {
            return Err(format!("expected '{{' at byte {i} in ITF states array"));
        }
        let obj_start = i;
        let obj_end = find_matching_brace(bytes, obj_start)?;
        let obj = &json[obj_start..=obj_end];
        let action = extract_string_field(obj, "\"mbt::actionTaken\"")?;
        let h_obj = extract_object_field(obj, "\"h\"")?;
        let state = ProcessTreeStateMachine {
            guardian: extract_itf_int(h_obj, "\"guardian\"")?,
            supervisor: extract_itf_int(h_obj, "\"supervisor\"")?,
            c1: extract_itf_int(h_obj, "\"c1\"")?,
            c2: extract_itf_int(h_obj, "\"c2\"")?,
            grace_expired: extract_bool_field(h_obj, "\"graceExpired\"")?,
            container_frozen: extract_bool_field(h_obj, "\"containerFrozen\"")?,
            container_killed: extract_bool_field(h_obj, "\"containerKilled\"")?,
            premature_kill: extract_bool_field(h_obj, "\"prematureKill\"")?,
            post_reap_signal: extract_bool_field(h_obj, "\"postReapSignal\"")?,
            spawn_escaped: extract_bool_field(h_obj, "\"spawnEscaped\"")?,
        };
        steps.push(ItfStep {
            index: steps.len(),
            action,
            state,
        });
        i = obj_end + 1;
    }

    if steps.is_empty() {
        return Err("ITF trace contained zero states".to_string());
    }
    Ok(steps)
}

fn find_matching_brace(bytes: &[u8], open_idx: usize) -> Result<usize, String> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, &b) in bytes.iter().enumerate().skip(open_idx) {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(idx);
                }
            }
            _ => {}
        }
    }
    Err(format!("unclosed '{{' starting at byte {open_idx}"))
}

fn extract_object_field<'a>(obj: &'a str, key: &str) -> Result<&'a str, String> {
    let pos = obj
        .find(key)
        .ok_or_else(|| format!("missing object field {key}"))?
        + key.len();
    let rest = &obj[pos..];
    let brace_rel = rest
        .find('{')
        .ok_or_else(|| format!("expected '{{' for field {key}"))?;
    let abs_open = pos + brace_rel;
    let abs_close = find_matching_brace(obj.as_bytes(), abs_open)?;
    Ok(&obj[abs_open..=abs_close])
}

fn extract_string_field(obj: &str, key: &str) -> Result<String, String> {
    let pos = obj
        .find(key)
        .ok_or_else(|| format!("missing string field {key}"))?
        + key.len();
    let rest = &obj[pos..];
    let colon = rest
        .find(':')
        .ok_or_else(|| format!("missing ':' for field {key}"))?;
    let after_colon = rest[colon + 1..].trim_start();
    let inner = after_colon
        .strip_prefix('"')
        .ok_or_else(|| format!("expected '\"' for field {key}"))?;
    let end = inner
        .find('"')
        .ok_or_else(|| format!("unterminated string for field {key}"))?;
    Ok(inner[..end].to_string())
}

fn extract_bool_field(obj: &str, key: &str) -> Result<bool, String> {
    let pos = obj
        .find(key)
        .ok_or_else(|| format!("missing bool field {key}"))?
        + key.len();
    let rest = &obj[pos..];
    let colon = rest
        .find(':')
        .ok_or_else(|| format!("missing ':' for field {key}"))?;
    let after_colon = rest[colon + 1..].trim_start();
    if after_colon.starts_with("true") {
        Ok(true)
    } else if after_colon.starts_with("false") {
        Ok(false)
    } else {
        Err(format!("invalid bool value for {key}: {after_colon}"))
    }
}

fn extract_itf_int(obj: &str, key: &str) -> Result<i64, String> {
    let pos = obj
        .find(key)
        .ok_or_else(|| format!("missing int field {key}"))?
        + key.len();
    let rest = &obj[pos..];
    let colon = rest
        .find(':')
        .ok_or_else(|| format!("missing ':' for field {key}"))?;
    let after_colon = rest[colon + 1..].trim_start();
    if after_colon.starts_with('{') {
        let abs_open = pos + colon + 1 + (rest[colon + 1..].len() - after_colon.len());
        let abs_close = find_matching_brace(obj.as_bytes(), abs_open)?;
        let bigint_obj = &obj[abs_open..=abs_close];
        let digits = extract_string_field(bigint_obj, "\"#bigint\"")?;
        digits
            .parse::<i64>()
            .map_err(|e| format!("invalid #bigint for {key}: {e}"))
    } else {
        let num_str: String = after_colon
            .chars()
            .take_while(|c| *c == '-' || c.is_ascii_digit())
            .collect();
        num_str
            .parse::<i64>()
            .map_err(|e| format!("invalid int for {key}: {e}"))
    }
}

fn load_or_generate_itf_traces() -> (Vec<(PathBuf, Vec<ItfStep>)>, Option<PathBuf>) {
    let (dir, cleanup_dir) = if let Ok(env_dir) = std::env::var("PTREE_ITF_TRACE_DIR") {
        let p = PathBuf::from(env_dir);
        assert!(
            p.is_dir(),
            "PTREE_ITF_TRACE_DIR={} does not exist or is not a directory",
            p.display()
        );
        (p, None)
    } else {
        // Standalone cargo test mode: generate fresh deterministic Quint MBT ITF traces.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!(
            "ptree-itf-standalone-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&tmp).expect("create standalone ITF temp dir");
        let qnt = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../packages/quint-models/engineering/concurrency/process-tree-reclamation/ProcessTreeReclamation.qnt");
        let out_pattern = tmp.join("trace_{seq}.itf.json");
        let output = Command::new("quint")
            .args([
                "run",
                qnt.to_str().unwrap(),
                "--main",
                "concurrency_process_tree_reclamation",
                "--mbt",
                "--max-samples",
                "60",
                "--n-traces",
                "20",
                "--max-steps",
                "24",
                "--invariant",
                "safety",
                "--seed",
                "0x154",
                "--out-itf",
                out_pattern.to_str().unwrap(),
            ])
            .output()
            .expect("invoke quint run --mbt for standalone ITF trace generation");
        assert!(
            output.status.success(),
            "quint run --mbt failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        (tmp.clone(), Some(tmp))
    };

    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("read ITF trace dir")
        .filter_map(|e| e.ok().map(|ent| ent.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".itf.json"))
        })
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no *.itf.json files found in {}",
        dir.display()
    );

    let traces = files
        .into_iter()
        .map(|p| {
            let text = fs::read_to_string(&p).expect("read ITF trace file");
            let parsed = parse_itf_trace(&text)
                .unwrap_or_else(|e| panic!("failed to parse {}: {e}", p.display()));
            (p, parsed)
        })
        .collect();
    (traces, cleanup_dir)
}

fn wait_for_pid_file(path: &Path, timeout: Duration) -> u32 {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                return pid;
            }
        }
        std::thread::sleep(Duration::from_millis(15));
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

/// Negative-control defective SUT reproducing the original `GatewayGuard::drop` incident:
/// immediately single-PID SIGKILLs without container containment, leaving live grandchildren
/// orphaned (`c1 = 4` / `c2 = 4`) or triggering premature kill.
struct BrokenSinglePidGatewayGuard {
    state: ProcessTreeStateMachine,
}

impl BrokenSinglePidGatewayGuard {
    fn new() -> Self {
        Self {
            state: ProcessTreeStateMachine::new(),
        }
    }

    fn apply_action(&mut self, action: &str) {
        if action == "escalateKill" {
            // Bug 1: ignores grace barrier AND only kills supervisor PID, stranding c1/c2 as orphans (4).
            if self.state.guardian == 1 {
                self.state.guardian = 2;
                self.state.supervisor = 4;
                self.state.container_frozen = true;
                self.state.container_killed = false;
                if self.state.c1 == 1 || self.state.c1 == 2 {
                    self.state.c1 = 4;
                }
                if self.state.c2 == 1 || self.state.c2 == 2 {
                    self.state.c2 = 4;
                }
                if !self.state.grace_expired && self.state.supervisor != 5 {
                    self.state.premature_kill = true;
                }
            }
        } else {
            self.state.apply_action(action).unwrap();
        }
    }
}

#[test]
fn mbt_1_live_quint_itf_traces_match_rust_process_tree_state_machine_step_for_step() {
    let (traces, cleanup) = load_or_generate_itf_traces();
    let mut total_transitions = 0usize;
    let mut observed_actions = BTreeSet::new();

    for (path, steps) in &traces {
        let mut sut = ProcessTreeStateMachine::new();
        for step in steps {
            sut.apply_action(&step.action).unwrap_or_else(|e| {
                panic!(
                    "action replay failed at {}[{}]: {e}",
                    path.display(),
                    step.index
                )
            });
            assert_eq!(
                sut,
                step.state,
                "ITF state divergence at {}[{}] after action '{}'",
                path.display(),
                step.index,
                step.action
            );
            assert!(
                sut.safety_invariant(),
                "safety invariant violated at {}[{}]",
                path.display(),
                step.index
            );
            observed_actions.insert(step.action.clone());
            total_transitions += 1;
        }
    }

    assert!(
        traces.len() >= 10,
        "expected >= 10 live Quint ITF traces, got {}",
        traces.len()
    );
    assert!(
        total_transitions >= 100,
        "expected >= 100 replayed ITF transitions, got {total_transitions}"
    );
    assert!(
        observed_actions.contains("init")
            && observed_actions.contains("spawnC1")
            && observed_actions.contains("sendShutdown")
            && observed_actions.contains("escalateKill"),
        "expected core lifecycle actions in replayed ITF traces, observed={observed_actions:?}"
    );

    if let Some(tmp) = cleanup {
        let _ = fs::remove_dir_all(tmp);
    }
}

#[test]
fn mbt_2_live_itf_terminal_scenarios_grounded_on_real_os_process_tree_guard() {
    let (traces, cleanup) = load_or_generate_itf_traces();

    // Verify at least one trace exercises graceful drain and one exercises escalated kill,
    // and ground both abstract Quint trace schedules onto real OS ProcessTreeGuard runs.
    let mut saw_escalate = false;
    let mut saw_shutdown = false;
    for (_, steps) in &traces {
        for s in steps {
            if s.action == "escalateKill" && s.state.container_killed {
                saw_escalate = true;
            }
            if s.action == "sendShutdown" && s.state.guardian == 1 {
                saw_shutdown = true;
            }
        }
    }
    assert!(saw_shutdown && saw_escalate, "ITF traces must exercise shutdown and escalation");

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ptree-mbt-os-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");

    // Scenario A (graceful Quint schedule): spawnC1 -> sendShutdown -> drain -> reapAfterShutdown
    let gc1_file = dir.join("gc1.pid");
    let drain_file = dir.join("drained.txt");
    let guard1 = ProcessTreeGuard::spawn_contained(
        mock_tree_cmd(&[
            "supervisor-graceful",
            gc1_file.to_str().unwrap(),
            drain_file.to_str().unwrap(),
        ]),
        Duration::from_secs(5),
    )
    .expect("spawn contained graceful tree");
    assert_eq!(guard1.guardian_phase(), 0);
    let pgid1 = guard1.pgid();
    let gc1 = wait_for_pid_file(&gc1_file, Duration::from_secs(5));
    let rep1 = guard1.shutdown_graceful().expect("graceful drain");
    assert!(!rep1.escalated_to_pgid_sigkill);
    assert_pgid_reaped(pgid1, Duration::from_secs(5));
    assert!(!target_exists(gc1 as i32));

    // Scenario B (escalated Quint schedule): spawnC1 -> sendShutdown -> supervisorHang -> expireGraceTimer -> escalateKill -> reapAfterKill
    let gc2_file = dir.join("gc2.pid");
    let guard2 = ProcessTreeGuard::spawn_contained(
        mock_tree_cmd(&["supervisor-hung", gc2_file.to_str().unwrap()]),
        Duration::from_millis(200),
    )
    .expect("spawn contained hung tree");
    assert_eq!(guard2.guardian_phase(), 0);
    let pgid2 = guard2.pgid();
    let gc2 = wait_for_pid_file(&gc2_file, Duration::from_secs(5));
    let rep2 = guard2.shutdown_graceful().expect("escalated kill");
    assert!(rep2.escalated_to_pgid_sigkill);
    assert_pgid_reaped(pgid2, Duration::from_secs(5));
    assert!(!target_exists(gc2 as i32));

    let _ = fs::remove_dir_all(&dir);
    if let Some(tmp) = cleanup {
        let _ = fs::remove_dir_all(tmp);
    }
}

#[test]
fn mbt_3_negative_control_defective_single_pid_gateway_guard_rejected_by_quint_itf() {
    let (traces, cleanup) = load_or_generate_itf_traces();

    // Replay the exact live Quint traces against BrokenSinglePidGatewayGuard AND also
    // check canonical escalation schedule: broken guard MUST diverge from Quint ITF state!
    let mut caught_divergence = false;
    for (_, steps) in &traces {
        let mut broken = BrokenSinglePidGatewayGuard::new();
        for step in steps {
            broken.apply_action(&step.action);
            if broken.state != step.state {
                caught_divergence = true;
                break;
            }
        }
    }
    // Also verify canonical GatewayGuard::drop bug trace triggers orphan c1 == 4 & safety == false.
    let mut broken_canonical = BrokenSinglePidGatewayGuard::new();
    for action in ["init", "spawnC1", "sendShutdown", "escalateKill"] {
        broken_canonical.apply_action(action);
    }
    assert_eq!(broken_canonical.state.c1, 4, "broken single-PID kill must strand c1 as orphan");
    assert!(!broken_canonical.state.safety_invariant());
    assert!(
        caught_divergence,
        "live Quint ITF traces must catch defective single-PID GatewayGuard divergence"
    );

    if let Some(tmp) = cleanup {
        let _ = fs::remove_dir_all(tmp);
    }
}

fn wait_for_port_file(path: &Path, timeout: Duration) -> u16 {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(port) = content.trim().parse::<u16>() {
                return port;
            }
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    panic!("timed out waiting for mbt driver port file {}", path.display());
}

fn send_driver_cmd(writer: &mut TcpStream, reader: &mut BufReader<TcpStream>, cmd: &str) -> String {
    writeln!(writer, "{cmd}").expect("write mbt driver cmd");
    writer.flush().expect("flush mbt driver cmd");
    let mut reply = String::new();
    reader
        .read_line(&mut reply)
        .expect("read mbt driver reply");
    reply.trim().to_string()
}

fn wait_until_pid_dead(pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !target_exists(pid as i32) {
            return;
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    panic!("expected OS process {pid} to exit within {timeout:?}");
}

/// Live OS-level online MBT driver: steps real OS `ProcessTreeGuard` + `mock_tree`
/// supervisor & grandchildren through live Quint `--mbt` ITF traces action-by-action,
/// checking kernel `getpgid` (`SpawnPreservesContainer`), non-premature kill, and zero orphans!
#[test]
fn mbt_4_online_os_process_driver_executes_live_quint_itf_actions_step_by_step() {
    let (traces, cleanup) = load_or_generate_itf_traces();

    let mut selected: Vec<&(PathBuf, Vec<ItfStep>)> = traces
        .iter()
        .filter(|(_, steps)| {
            let spawns = steps
                .iter()
                .any(|s| s.action == "spawnC1" || s.action == "spawnC2");
            let terminates = steps.iter().any(|s| {
                s.action == "escalateKill"
                    || s.action == "supervisorCleanExit"
                    || s.action == "sendShutdown"
            });
            spawns && terminates
        })
        .take(4)
        .collect();
    assert!(
        !selected.is_empty(),
        "expected at least one live Quint ITF trace with spawn + shutdown/escalation"
    );
    if !selected
        .iter()
        .any(|(_, steps)| steps.iter().any(|s| s.action == "escalateKill"))
    {
        if let Some(esc) = traces
            .iter()
            .find(|(_, steps)| steps.iter().any(|s| s.action == "escalateKill"))
        {
            selected.push(esc);
        }
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_dir = std::env::temp_dir().join(format!(
        "ptree-online-os-mbt-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&root_dir).expect("create online mbt dir");

    let mut total_os_spawns = 0usize;
    let mut total_os_teardowns = 0usize;

    for (trace_idx, (trace_path, steps)) in selected.iter().enumerate() {
        let run_dir = root_dir.join(format!("trace-{trace_idx}"));
        fs::create_dir_all(&run_dir).expect("create trace run dir");
        let port_file = run_dir.join("mbt.port");

        let mut guard_opt = Some(
            ProcessTreeGuard::spawn_contained(
                mock_tree_cmd(&[
                    "supervisor-mbt-driver",
                    port_file.to_str().unwrap(),
                    run_dir.to_str().unwrap(),
                ]),
                Duration::from_millis(180),
            )
            .expect("spawn contained online mbt driver"),
        );
        let pgid = guard_opt.as_ref().unwrap().pgid();
        let port = wait_for_port_file(&port_file, Duration::from_secs(5));
        let mut writer =
            TcpStream::connect(("127.0.0.1", port)).expect("connect to mbt driver");
        let mut reader = BufReader::new(writer.try_clone().expect("clone mbt tcp"));

        let mut prev = ProcessTreeStateMachine::new();
        let mut c1_pid: Option<u32> = None;
        let mut c2_pid: Option<u32> = None;
        let mut reaped = false;

        for step in steps {
            let next = &step.state;
            if !reaped {
                match step.action.as_str() {
                    "spawnC1" if prev.c1 == 0 && next.c1 == 1 => {
                        let reply = send_driver_cmd(&mut writer, &mut reader, "SPAWN c1");
                        let pid: u32 = reply
                            .strip_prefix("PID ")
                            .unwrap_or_else(|| panic!("unexpected SPAWN c1 reply: {reply}"))
                            .parse()
                            .expect("parse c1 pid");
                        let pid_file = run_dir.join("c1.pid");
                        let _ = wait_for_pid_file(&pid_file, Duration::from_secs(5));
                        assert!(target_exists(pid as i32), "c1 must be live after spawnC1");
                        assert_eq!(
                            process_pgid(pid).expect("getpgid(c1)"),
                            pgid,
                            "SpawnPreservesContainer violated for c1 in {}",
                            trace_path.display()
                        );
                        c1_pid = Some(pid);
                        total_os_spawns += 1;
                    }
                    "spawnC2" if prev.c2 == 0 && next.c2 == 1 => {
                        let reply = send_driver_cmd(&mut writer, &mut reader, "SPAWN c2");
                        let pid: u32 = reply
                            .strip_prefix("PID ")
                            .unwrap_or_else(|| panic!("unexpected SPAWN c2 reply: {reply}"))
                            .parse()
                            .expect("parse c2 pid");
                        let pid_file = run_dir.join("c2.pid");
                        let _ = wait_for_pid_file(&pid_file, Duration::from_secs(5));
                        assert!(target_exists(pid as i32), "c2 must be live after spawnC2");
                        assert_eq!(
                            process_pgid(pid).expect("getpgid(c2)"),
                            pgid,
                            "SpawnPreservesContainer violated for c2 in {}",
                            trace_path.display()
                        );
                        c2_pid = Some(pid);
                        total_os_spawns += 1;
                    }
                    "supervisorHttpAck" if prev.supervisor == 0 && next.supervisor == 1 => {
                        let reply = send_driver_cmd(&mut writer, &mut reader, "HTTP_ACK");
                        assert_eq!(reply, "ACK 200");
                        if let Some(pid) = c1_pid {
                            assert!(target_exists(pid as i32), "c1 prematurely killed on HTTP_ACK");
                        }
                        if let Some(pid) = c2_pid {
                            assert!(target_exists(pid as i32), "c2 prematurely killed on HTTP_ACK");
                        }
                    }
                    "supervisorBeginDrain" if prev.supervisor < 2 && next.supervisor == 2 => {
                        let reply = send_driver_cmd(&mut writer, &mut reader, "BEGIN_DRAIN");
                        assert_eq!(reply, "DRAINING");
                    }
                    "childC1Exit" if (prev.c1 == 1 || prev.c1 == 2) && next.c1 == 3 => {
                        if let Some(pid) = c1_pid.take() {
                            let reply = send_driver_cmd(&mut writer, &mut reader, "EXIT_CHILD c1");
                            assert_eq!(reply, "EXITED c1");
                            wait_until_pid_dead(pid, Duration::from_secs(5));
                        }
                    }
                    "childC2Exit" if (prev.c2 == 1 || prev.c2 == 2) && next.c2 == 3 => {
                        if let Some(pid) = c2_pid.take() {
                            let reply = send_driver_cmd(&mut writer, &mut reader, "EXIT_CHILD c2");
                            assert_eq!(reply, "EXITED c2");
                            wait_until_pid_dead(pid, Duration::from_secs(5));
                        }
                    }
                    "supervisorHang" if prev.supervisor < 3 && next.supervisor == 5 => {
                        let reply = send_driver_cmd(&mut writer, &mut reader, "HANG");
                        assert_eq!(reply, "HUNG");
                    }
                    "supervisorCleanExit" if prev.supervisor == 2 && next.supervisor == 3 => {
                        let reply = send_driver_cmd(&mut writer, &mut reader, "CLEAN_EXIT");
                        assert_eq!(reply, "BYE");
                        let guard = guard_opt.take().unwrap();
                        let rep = guard.shutdown_graceful().expect("reap after clean exit");
                        assert!(!rep.escalated_to_pgid_sigkill);
                        assert_pgid_reaped(pgid, Duration::from_secs(5));
                        reaped = true;
                        total_os_teardowns += 1;
                    }
                    "escalateKill" if prev.guardian == 1 && next.guardian == 2 => {
                        let _ = send_driver_cmd(&mut writer, &mut reader, "HANG");
                        let guard = guard_opt.take().unwrap();
                        let rep = guard.shutdown_graceful().expect("escalated pgid sigkill");
                        assert!(rep.escalated_to_pgid_sigkill);
                        assert_pgid_reaped(pgid, Duration::from_secs(5));
                        if let Some(pid) = c1_pid.take() {
                            assert!(!target_exists(pid as i32), "c1 leaked after escalateKill");
                        }
                        if let Some(pid) = c2_pid.take() {
                            assert!(!target_exists(pid as i32), "c2 leaked after escalateKill");
                        }
                        reaped = true;
                        total_os_teardowns += 1;
                    }
                    _ => {}
                }
            }
            prev = next.clone();
        }

        if let Some(guard) = guard_opt.take() {
            let _ = guard.shutdown_graceful();
            assert_pgid_reaped(pgid, Duration::from_secs(5));
            if let Some(pid) = c1_pid.take() {
                assert!(!target_exists(pid as i32));
            }
            if let Some(pid) = c2_pid.take() {
                assert!(!target_exists(pid as i32));
            }
            total_os_teardowns += 1;
        }
    }

    assert!(total_os_spawns >= 1, "online OS MBT must spawn real OS grandchildren");
    assert!(total_os_teardowns >= 1, "online OS MBT must reap real OS process trees");

    let _ = fs::remove_dir_all(&root_dir);
    if let Some(tmp) = cleanup {
        let _ = fs::remove_dir_all(tmp);
    }
}

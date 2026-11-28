// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Closed-Loop AI Agent Software Aging Governance Harness (SM1-SM6).
 *
 * Mirrors `languages-engineering/ts/defense/agent-audit/{remediation-catalog,governance-harness}.ts`
 * for long-running stability obligations:
 *   1. Maps every SM2-SM5 static aging finding to a structured C2 Remediation Directive
 *      with explicit anti-evasion prohibitions (forbidding restart band-aids, budget inflation,
 *      or silencing checks).
 *   2. Exports SARIF 2.1.0 and structured `AgingRepairPacket` JSON for AI agent loops.
 *   3. Enforces a bounded multi-attempt repair loop pairing Static Aging AST Audit
 *      with an Independent Steady-State Slope Oracle; prose claims are untrusted telemetry,
 *      never evidence, and exhausting `maxRepairAttempts` escalates deterministically to human review.
 */

import {createHash} from 'node:crypto';
import {
  auditFileForAging,
  type AgingFinding,
  type AgingMechanism,
  type FileAgingAuditReport,
} from './aging-ast-auditor.ts';
import type {SlopeOracleVerdict} from './slope-oracle.ts';

export interface AgingRemediationDirective {
  mechanism: AgingMechanism;
  studyRef: string;
  c2SteadyReplacement: string;
  antiEvasionWarning: string;
}

const MECHANISM_DIRECTIVES: Record<AgingMechanism, AgingRemediationDirective> = {
  'SM2-resource-leak': {
    mechanism: 'SM2-resource-leak',
    studyRef: 'docs/40-49-research/40-reference-studies/40.04-software-aging-and-steady-state-stability.org#six-stability-mechanisms',
    c2SteadyReplacement:
      'Bind handle/timer/body/allocation release to deterministic exit boundaries (Go defer + Body.Close/Timer.Stop, Rust Drop guard, C single goto cleanup, C++ RAII, TS try/finally + AbortSignal) and prove delta==0 at quiescence.',
    antiEvasionWarning:
      'Do NOT evade by raising ulimit/FD ceilings, adding periodic process restarts, or suppressing errors without releasing ownership.',
  },
  'SM3-watermark-ratchet': {
    mechanism: 'SM3-watermark-ratchet',
    studyRef: 'docs/40-49-research/40-reference-studies/40.04-software-aging-and-steady-state-stability.org#six-stability-mechanisms',
    c2SteadyReplacement:
      'Enforce explicit maxRetainCap and slotCap on reusable buffer pools, detach small sub-slices via bytes.Clone/copy, bound caches with LRU/TTL eviction, and rotate non-shrinking maps/unordered_maps at quiescence.',
    antiEvasionWarning:
      'Do NOT evade by raising RAM/GOMEMLIMIT ceilings or removing clear() calls while keeping unbounded retention.',
  },
  'SM4-orphan-concurrency': {
    mechanism: 'SM4-orphan-concurrency',
    studyRef: 'docs/40-49-research/40-reference-studies/40.04-software-aging-and-steady-state-stability.org#six-stability-mechanisms',
    c2SteadyReplacement:
      'Use structured concurrency with lexical join/quiescence barriers (Go errgroup.SetLimit + ctx.Done select + WaitGroup, Rust JoinSet/TaskTracker + spawn_blocking for sync I/O, C++ std::jthread) so every child exits before parent scope closes.',
    antiEvasionWarning:
      'Do NOT evade by detaching background tasks, silencing warnings, or omitting cancellation responsiveness.',
  },
  'SM5-metastable-overload': {
    mechanism: 'SM5-metastable-overload',
    studyRef: 'docs/40-49-research/40-reference-studies/40.04-software-aging-and-steady-state-stability.org#six-stability-mechanisms',
    c2SteadyReplacement:
      'Replace unbounded queues/channels/retries/fan-out with bounded admission, congestion-aware load shedding (DAGOR/Breakwater), explicit retry budgets, lag-resync snapshot recovery, and per-consumer slow-subscriber eviction.',
    antiEvasionWarning:
      'Do NOT evade by dropping failed requests from latency/error metrics (coordinated omission) or adding unbounded retry queues.',
  },
  'SM7-ui-render-aging': {
    mechanism: 'SM7-ui-render-aging',
    studyRef: 'docs/40-49-research/40-reference-studies/40.04-software-aging-and-steady-state-stability.org#ui-render-steady-state',
    c2SteadyReplacement:
      'Enforce bounded DOM viewport virtualization (mountedNodes <= windowCap), coalesce animation frames (<=1 pending rAF), and switch streaming output to O(1) incremental block rendering rather than full-transcript innerHTML re-parsing.',
    antiEvasionWarning:
      'Do NOT evade by throttling timers artificially while keeping unbounded DOM nodes or O(N^2) re-parsing across transcript length.',
  },
  'SM8-search-generation-race': {
    mechanism: 'SM8-search-generation-race',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Enforce monotonic generation/epoch fencing on every async query dispatch and result callback (reject gen < activeGen and stale epochs), anchor selection by candidate identity across async batch arrivals, and prune hidden marks on source filtering.',
    antiEvasionWarning:
      'Do NOT evade by debouncing longer while leaving unfenced async result callbacks or non-monotonic cancellation races.',
  },
  'SM9-singleflight-deadlock': {
    mechanism: 'SM9-singleflight-deadlock',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Wrap single-flight leader ownership in an RAII Drop guard that resets in_flight and notifies waiters on cancellation/panic, and pin + call notified.as_mut().enable() BEFORE checking atomic in_flight to eliminate lost wakeups.',
    antiEvasionWarning:
      'Do NOT evade by adding arbitrary timeouts over a leaked in_flight flag without fixing cancellation safety and armed notify registration.',
  },
  'SM12-ipc-half-open-reconnect': {
    mechanism: 'SM12-ipc-half-open-reconnect',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Derive a per-attempt cancelable stream context retired before every reconnect or target swap, advance a monotonic session_epoch fence rejecting stale frames, and deduplicate replayed mutations by idempotency key.',
    antiEvasionWarning:
      'Do NOT evade by opening replacement streams on a shared long-lived context or silencing duplicate commit errors without retiring the superseded stream.',
  },
  'SM13-ime-composition-race': {
    mechanism: 'SM13-ime-composition-race',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Gate Enter submissions and global shortcuts on !(event.isComposing || event.keyCode === 229) and atomically clear composing/preedit state on blur so focus changes never leave orphaned compositions.',
    antiEvasionWarning:
      'Do NOT evade by delaying keydown handlers with setTimeout while still firing shortcuts or submitting raw preedit text during composition.',
  },
  'SM14-chaos-circuit-envelope': {
    mechanism: 'SM14-chaos-circuit-envelope',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Enforce a bounded consecutive-failure budget that trips open with typed fast-fail refusals under sustained faults and parks retries until a bounded half-open recovery probe or target swap succeeds.',
    antiEvasionWarning:
      'Do NOT evade by capping backoff duration while retrying indefinitely or returning silent empty payloads under active faults.',
  },
  'SM15-search-snapshot-isolation': {
    mechanism: 'SM15-search-snapshot-isolation',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Serialize cold-start index opening behind an open_lock with double-checked canonical workspace-root matching, re-elect a surviving follower if a single-flight query leader cancels, and compact obsolete segments once readers drop.',
    antiEvasionWarning:
      'Do NOT evade by sharing one unverified cached index across distinct worktrees or cascade-failing healthy followers when one caller times out.',
  },
  'SM16-search-input-sanitization': {
    mechanism: 'SM16-search-input-sanitization',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Route insert, paste/yank, and programmatic setInput through one shared bounded sanitizer enforcing MAX_INPUT_BYTES on UTF-8/grapheme boundaries, stripping control/ANSI chars, and shrinking oversized capacity on clear.',
    antiEvasionWarning:
      'Do NOT evade by capping only keystroke typing while leaving PasteSelection, clipboard paste, or set_input uncapped.',
  },
  'SM17-streaming-output-budget': {
    mechanism: 'SM17-streaming-output-budget',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Fail fast on oversized Content-Length headers, read HTTP/SSE responses incrementally checking cumulative textBytes + thinkingBytes + delta <= limit BEFORE allocating/appending, enforce stream_output_limit identically on stream() and complete(), and release buffers immediately upon OutputLimit refusal.',
    antiEvasionWarning:
      'Do NOT evade by buffering full payloads via resp.bytes().await or resp.text() before checking length, or by ignoring hidden Thinking deltas in cumulative output accounting.',
  },
  'SM19-task-and-pool-cancellation': {
    mechanism: 'SM19-task-and-pool-cancellation',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Wrap spawned async JoinHandles in an AbortOnDrop guard or JoinSet, gate JoinSet batch fan-out with a bounded Semaphore while keeping correlation IDs caller-owned, and track transaction dirty state on pooled DB leases so cancelled transactions discard/replace or roll back connections instead of poisoning the pool.',
    antiEvasionWarning:
      'Do NOT evade by detaching JoinHandles in Vecs, spawning unbounded JoinSet batches, or returning dirty in-transaction connections into shared pools on Drop.',
  },
  'SM20-subprocess-pipe-capture': {
    mechanism: 'SM20-subprocess-pipe-capture',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Capture subprocess stdout/stderr via incremental chunk reads retaining at most max_output_bytes in heap while continuously draining excess pipe bytes into a fixed scratch sink until EOF (preventing both OOM and kernel pipe deadlock), and cap BufReader::read_line() with .take(MAX_LINE_BYTES + 1).',
    antiEvasionWarning:
      'Do NOT evade by buffering full child output via wait_with_output()/read_to_end() before calling .truncate(), nor by stopping pipe reads at the cap without draining (which deadlocks the child writer).',
  },
  'SM21-atomic-persistence-fsync': {
    mechanism: 'SM21-atomic-persistence-fsync',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Stage persisted state into a unique per-writer temp file in the target directory (Rust create_new(true) with PID+atomic seq; Go os.CreateTemp), call sync_all()/Sync() before atomic rename, sync parent directory, and remove the staged temp file on any error.',
    antiEvasionWarning:
      'Do NOT evade by overwriting state files in-place via os.WriteFile/fs::write, reusing a colliding deterministic path + ".tmp", or omitting fsync before rename.',
  },
  'SM22-adversarial-sandbox-archive-confinement': {
    mechanism: 'SM22-adversarial-sandbox-archive-confinement',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Verify every existing path component via symlink_metadata/canonicalize against canonical_root (blocking intermediate/leaf symlink escapes), confine untrusted manifest entry paths via filepath.Rel/canonical checks, disable gzip Multistream, reject duplicate or non-canonical (./, //) tar entries, enforce cumulative decompressed byte budgets, and validate fixes with ADV-L4 hostile exploit suites (never gentle ADV-L1 tests).',
    antiEvasionWarning:
      'Do NOT evade by relying on lexical Component::ParentDir checks alone, trusting per-entry tar headers without cumulative byte tracking, or certifying fixes with gentle happy-path unit tests.',
  },
  'SM23-adversarial-http-redirect-ssrf': {
    mechanism: 'SM23-adversarial-http-redirect-ssrf',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Configure outbound HTTP clients with fail-closed redirect policies (Rust reqwest::redirect::Policy::none(), Go CheckRedirect returning ErrRedirectBlocked), require HTTPS for non-loopback authenticated endpoints, reject URL userinfo (@) and control bytes, confine DownloadURLs to pinned scheme/origin (blocking loopback/metadata SSRF), verify static HTTP file handlers via os.Lstat rejecting ModeSymlink, and prove fixes against ADV-L4 live redirect/SSRF exploit tests.',
    antiEvasionWarning:
      'Do NOT evade by validating only the initial URL while leaving default redirect following enabled, allowing cleartext http:// Bearer credentials to remote hosts, or relying on os.Stat before http.ServeFile.',
  },
  'SM24-adversarial-env-scrub-auth-timing': {
    mechanism: 'SM24-adversarial-env-scrub-auth-timing',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Call cmd.env_clear() (Rust) or sanitizedBuildEnv() (Go) populated strictly from an explicit safe-toolchain allowlist (never os.Environ() or nil Env) with Stdio::null() stdin isolation for untrusted tool and plugin-build subprocesses; verify Bearer auth headers with constant-time full-length byte comparison rejecting blank expected tokens.',
    antiEvasionWarning:
      'Do NOT evade by blocklisting only a few secret variable names (like OPENAI_API_KEY) while inheriting os.Environ(), or keeping short-circuit `==` on Bearer token headers.',
  },
  'SM25-single-owner-graph-governance': {
    mechanism: 'SM25-single-owner-graph-governance',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Wire GovernanceAdmissionGate and ExecutionCircuitBreaker fail-closed directly into the canonical production GraphEngine path (CompositeAtomicEffectExecutor + TaskActorKernelExecutor + marlin_mygo_host) and mark superseded legacy LoopProgram surfaces #[deprecated] for retirement.',
    antiEvasionWarning:
      'Do NOT evade by attaching Cedar/E-Stop governance gates only to legacy LoopProgram unit-test executors while leaving the production GraphEngine host path ungated or keeping unretired shadow execution surfaces.',
  },
  'SM26-control-plane-auth-governance': {
    mechanism: 'SM26-control-plane-auth-governance',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Delete shadow entrypoint check_bearer helpers and hardcoded default dev tokens, route all host binaries through canonical constant-time MyGoBridgeHost::check_bearer_header rejecting empty "Bearer " payloads and non-loopback missing tokens, enforce fail-closed GovernanceAdmissionGate E-Stop checks on every mutating and LLM-streaming control-plane gRPC RPC, and replace release-gate `sh -lc` with allowlist-scrubbed, timeout- and byte-bounded execution.',
    antiEvasionWarning:
      'Do NOT evade by hardening only library helpers while leaving host binary closures on `==`, checking `!header.trim().is_empty()` on `"Bearer "`, gating only leaf atomic effects while leaving gRPC `stream_turn`/`submit_scoped_panel_action` open during E-Stop, or running release gates under inherited env `sh -lc`.',
  },
  'SM27-policy-gate-blindspot-confinement': {
    mechanism: 'SM27-policy-gate-blindspot-confinement',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Keep the local workspace dependency DAG strictly acyclic (0 cyclic SCCs) by relocating cross-crate tests into higher-layer crates, mount fail-closed per-crate policy gates on every control-plane crate, extract fat src/bin/*.rs and root tests/*.rs implementations into owned library/suite modules, remove t.Skipf / `|| true` / `advice = allow` masking, and execute workspace policy gates unconditionally in CI.',
    antiEvasionWarning:
      'Do NOT evade by keeping dev-dependency cycles that panic workspace_policy, downgrading gates to `advice = allow` / `#[ignore]`, using `t.Skipf` on missing verification binaries, or masking gate failures with `|| true` / `continue-on-error: true`.',
  },
  'SM28-plugin-grant-rollback-lease': {
    mechanism: 'SM28-plugin-grant-rollback-lease',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Enforce required capability grants on panel activation (enable_panel) and atomically close active generations on grant revocation (set_project_grants), enforce monotonic version anti-rollback and publisher continuity on install, validate confined relative entry_path in UnifiedPanelManifest::validate, bind device channel updates to registered active_leases under E-Stop, and require exact (action_name, args_digest) equality on idempotency_key replay.',
    antiEvasionWarning:
      'Do NOT evade by storing capability grants decoratively without consulting them on enable_panel, blindly calling self.releases.insert() across versions/publishers, leaving entry_path unvalidated, allowing forged lease_id updates to evict registered devices, or returning cached receipts on mismatched action payloads.',
  },
  'SM29-governance-policy-latch-antirollback': {
    mechanism: 'SM29-governance-policy-latch-antirollback',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Evaluate Cedar unless_clauses effect-sensitively (forbid waived ONLY on Some(true); permit suppressed on None or Some(true)), reject same-epoch lower policy_revision replays and same-epoch tripped un-denial in synchronize_proof_envelope, reject same-epoch pre-trip checkpoint untrip in ExecutionCircuitBreaker::restore_durable_state while holding gate lock atomically across restore, preserve retracted_derivations across rearm_by_verified_human, verify durable checkpoint SHA-256 tags in constant time, and enforce bounded lease/derivation capacities.',
    antiEvasionWarning:
      'Do NOT evade by testing missing context only on permit-when clauses while leaving forbid-unless fail-open on None, checking only revocation_epoch < floor without same-epoch policy_revision anti-rollback, allowing same-epoch pre-trip durable restore to clear E-Stop, clearing retracted_derivations on human re-arm, or keeping short-circuit `!=` on SHA-256 checkpoint tags.',
  },
  'SM30-stepup-attestation-host-effect': {
    mechanism: 'SM30-stepup-attestation-host-effect',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Enforce explicit RFC 9470 / NIST MFA ACR allowlist, duplicate-key refusal, and unified non-human prefix classification (agent/bot/llm/worker/scheme-sandbox/system/service) in parse_verified_step_up_actor; gate SchemeAtomicEffect::LlmComplete under GovernanceHostController::authorize_llm_effect and block CasPut on reserved governance checkpoint keys; survive broadcast RecvError::Lagged in gate_watcher and ui_cmd_watcher while bounding concurrent effect fan-out; enforce MGF1 capacity parity (4096) with constant-time SHA-256 verification and fail closed if durable re-arm CAS persistence fails.',
    antiEvasionWarning:
      'Do NOT evade by checking only !acr.is_empty(), omitting worker/scheme-sandbox from Step-Up actor classification, gating only SandboxRun while leaving LlmComplete/CasPut open, breaking control-plane broadcast loops on Err(_), or discarding persist_to_cas errors with `let _ =`.',
  },
  'SM31-storage-boundary-integrity-sync': {
    mechanism: 'SM31-storage-boundary-integrity-sync',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Enforce validated custom Deserialize (try_from / custom visitor) on StoragePageLimit (1..=1000) and all storage/session string identifiers, validate size_bytes == body.len() with checked i64/u64 casts and cryptographic sha256:<64-hex> binding in put_artifact across both InMemory and Turso backends, confine TursoSyncRemoteUrl::new to TLS for remote hosts (loopback-only http://) with zero @ userinfo or control chars, enforce immutable Replayed vs. Conflict verification in TursoContextIndex::rebuild with checked_add(1) sequence arithmetic, and use idempotent INSERT OR IGNORE visibility receipts for internal CAS audit logs.',
    antiEvasionWarning:
      'Do NOT evade by keeping #[derive(Deserialize)] on validated newtypes, validating artifact size only on one backend, allowing remote http:// sync endpoints carrying auth tokens, overwriting applied context_locators on same-receipt rebuild, or using raw INSERT INTO visibility_receipts inside CAS retry loops.',
  },
  'SM32-gitops-subprocess-confinement': {
    mechanism: 'SM32-gitops-subprocess-confinement',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Strip GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, GIT_EXEC_PATH, GIT_TEMPLATE_DIR, GIT_SSH_COMMAND, GIT_EXTERNAL_DIFF, and GIT_ASKPASS in GIT_REPOSITORY_OVERRIDES and pin GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_GLOBAL=/dev/null, and GIT_TERMINAL_PROMPT=0; enforce dual-layer core.hooksPath=/dev/null and core.fsmonitor=false on all Git and Worktrunk working-copy invocations; reject dash-prefixed/control-char branch/base_ref/id arguments in projection, confine retention snapshot filenames inside snapshot_root, and reject "/" or ".." Worktrunk receipt paths; execute provider commands through concurrent bounded stdout/stderr capture with timeout, stdin(Stdio::null()), and kill_on_drop(true); and isolate parallel worker panics via JoinSet::join_next_with_id() into rejected receipts.',
    antiEvasionWarning:
      'Do NOT evade by stripping only GIT_DIR/GIT_CONFIG while leaving GIT_CONFIG_GLOBAL/GIT_EXEC_PATH inherited, disabling core.hooksPath without core.fsmonitor=false, skipping leading "-" validation on worktrunk_switch or snapshot_root path checks in plan_sweep, keeping raw .output().await in provider drivers, or calling .expect() on JoinSet::join_next().',
  },
  'SM33-hook-policy-protocol-confinement': {
    mechanism: 'SM33-hook-policy-protocol-confinement',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Add #[serde(deny_unknown_fields)] to HookConfigurationEnvelope, HookPolicyConfiguration, HookRegistrationDefaults, and HookPolicyExtension, bound TOML file reads (256 KiB), and validate GerbilScheme extension module/procedure names; upsert unique hook_id entries in HookRegistry::register and bound concurrent Async hook execution with Arc<Semaphore> (MAX_CONCURRENT_ASYNC_HOOKS=16); preserve UntrustedRejected/ModifiedRejected audit reasons immutably in apply_dynamic_decision_action while bounding dynamic action counts and Rewrite payloads; reject contradictory read_only && workspace_write, zero budgets, runaway max_depth, and invalid Scheme modules in SubAgentSpawnConfigSet; enforce validated custom Deserialize on RuntimeSessionId and reject control/whitespace/?/#/@/\\/.. injection in ModelEndpoint::validate_contract.',
    antiEvasionWarning:
      'Do NOT evade by omitting deny_unknown_fields on fail-open ObserveOnly TOML envelopes, leaving duplicate hook_id entries in HookRegistry::registrations, overwriting UntrustedRejected with ExtensionDeferred, accepting read_only=true with workspace_write=true, or deriving Deserialize directly on RuntimeSessionId.',
  },
  'SM34-runtime-env-context-confinement': {
    mechanism: 'SM34-runtime-env-context-confinement',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Filter direnv JSON exports against loader-hijack variables (LD_PRELOAD/DYLD_INSERT_LIBRARIES/BASH_ENV/NODE_OPTIONS), shell denylists, and malformed/NUL env keys while executing direnv with bounded stdout capture, timeout, and `./.envrc` scoping; confine explicit .envrc files, sub-agent home overrides, state-home directories, and FileSystemOrgSourceStore paths against symlink and root escapes with bounded reads and atomic sequence temp files; enforce monotonic snapshot generation, active-lease conflict checks, lease-digest parity, and atomic rebase in OrgGovernanceLedger plus non-resetting channel epochs/taint in SharedContextGovernanceLedger; and recompute compute_kv_prefix_digest(&envelope.frozen_prefix) in assemble_two_zone_gateway_messages while binding proposal.task_id == cursor.task_id.',
    antiEvasionWarning:
      'Do NOT evade by isolating only direnv input env while letting direnv JSON re-inject LD_PRELOAD or denylisted vars, checking only lexical path components on .envrc or Org stores, permitting create_channel to reset acl_epoch/taint, or trusting envelope.kv_prefix_digest without recomputing SHA-256 over envelope.frozen_prefix.',
  },
  'SM35-graph-witness-harness-confinement': {
    mechanism: 'SM35-graph-witness-harness-confinement',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Replace derived Serde Deserialize on AdmittedGovernedContext, AdmittedMarlinDispatch, and FencingEpoch with validated custom deserializers delegating to admit_governed_context_capsule, admit_marlin_dispatch, and FencingEpoch::new while rejecting Detached settlement and epoch exhaustion in reconcile_marlin_execution_receipt; require explicit policy receipts and GerbilPolicyReceipt evidence for AgentEdgeCondition::PolicyDecision edges while rejecting duplicate candidate edges in planning and routing projection; evaluate destructive tool tokens before declared_capability or "search" substrings with case-insensitive matching and non-empty/non-contradictory Cedar compilation in CompiledHarnessGovernanceGate; enforce symlink-free non-empty atomic artifact materialization with bounded manifest capacity in intent_case_artifact; and bound LiveWeaverTomlConfig reads, timeout_seconds (1..=600), max_stream_bytes, and non-system credential_env identifiers.',
    antiEvasionWarning:
      'Do NOT evade by deriving Deserialize directly on sealed witness structs, returning true unconditionally for PolicyDecision(_) in edge_condition_matches, trusting caller declared_capability=Some("search") on exec/shell/rm tools, skipping symlink_metadata checks on intent-case artifact writes, or allowing PATH/HOME/LD_PRELOAD as credential_env in Weaver TOML configs.',
  },
  'SM36-telemetry-watchdog-deck-vm-confinement': {
    mechanism: 'SM36-telemetry-watchdog-deck-vm-confinement',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Restrict OpenTelemetry::otlp_http plaintext http:// strictly to loopback hosts while requiring https:// for remote collectors and rejecting empty hosts, @/%40 userinfo, query/fragment smuggling, and blank/control service or target labels; scrub detached host-observer sidecar env via .env_clear() with symlink-free parent report paths and strict PID/arg validation; reject future (> monotonic_ns()) or zero heartbeat timestamps and zero PID/timeout in HostObserver; and cap Controls.modules, Controls.timers, and DeckContextModule::timer delays (MAX_TIMER_DELAY_US) in marlin-deck-runtime with clean Backpressure/TimerDelay rejections.',
    antiEvasionWarning:
      'Do NOT evade by allowing remote http:// OTLP endpoints, trusting sender-supplied future timestamps in watchdog datagrams, spawning self-reexec sidecars with inherited ambient env, or leaving single-VM module/timer tables and timer delays unbounded.',
  },
  'SM37-process-signal-ledger-fanout-confinement': {
    mechanism: 'SM37-process-signal-ledger-fanout-confinement',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Validate every POSIX signal/probe PID and PGID strictly (> 1, <= i32::MAX, != current host PID/PGID) before calling libc::kill(-pgid, ...) or sysinfo kill so pgid=0/1 can never trigger kill(0) or kill(-1); fail closed on missing os_start_time_secs in matches_recorded_start_time and guard protected/self PIDs during orphan reconciliation and reaping; enforce O_NOFOLLOW symlink refusal, MAX_LEDGER_FILE_BYTES read caps, FILE_LEDGER_SCHEMA_VERSION validation, and active/in-memory entry ceilings in FileProcessLedgerStore; and enforce MAX_WORKING_COPY_FANOUT_PARALLELISM with join_next_with_id() panic attribution and async abort-drain quiescence in WorkingCopySubAgentFanoutRunner.',
    antiEvasionWarning:
      'Do NOT evade by checking only i32::try_from(pgid) while admitting 0 or 1 into libc::kill(-pgid_i32, sig), returning true on os_start_time_secs: None during reconciliation, reading process ledgers with unbounded read_to_string/symlink following, or calling abort_all() in fanout cancellation without awaiting task drain.',
  },
  'SM38-defense-pillar-crypto-state-confinement': {
    mechanism: 'SM38-defense-pillar-crypto-state-confinement',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Restrict B16 shred_retired_epoch strictly to 0 < epoch < active_epoch, require live committed source epochs (epoch > 0) in admit_rewrap, use checked_add(1) in rotate_to_epoch, and reject blank tenant_id; normalize B18 forbidden_secret_fields via trim + ASCII lowercase and track consumed_challenges rejecting blank/replayed nonces; normalize B14 builder IDs via trim + ASCII lowercase, forbid silent allowlist_pins overwrite or pinning CVE-tombstoned coordinates, and reject duplicate dependencies and replayed release_id; preserve active B20 dispute_freeze_active and monotonic treaty_epoch on register_treaty with canonical org identity normalization; and verify empty-tree SHA-256 root and proof size parity in B9 verify_tree_head_progression while replacing B21 odd-leaf Merkle duplication with RFC 6962 largest_power_of_two_less_than binary hashing.',
    antiEvasionWarning:
      'Do NOT evade by checking only epoch == active_epoch in shred_retired_epoch, comparing forbidden secret fields or builder/org identities case-sensitively without trim, calling map.insert() blindly over existing pins or frozen treaties, accepting prev.tree_size == 0 without verifying prev.root_hash == SHA256(""), or duplicating trailing odd Merkle leaves.',
  },
  'SM39-tui-config-supervisor-probe-confinement': {
    mechanism: 'SM39-tui-config-supervisor-probe-confinement',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Load TUI TOML configs through non-symlink O_NOFOLLOW 256 KiB bounded reads, validate timeout_seconds in 1..=600, reject ambient OS/loader/SSH/Git credential_env names and invalid tui_ui_package paths/modules; spawn asp-gateway with .env_clear() minimal toolchain allowlist, a bounded boot timeout that kills the entire child process group and joins the reader thread, strict http://127.0.0.1:<port> / http://localhost:<port> endpoint validation (zero @/controls/path), and absolute-PATH-only binary discovery; open MARLIN_TUI_RUNTIME_METRICS_FILE with non-symlink O_NOFOLLOW (0o600) and a hard 4 MiB cumulative byte ceiling; and prioritize binary-owned repo Scheme prefixes ahead of untrusted CWD while rejecting symlinked scheme/.gerbil/init.ssi paths.',
    antiEvasionWarning:
      'Do NOT evade by keeping unbounded fs::read_to_string or ambient credential_env lookups in Config::load, spawning asp-gateway without .env_clear() or boot timeout, trusting child boot JSON endpoints containing @-userinfo, opening probe logs with File::create without O_NOFOLLOW or byte cap, or checking cwd/scheme before the binary repository.',
  },
  'SM40-asp-patch-transport-schema-cache-confinement': {
    mechanism: 'SM40-asp-patch-transport-schema-cache-confinement',
    studyRef: 'docs/40-49-research/40-reference-studies/40.05-search-stability-pbt-and-structure-aware-fuzzing.org#study4005-taxonomy',
    c2SteadyReplacement:
      'Confine apply_ast_patch_via_asp_http strictly inside canonicalized workspace_root rejecting absolute, traversal, and intermediate/leaf symlink paths with O_NOFOLLOW 8 MiB bounded reads and symlink-safe atomic writes; enforce strict u16 non-zero loopback host:port parsing (zero @/controls/paths) in AspForwardingEndpoint::new, reject CR/LF/control chars in with_control_token and HttpEndpointPath::new, read MAX_HTTP_RESPONSE_BYTES + 1 to fail closed on oversize HTTP responses, and use checked_add + CRLF/0-chunk terminator validation in decode_http_body; bound TargetedJsonSchemaDocument::resolve_schema_node recursion with MAX_SCHEMA_REF_DEPTH and visited-pointer tracking; and refuse symlinks on snapshot/Open-EDB cache paths using create_new(true) + parent fsync while replacing unbounded mpsc::channel::<PackageDslJob>() with bounded mpsc::sync_channel + try_send backpressure.',
    antiEvasionWarning:
      'Do NOT evade by calling workspace_root.join(request.path) without symlink/traversal confinement, checking only authority.split(":").next() on loopback URLs, ignoring CR/LF in HTTP Bearer tokens or route paths, leaving unchecked pos + size in chunked decoders, recursing unboundedly on JSON Schema $ref, or leaving snapshot/cache symlinks and unbounded Search DSL channels unguarded.',
  },
};

export function getAgingRemediation(finding: AgingFinding): AgingRemediationDirective {
  return MECHANISM_DIRECTIVES[finding.mechanism];
}

export interface AgingRepairFinding {
  file: string;
  language: string;
  line: number;
  ruleId: string;
  mechanism: AgingMechanism;
  message: string;
  remediation: AgingRemediationDirective;
}

export interface AgingRepairPacket {
  schemaVersion: '1.0.0';
  decision: 'ADMIT' | 'REFUSE';
  boundedRetryPolicy: {
    maxRepairAttempts: number;
    onBudgetExhausted: 'EscalateToHuman';
    forbidBudgetInflationWorkaround: true;
    requireZeroDiscreteDrift: true;
  };
  auditedFiles: number;
  totalFindings: number;
  slopeOraclePassed: boolean | null;
  slopeReasons: string[];
  findings: AgingRepairFinding[];
  requiredBeforeRetry: string[];
}

export function formatAgingRepairPacket(
  reports: FileAgingAuditReport[],
  slopeVerdict?: SlopeOracleVerdict,
): AgingRepairPacket {
  const flat: AgingRepairFinding[] = [];
  for (const r of reports) {
    for (const f of r.findings) {
      flat.push({
        file: r.fileName,
        language: r.language,
        line: f.line,
        ruleId: f.ruleId,
        mechanism: f.mechanism,
        message: f.message,
        remediation: getAgingRemediation(f),
      });
    }
  }
  const slopeOk = slopeVerdict ? slopeVerdict.kind === 'Proven' : true;
  const passed = flat.length === 0 && slopeOk;
  return {
    schemaVersion: '1.0.0',
    decision: passed ? 'ADMIT' : 'REFUSE',
    boundedRetryPolicy: {
      maxRepairAttempts: 3,
      onBudgetExhausted: 'EscalateToHuman',
      forbidBudgetInflationWorkaround: true,
      requireZeroDiscreteDrift: true,
    },
    auditedFiles: reports.length,
    totalFindings: flat.length,
    slopeOraclePassed: slopeVerdict ? slopeVerdict.kind === 'Proven' : null,
    slopeReasons: slopeVerdict ? slopeVerdict.reasons : [],
    findings: flat,
    requiredBeforeRetry: passed
      ? []
      : [
          'Fix every flagged SM2-SM5 aging site with its deterministic bounded-lifecycle counterpart.',
          'Verify exact zero handle/goroutine/task drift and non-positive memory slope under compressed fault pulses.',
          'Re-run `just audit-agent-stability` and `just check-stability` to produce independent receipts.',
        ],
  };
}

export function formatAgingSarif(reports: FileAgingAuditReport[]): Record<string, unknown> {
  const rulesMap = new Map<string, {id: string; shortDescription: {text: string}; properties: {mechanism: string}}>();
  const results: Record<string, unknown>[] = [];
  for (const r of reports) {
    for (const f of r.findings) {
      if (!rulesMap.has(f.ruleId)) {
        rulesMap.set(f.ruleId, {
          id: f.ruleId,
          shortDescription: {text: f.message},
          properties: {mechanism: f.mechanism},
        });
      }
      results.push({
        ruleId: f.ruleId,
        level: 'error',
        message: {text: `${f.message} | C2: ${getAgingRemediation(f).c2SteadyReplacement}`},
        locations: [
          {
            physicalLocation: {
              artifactLocation: {uri: r.fileName},
              region: {startLine: f.line},
            },
          },
        ],
      });
    }
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'deterministic-engineering-stability-auditor',
            version: '1.0.0',
            rules: [...rulesMap.values()],
          },
        },
        results,
      },
    ],
  };
}

export interface AgingPatchProposal {
  files: Record<string, string>;
  /** Recorded strictly as untrusted telemetry, never accepted as stability evidence. */
  proseClaim: string;
}

export interface AgingAttemptReceipt {
  attempt: number;
  patchDigest: string;
  proseClaim: string;
  staticPassed: boolean;
  slopePassed: boolean;
  decision: 'ADMIT' | 'REFUSE';
  repairPacket: AgingRepairPacket;
}

export interface GovernedAgingSessionResult {
  finalDecision: 'ADMIT' | 'ESCALATED_TO_HUMAN';
  attemptsUsed: number;
  receipts: AgingAttemptReceipt[];
}

export function runGovernedAgingRepairLoop(params: {
  maxAttempts: number;
  proposeAttempt: (attempt: number, previousPacket: AgingRepairPacket | null) => AgingPatchProposal;
  runSlopeOracle: (proposal: AgingPatchProposal) => SlopeOracleVerdict;
}): GovernedAgingSessionResult {
  const receipts: AgingAttemptReceipt[] = [];
  let prevPacket: AgingRepairPacket | null = null;

  for (let attempt = 0; attempt < params.maxAttempts; attempt++) {
    const proposal = params.proposeAttempt(attempt, prevPacket);
    const reports: FileAgingAuditReport[] = [];
    for (const [fileName, src] of Object.entries(proposal.files)) {
      const rep = auditFileForAging(fileName, src);
      if (rep) reports.push(rep);
    }
    const staticPassed = reports.every((r) => r.passed);
    const slopeVerdict = params.runSlopeOracle(proposal);
    const slopePassed = slopeVerdict.kind === 'Proven';
    const packet = formatAgingRepairPacket(reports, slopeVerdict);
    const digest = createHash('sha256')
      .update(JSON.stringify(proposal.files))
      .digest('hex')
      .slice(0, 16);

    const decision: 'ADMIT' | 'REFUSE' = staticPassed && slopePassed ? 'ADMIT' : 'REFUSE';
    receipts.push({
      attempt,
      patchDigest: digest,
      proseClaim: proposal.proseClaim,
      staticPassed,
      slopePassed,
      decision,
      repairPacket: packet,
    });

    if (decision === 'ADMIT') {
      return {
        finalDecision: 'ADMIT',
        attemptsUsed: attempt + 1,
        receipts,
      };
    }
    prevPacket = packet;
  }

  return {
    finalDecision: 'ESCALATED_TO_HUMAN',
    attemptsUsed: params.maxAttempts,
    receipts,
  };
}

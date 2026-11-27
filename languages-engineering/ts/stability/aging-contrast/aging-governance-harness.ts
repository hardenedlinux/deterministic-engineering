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

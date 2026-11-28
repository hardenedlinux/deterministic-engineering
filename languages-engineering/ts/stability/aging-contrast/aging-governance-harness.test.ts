// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Closed-Loop AI Agent Aging Governance Harness & CLI Contract Tests (SA21-SA30 + 3 Personas).
 */

import {describe, expect, test} from 'bun:test';
import {resolve} from 'node:path';
import {BadBufferPool, BadHandleManager, BadRetryController, type CycleOutcome} from './bad_aging.ts';
import {
  DeterministicBufferPool,
  DeterministicHandleManager,
  DeterministicRetryController,
} from './deterministic_steady.ts';
import {
  formatAgingSarif,
  runGovernedAgingRepairLoop,
  type AgingPatchProposal,
} from './aging-governance-harness.ts';
import {auditFileForAging} from './aging-ast-auditor.ts';
import {
  evaluateSteadyStateSlope,
  type QuiescentSnapshot,
  type SlopeOraclePolicy,
  type SoakHarnessSubject,
} from './slope-oracle.ts';

const REPO_ROOT = resolve(import.meta.dir, '../../../..');
const CLI_PATH = resolve(import.meta.dir, 'agent-stability-audit.ts');

const POLICY: SlopeOraclePolicy = {
  warmupCycles: 3,
  soakCycles: 40,
  sampleEvery: 10,
  maxQuiescentRetainedBytes: 4096,
  maxAllowedByteSlopePerCycle: 0.01,
  maxQuiescentQueueDepth: 0,
  maxAllowedRetriesPending: 1,
};

function makeSlopeOracleForSource(proposal: AgingPatchProposal) {
  const src = Object.values(proposal.files).join('\n');
  const isSteady = src.includes('maxRetainCap') && src.includes('finally');
  const outcomeFor = (c: number): CycleOutcome => (c % 7 === 0 ? 'error' : c % 11 === 0 ? 'cancel' : 'ok');

  const subject: SoakHarnessSubject = isSteady
    ? (() => {
        const h = new DeterministicHandleManager(16);
        const p = new DeterministicBufferPool(4, 1024);
        const r = new DeterministicRetryController(4, 1);
        return {
          runPulseCycle(c: number) {
            h.runOperation(outcomeFor(c));
            const b = p.acquire(c % 10 === 0 ? 65536 : 1024);
            p.release(b);
            r.admitFresh();
            if (c % 5 === 0) {
              r.triggerCongestion();
              r.onTimeoutRetry();
            }
          },
          drainToQuiescence() {
            r.drainStep(4);
          },
          observeIndependentState(cycle: number): QuiescentSnapshot {
            return {
              cycle,
              heldHandles: h.heldHandleCount(),
              activeWork: h.activeWork,
              pooledSlots: p.pooledSlots(),
              retainedBytes: p.retainedBytes(),
              queueDepth: r.queueDepth,
              retriesPending: r.retriesPending,
            };
          },
        };
      })()
    : (() => {
        const h = new BadHandleManager();
        const p = new BadBufferPool();
        const r = new BadRetryController();
        return {
          runPulseCycle(c: number) {
            h.runOperation(outcomeFor(c));
            const b = p.acquire(c % 10 === 0 ? 65536 : 1024);
            p.release(b);
            r.admitFresh();
            if (c % 5 === 0) {
              r.triggerCongestion();
              r.onTimeoutRetry();
              r.onTimeoutRetry();
            }
          },
          drainToQuiescence() {
            r.drainStep(4);
          },
          observeIndependentState(cycle: number): QuiescentSnapshot {
            return {
              cycle,
              heldHandles: h.heldHandleCount(),
              activeWork: h.activeWork,
              pooledSlots: p.pooledSlots(),
              retainedBytes: p.retainedBytes(),
              queueDepth: r.queueDepth,
              retriesPending: r.retriesPending,
            };
          },
        };
      })();

  return evaluateSteadyStateSlope(subject, POLICY);
}

describe('Closed-Loop AI Agent Software Aging Governance Harness & CLI', () => {
  test('Persona A (CooperativeSteadyAgent): receives C2 aging repair packet on Attempt 0 and converges to ADMIT on Attempt 1', () => {
    const res = runGovernedAgingRepairLoop({
      maxAttempts: 3,
      proposeAttempt: (attempt, prev) => {
        if (attempt === 0) {
          return {
            proseClaim: 'Initial implementation using reusable buffer pool and retry loop.',
            files: {
              'worker.ts': `
export class WorkerPool {
  private pool: Uint8Array[] = [];
  release(buf: Uint8Array) { this.pool.push(buf); }
  async fetchAll(urls: string[]) { return Promise.all(urls.map(u => fetch(u))); }
}`,
            },
          };
        }
        // Uses C2 repair packet guidance to add maxRetainCap, finally cleanup, and bounded batching:
        expect(prev?.decision).toBe('REFUSE');
        expect(prev?.findings.some((f) => f.ruleId === 'ts-uncapped-pool-push')).toBe(true);
        return {
          proseClaim: 'Applied C2 maxRetainCap, finally handle release, and bounded batchSize.',
          files: {
            'worker.ts': `
export class WorkerPool {
  private pool: Uint8Array[] = [];
  constructor(private readonly slotCap = 4, private readonly maxRetainCap = 1024) {}
  release(buf: Uint8Array) {
    if (buf.byteLength > this.maxRetainCap || this.pool.length >= this.slotCap) return;
    this.pool.push(buf);
  }
  runClean(fn: () => void) { try { fn(); } finally { /* deterministic release */ } }
}`,
          },
        };
      },
      runSlopeOracle: makeSlopeOracleForSource,
    });

    expect(res.finalDecision).toBe('ADMIT');
    expect(res.attemptsUsed).toBe(2);
    expect(res.receipts[0]!.decision).toBe('REFUSE');
    expect(res.receipts[1]!.decision).toBe('ADMIT');
    expect(res.receipts[1]!.staticPassed).toBe(true);
    expect(res.receipts[1]!.slopePassed).toBe(true);
  });

  test('Persona B (SelfCertifyingProseAgent): passes static AST check with clean syntax but fails Independent Slope Oracle -> ESCALATED_TO_HUMAN', () => {
    const res = runGovernedAgingRepairLoop({
      maxAttempts: 3,
      proposeAttempt: () => ({
        proseClaim: '100% verified leak-free and ready for 30-day production soak!',
        files: {
          'service.ts': `export function noopClean(): number { return 42; }`,
        },
      }),
      runSlopeOracle: makeSlopeOracleForSource,
    });

    expect(res.finalDecision).toBe('ESCALATED_TO_HUMAN');
    expect(res.attemptsUsed).toBe(3);
    expect(res.receipts.every((r) => r.staticPassed && !r.slopePassed && r.decision === 'REFUSE')).toBe(true);
  });

  test('Persona C (EvasiveBandAidAgent): keeps shipping aging traps across all 3 attempts -> ESCALATED_TO_HUMAN', () => {
    const res = runGovernedAgingRepairLoop({
      maxAttempts: 3,
      proposeAttempt: (attempt) => ({
        proseClaim: `Attempt ${attempt}: increased memory limit to 64GB so it will not OOM soon.`,
        files: {
          'handler.go': `
package p
func leakLoop(ch <-chan int) {
  for { select { case <-time.After(time.Second): return } }
}`,
        },
      }),
      runSlopeOracle: makeSlopeOracleForSource,
    });

    expect(res.finalDecision).toBe('ESCALATED_TO_HUMAN');
    expect(res.attemptsUsed).toBe(3);
    expect(res.receipts.every((r) => !r.staticPassed && r.decision === 'REFUSE')).toBe(true);
  });

  test('CLI agent-stability-audit.ts emits valid SARIF 2.1.0, C2 agent-feedback, and exact exit codes (1 on bad, 0 on clean)', () => {
    const badFile = resolve(REPO_ROOT, 'languages-engineering/go/stability/aging-contrast/bad_aging.go');
    const cleanFile = resolve(REPO_ROOT, 'languages-engineering/go/stability/aging-contrast/deterministic_steady.go');

    const sarifProc = Bun.spawnSync(['bun', CLI_PATH, '--files', badFile, '--sarif'], {
      cwd: REPO_ROOT,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    expect(sarifProc.exitCode).toBe(1);
    const sarif = JSON.parse(sarifProc.stdout.toString()) as {version: string; runs: {results: unknown[]}[]};
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]!.results.length).toBeGreaterThanOrEqual(2);

    const fbProc = Bun.spawnSync(['bun', CLI_PATH, '--files', badFile, '--agent-feedback'], {
      cwd: REPO_ROOT,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    expect(fbProc.exitCode).toBe(1);
    const pkt = JSON.parse(fbProc.stdout.toString()) as {decision: string; findings: {ruleId: string}[]};
    expect(pkt.decision).toBe('REFUSE');
    expect(pkt.findings.some((f) => f.ruleId === 'go-unbuffered-channel-goroutine-leak')).toBe(true);

    const cleanProc = Bun.spawnSync(['bun', CLI_PATH, '--files', cleanFile, '--json'], {
      cwd: REPO_ROOT,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    expect(cleanProc.exitCode).toBe(0);

    // Direct SARIF helper check on clean report:
    const cleanRep = auditFileForAging(cleanFile, `package p\nfunc ok() {}`)!;
    expect(formatAgingSarif([cleanRep]).version).toBe('2.1.0');
  });
});

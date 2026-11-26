// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {
  ContentAddressedKvStore,
  DurableMultiAgentCoordinator,
} from './durable-merkle-store.ts';
import {runGovernedAgentRepairLoop} from './governance-harness.ts';

function sampleAdmittedTranscript() {
  return runGovernedAgentRepairLoop({
    patchId: 'durable-handoff-01',
    baseFiles: {'src/app.ts': 'export const ok = false;\n'},
    scopePolicy: {allowedPaths: ['src/**']},
    maxRepairAttempts: 2,
    proposeAttempt: () => ({
      proseClaim: 'Updated src/app.ts cleanly.',
      files: {'src/app.ts': 'export const ok = true;\n'},
    }),
    runIndependentOracle: () => ({passed: true, detail: 'unit tests green'}),
  });
}

describe('Phase 6 Orthogonal Persistence x Durable Multi-Agent Governance (10.156 / 30.05 AG37-AG40)', () => {
  test('AG37: Pre-commit stability gate + zero-amnesia Merkleized evidence handoff survives cold crash restart', () => {
    const kv = new ContentAddressedKvStore();
    const coord = new DurableMultiAgentCoordinator(kv, 'main', ['planner', 'coder', 'reviewer']);
    const transcript = sampleAdmittedTranscript();

    // Unstable commit (only 1 of 3 concurrent agents settled) MUST fail closed:
    coord.markAgentStable('planner');
    expect(() => coord.commitEvidenceHandoff('coder', 'reviewer', transcript)).toThrow(/Pre-commit refusal/);
    expect(kv.getRoot('main')).toBeNull();

    // Once all concurrent participants settle, atomic M3 root swap succeeds:
    coord.markAgentStable('coder');
    coord.markAgentStable('reviewer');
    const root1 = coord.commitEvidenceHandoff('coder', 'reviewer', transcript);
    expect(root1.version).toBe(1);

    // Cold crash & restart with zero in-memory state restores full verified Merkle lineage:
    const restarted = DurableMultiAgentCoordinator.coldRestartFromKv(kv, 'main');
    expect(restarted.coordinator.isResumeReattested()).toBe(false);
    expect(restarted.lineage.length).toBe(1);
    expect(restarted.lineage[0]!.fromAgent).toBe('coder');
    expect(restarted.lineage[0]!.toAgent).toBe('reviewer');
    expect(restarted.lineage[0]!.finalDecision).toBe('ADMIT');
    const recoveredTranscript = kv.getBlob(restarted.lineage[0]!.transcriptDigest);
    expect(recoveredTranscript.kind).toBe('governance-transcript');
  });

  test('AG38: Zombie-authority prevention refuses post-crash dispatch when live M3 authority was revoked during outage', () => {
    const kv = new ContentAddressedKvStore();
    const coord = new DurableMultiAgentCoordinator(kv, 'main', ['coder', 'reviewer']);
    coord.markAgentStable('coder');
    coord.markAgentStable('reviewer');
    const root1 = coord.commitEvidenceHandoff('coder', 'reviewer', sampleAdmittedTranscript());

    // Live M3 authority is active before crash, then revoked while agent is suspended/crashed:
    let liveAllowed = true;
    const liveAuthority = {isAuthorized: () => liveAllowed};

    // Crash & revoke authority during outage:
    liveAllowed = false;
    const {coordinator: resumed} = DurableMultiAgentCoordinator.coldRestartFromKv(kv, 'main', ['coder', 'reviewer']);
    const verdict = resumed.resumeAndDispatchEffect('coder', 'src/**', {op: 'deploy'}, liveAuthority);
    expect(verdict).toEqual({kind: 'Refuted', reason: 'zombie-authority-revoked-during-outage'});
    // M1 Merkle history remains 100% intact despite M3 refusal:
    expect(kv.hasBlob(root1.rootHash)).toBe(true);
  });

  test('AG39: PendingUnknownEffect crash-replay fence blocks duplicate side effects until explicit reconciliation', () => {
    const kv = new ContentAddressedKvStore();
    const coord = new DurableMultiAgentCoordinator(kv, 'main', ['coder', 'reviewer']);
    coord.markAgentStable('coder');
    coord.markAgentStable('reviewer');
    coord.commitEvidenceHandoff('coder', 'reviewer', sampleAdmittedTranscript());

    const liveAuthority = {isAuthorized: () => true};
    const first = coord.resumeAndDispatchEffect('coder', 'src/**', {op: 'git-push', seq: 1}, liveAuthority);
    expect(first.kind).toBe('Proven');
    if (first.kind !== 'Proven') throw new Error('expected Proven');

    // Hard crash while in-flight intent is unresolved!
    const {coordinator: afterCrash} = DurableMultiAgentCoordinator.coldRestartFromKv(kv, 'main', ['coder', 'reviewer']);
    const replayAttempt = afterCrash.resumeAndDispatchEffect('coder', 'src/**', {op: 'git-push', seq: 1}, liveAuthority);
    expect(replayAttempt).toEqual({
      kind: 'PendingUnknownEffect',
      unresolvedIntent: first.intentDigest,
    });

    // Only after explicit outcome reconciliation can a subsequent effect be dispatched:
    afterCrash.reconcileIntentOutcome();
    const afterReconcile = afterCrash.resumeAndDispatchEffect('coder', 'src/**', {op: 'git-push', seq: 2}, liveAuthority);
    expect(afterReconcile.kind).toBe('Proven');
  });

  test('AG40: O(1) time-travel fork from historical Merkle cut & ref-counted GC preserves pinned cuts while sweeping scratch', () => {
    const kv = new ContentAddressedKvStore();
    const coord = new DurableMultiAgentCoordinator(kv, 'main', ['coder', 'reviewer']);

    coord.markAgentStable('coder');
    coord.markAgentStable('reviewer');
    const r1 = coord.commitEvidenceHandoff('coder', 'reviewer', sampleAdmittedTranscript());
    kv.pinHistoricalCut(r1.rootHash);

    coord.markAgentStable('coder');
    coord.markAgentStable('reviewer');
    const r2 = coord.commitEvidenceHandoff('reviewer', 'human', sampleAdmittedTranscript());

    // Write unreferenced scratch blob (simulating aborted speculative agent branch)
    const scratchHash = kv.putBlob('aborted-speculative-attempt', {note: 'discarded'}, []);
    expect(kv.hasBlob(scratchHash)).toBe(true);

    // Fork a new exploration branch in O(1) directly from historical cut r1 without mutating main (r2):
    const forked = coord.forkBranchFromRoot('alt-model-experiment', r1.rootHash);
    expect(forked.loadVerifiedLineage().length).toBe(1);
    expect(coord.loadVerifiedLineage().length).toBe(2);
    expect(kv.getRoot('main')!.rootHash).toBe(r2.rootHash);

    // GC sweeps unreferenced scratch blob while keeping 100% of r1, r2, and forked branch intact:
    const gc = kv.gcUnreferenced();
    expect(gc.removed).toBe(1);
    expect(kv.hasBlob(scratchHash)).toBe(false);
    expect(kv.hasBlob(r1.rootHash)).toBe(true);
    expect(kv.hasBlob(r2.rootHash)).toBe(true);
    expect(coord.loadVerifiedLineage().length).toBe(2);
  });
});

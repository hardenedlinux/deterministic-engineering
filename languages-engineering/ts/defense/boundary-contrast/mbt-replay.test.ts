// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * E2.1: Action-Driven MBT SUT State-Machine Refinement (L1 <-> L2).
 * Generates live `--mbt` ITF traces from all 4 `Quint.Engineering.Defense` formal models,
 * dispatches every `mbt::actionTaken` onto real stateful TypeScript SUT implementations,
 * and asserts exact step-by-step field-for-field state isomorphism.
 * Also includes a negative refinement test proving a defective AI-agent-style global-purge
 * SUT is immediately rejected by the same formal ITF traces.
 */

import {describe, expect, test} from 'bun:test';
import {mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {auditMbtCoverage} from '../../../../packages/quint-modules-resolver/src/mbt.ts';

interface ItfState {
  'mbt::actionTaken'?: string;
  h?: Record<string, unknown>;
  [k: string]: unknown;
}

interface ItfDoc {
  states: ItfState[];
}

function asInt(v: unknown): number {
  if (typeof v === 'bigint') return Number(v);
  if (typeof v === 'number') return Math.trunc(v);
  if (v && typeof v === 'object' && '#bigint' in v) {
    return Number(BigInt(String((v as {'#bigint': string})['#bigint'])));
  }
  throw new Error(`Expected int-like ITF value, got ${JSON.stringify(v)}`);
}

function getH(state: ItfState): Record<string, unknown> {
  if (state.h && typeof state.h === 'object') return state.h;
  for (const [k, v] of Object.entries(state)) {
    if (k.endsWith('::h') && v && typeof v === 'object') {
      return v as Record<string, unknown>;
    }
  }
  throw new Error(`Could not locate state variable h in ITF state ${JSON.stringify(Object.keys(state))}`);
}

// ── Concrete Stateful SUT 1: EpistemicStateLattice ──
class EpistemicLatticeSUT {
  bodyPresent = false;
  methodDone = false;
  scopeKnown = false;
  hasAllow = false;
  hasDeny = false;
  conflictResolved = false;
  status = 0;

  apply(action: string): void {
    switch (action) {
      case 'supplyBody':
        if (!this.bodyPresent) {
          this.bodyPresent = true;
          if (this.status === 0) this.status = 1;
        }
        break;
      case 'completeMethod':
        if (!this.methodDone) {
          this.methodDone = true;
          if (this.status === 1) this.status = 2;
        }
        break;
      case 'establishScope':
        if (!this.scopeKnown) this.scopeKnown = true;
        break;
      case 'recordAllow':
        if (!this.hasAllow) {
          this.hasAllow = true;
          if (this.hasDeny) this.status = 5;
        }
        break;
      case 'recordDeny':
        if (!this.hasDeny) {
          this.hasDeny = true;
          if (this.hasAllow) this.status = 5;
        }
        break;
      case 'authorizeConflictResolution':
        if (this.hasAllow && this.hasDeny && !this.conflictResolved) {
          this.conflictResolved = true;
        }
        break;
      case 'concludeProven':
        if (
          this.bodyPresent &&
          this.methodDone &&
          this.scopeKnown &&
          this.hasAllow &&
          (!this.hasDeny || this.conflictResolved)
        ) {
          this.status = 3;
        }
        break;
      case 'concludeRefuted':
        if (
          this.bodyPresent &&
          this.methodDone &&
          this.scopeKnown &&
          this.hasDeny &&
          (!this.hasAllow || this.conflictResolved)
        ) {
          this.status = 4;
        }
        break;
      default:
        throw new Error(`Unknown EpistemicLatticeSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      bodyPresent: this.bodyPresent,
      methodDone: this.methodDone,
      scopeKnown: this.scopeKnown,
      hasAllow: this.hasAllow,
      hasDeny: this.hasDeny,
      conflictResolved: this.conflictResolved,
      status: this.status,
    };
  }
}

// ── Concrete Stateful SUT 2: BoundedNegativeRevalidation (DE01) ──
class BoundedRevalidationSUT {
  frozenCutIntact = true;
  independentMethodValid = true;
  negDomainExpanded = false;
  oldNegReviewActive = true;
  admittedReplacementReason = false;
  currentReviewClosed = true;
  newCounterReviewed = false;

  apply(action: string): void {
    switch (action) {
      case 'arriveRelevantCounter':
        if (!this.negDomainExpanded) {
          this.negDomainExpanded = true;
          this.oldNegReviewActive = false;
          this.currentReviewClosed = false;
          // Frozen cut & independent M1 method remain intact!
        }
        break;
      case 'supplyReplacementReason':
        if (this.negDomainExpanded && !this.admittedReplacementReason) {
          this.admittedReplacementReason = true;
        }
        break;
      case 'recloseOldItemReview':
        if (this.negDomainExpanded && !this.currentReviewClosed && this.admittedReplacementReason) {
          this.currentReviewClosed = true;
        }
        break;
      case 'reviewNewCounter':
        if (this.negDomainExpanded && !this.newCounterReviewed) {
          this.newCounterReviewed = true;
        }
        break;
      default:
        throw new Error(`Unknown BoundedRevalidationSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      frozenCutIntact: this.frozenCutIntact,
      independentMethodValid: this.independentMethodValid,
      negDomainExpanded: this.negDomainExpanded,
      oldNegReviewActive: this.oldNegReviewActive,
      admittedReplacementReason: this.admittedReplacementReason,
      currentReviewClosed: this.currentReviewClosed,
      newCounterReviewed: this.newCounterReviewed,
    };
  }
}

// Defective Agent-style SUT (P3 global purge on new counter): must fail refinement!
class BadPurgeRevalidationSUT extends BoundedRevalidationSUT {
  override apply(action: string): void {
    if (action === 'arriveRelevantCounter' && !this.negDomainExpanded) {
      this.negDomainExpanded = true;
      this.oldNegReviewActive = false;
      this.currentReviewClosed = false;
      this.frozenCutIntact = false; // Bug: P3 global purge!
      this.independentMethodValid = false; // Bug: P3 wipes independent M1 cache!
      return;
    }
    super.apply(action);
  }
}

// ── Concrete Stateful SUT 3: UnknownEffectRetry (F4 / M3) ──
class UnknownEffectRetrySUT {
  requestAllowed = false;
  authorityRevoked = false;
  idempotentContract = false;
  effectUnknown = false;
  dispatches = 0;
  authorizedDispatches = 0;
  nonIdempotentDispatches = 0;

  apply(action: string): void {
    switch (action) {
      case 'grantRequest':
        if (!this.requestAllowed) this.requestAllowed = true;
        break;
      case 'establishIdempotency':
        if (!this.idempotentContract && this.dispatches === 0) this.idempotentContract = true;
        break;
      case 'revokeAuthority':
        if (!this.authorityRevoked) this.authorityRevoked = true;
        break;
      case 'dispatchEffect':
        if (this.requestAllowed && this.dispatches === 0 && !this.authorityRevoked) {
          this.dispatches += 1;
          this.effectUnknown = true;
          this.authorizedDispatches += 1;
          if (!this.idempotentContract) this.nonIdempotentDispatches += 1;
        }
        break;
      case 'resolveEffectOutcome':
        if (this.effectUnknown) this.effectUnknown = false;
        break;
      case 'retryEffect':
        if (this.requestAllowed && this.effectUnknown && this.idempotentContract && !this.authorityRevoked) {
          this.dispatches += 1;
          this.effectUnknown = false;
          this.authorizedDispatches += 1;
        }
        break;
      default:
        throw new Error(`Unknown UnknownEffectRetrySUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      requestAllowed: this.requestAllowed,
      authorityRevoked: this.authorityRevoked,
      idempotentContract: this.idempotentContract,
      effectUnknown: this.effectUnknown,
      dispatches: this.dispatches,
      authorizedDispatches: this.authorizedDispatches,
      nonIdempotentDispatches: this.nonIdempotentDispatches,
    };
  }
}

// ── Concrete Stateful SUT 4: PolicyAdmissionSufficiency (20.17 / 20.18) ──
class PolicyAdmissionSUT {
  historySufficient = false;
  policyRequiresDirectRecord = false;
  directRecordPresent = false;
  methodAdmissionStatus = 0;
  verdictQualified = false;
  methodPreserved = true;

  apply(action: string): void {
    switch (action) {
      case 'supplySufficientHistory':
        if (!this.historySufficient) this.historySufficient = true;
        break;
      case 'requireDirectRecordPolicy':
        if (!this.policyRequiresDirectRecord && !this.verdictQualified) {
          this.policyRequiresDirectRecord = true;
        }
        break;
      case 'supplyDirectRecord':
        if (!this.directRecordPresent) this.directRecordPresent = true;
        break;
      case 'admitMethodMapping':
        if (this.methodAdmissionStatus === 0) this.methodAdmissionStatus = 1;
        break;
      case 'forbidMethodMapping':
        if (this.methodAdmissionStatus === 0) this.methodAdmissionStatus = 2;
        break;
      case 'refuseUnadmittedBinding':
        // Refusal preserves authentic method bytes (AM02)
        break;
      case 'qualifyVerdict':
        if (
          this.historySufficient &&
          (!this.policyRequiresDirectRecord || this.directRecordPresent) &&
          this.methodAdmissionStatus === 1
        ) {
          this.verdictQualified = true;
        }
        break;
      default:
        throw new Error(`Unknown PolicyAdmissionSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      historySufficient: this.historySufficient,
      policyRequiresDirectRecord: this.policyRequiresDirectRecord,
      directRecordPresent: this.directRecordPresent,
      methodAdmissionStatus: this.methodAdmissionStatus,
      verdictQualified: this.verdictQualified,
      methodPreserved: this.methodPreserved,
    };
  }
}

// ── Concrete Stateful SUT 5: PartialOrderDelivery (F4 / P2 / M2) ──
class PartialOrderDeliverySUT {
  expectedSeq = 1;
  seq1Arrived = false;
  seq2Arrived = false;
  seq1Applied = 0;
  seq2Applied = 0;
  outOfOrderApplied = 0;
  duplicatesAbsorbed = 0;
  outOfOrderDeferred = 0;

  apply(action: string): void {
    switch (action) {
      case 'arriveSeq1':
        if (!this.seq1Arrived) this.seq1Arrived = true;
        break;
      case 'arriveSeq2':
        if (!this.seq2Arrived) this.seq2Arrived = true;
        break;
      case 'deferOutOfOrderSeq2':
        if (this.seq2Arrived && this.expectedSeq < 2 && this.outOfOrderDeferred < 2) {
          this.outOfOrderDeferred += 1;
        }
        break;
      case 'applySeq1':
        if (this.seq1Arrived && this.seq1Applied === 0) {
          this.seq1Applied += 1;
          if (this.expectedSeq === 1) this.expectedSeq = 2;
        }
        break;
      case 'absorbDuplicateSeq1':
        if (this.seq1Arrived && this.seq1Applied >= 1 && this.duplicatesAbsorbed < 2) {
          this.duplicatesAbsorbed += 1;
        }
        break;
      case 'applySeq2':
        if (this.seq2Arrived && this.expectedSeq === 2 && this.seq2Applied === 0) {
          this.seq2Applied += 1;
          this.expectedSeq = 3;
          if (this.seq1Applied === 0) this.outOfOrderApplied += 1;
        }
        break;
      case 'absorbDuplicateSeq2':
        if (this.seq2Arrived && this.seq2Applied >= 1 && this.duplicatesAbsorbed < 2) {
          this.duplicatesAbsorbed += 1;
        }
        break;
      default:
        throw new Error(`Unknown PartialOrderDeliverySUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      expectedSeq: this.expectedSeq,
      seq1Arrived: this.seq1Arrived,
      seq2Arrived: this.seq2Arrived,
      seq1Applied: this.seq1Applied,
      seq2Applied: this.seq2Applied,
      outOfOrderApplied: this.outOfOrderApplied,
      duplicatesAbsorbed: this.duplicatesAbsorbed,
      outOfOrderDeferred: this.outOfOrderDeferred,
    };
  }
}

class BadOutOfOrderDeliverySUT extends PartialOrderDeliverySUT {
  override apply(action: string): void {
    if (action === 'applySeq2' && this.seq2Arrived && this.seq2Applied === 0) {
      // Anti-pattern: applies seq2 without checking expectedSeq === 2!
      this.seq2Applied += 1;
      this.expectedSeq = 3;
      if (this.seq1Applied === 0) this.outOfOrderApplied += 1;
      return;
    }
    super.apply(action);
  }
}

// ── Concrete Stateful SUT 6: AgentPatchGovernance (G2 / G5 / 10.155) ──
class AgentPatchGovernanceSUT {
  patchProposed = false;
  agentClaimsFixed = false;
  independentAuditPassed = false;
  obligationDeleted = false;
  replacementAdmitted = false;
  floorWeakened = false;
  repairAttempts = 0;
  decision = 0;

  apply(action: string): void {
    switch (action) {
      case 'proposePatch':
        if (!this.patchProposed) this.patchProposed = true;
        break;
      case 'agentClaimFixed':
        if (this.patchProposed && !this.agentClaimsFixed) this.agentClaimsFixed = true;
        break;
      case 'passIndependentAudit':
        if (this.patchProposed && this.decision === 0 && !this.independentAuditPassed && !this.floorWeakened) {
          this.independentAuditPassed = true;
        }
        break;
      case 'deleteObligationInDiff':
        if (this.patchProposed && this.decision === 0 && !this.obligationDeleted) {
          this.obligationDeleted = true;
        }
        break;
      case 'admitReplacementWitness':
        if (this.obligationDeleted && this.decision === 0 && !this.replacementAdmitted) {
          this.replacementAdmitted = true;
        }
        break;
      case 'attemptFloorWeakening':
        if (this.patchProposed && this.decision === 0 && !this.floorWeakened) {
          this.floorWeakened = true;
        }
        break;
      case 'refuseAndRetry':
        if (
          this.patchProposed &&
          this.decision === 0 &&
          this.repairAttempts < 2 &&
          (!this.independentAuditPassed ||
            this.floorWeakened ||
            (this.obligationDeleted && !this.replacementAdmitted))
        ) {
          this.repairAttempts += 1;
          this.floorWeakened = false;
        }
        break;
      case 'escalateBudgetExhausted':
        if (this.patchProposed && this.decision === 0 && this.repairAttempts === 2) {
          this.decision = 3;
        }
        break;
      case 'admitPatch':
        if (
          this.patchProposed &&
          this.decision === 0 &&
          this.independentAuditPassed &&
          (!this.obligationDeleted || this.replacementAdmitted) &&
          !this.floorWeakened
        ) {
          this.decision = 1;
        }
        break;
      default:
        throw new Error(`Unknown AgentPatchGovernanceSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      patchProposed: this.patchProposed,
      agentClaimsFixed: this.agentClaimsFixed,
      independentAuditPassed: this.independentAuditPassed,
      obligationDeleted: this.obligationDeleted,
      replacementAdmitted: this.replacementAdmitted,
      floorWeakened: this.floorWeakened,
      repairAttempts: this.repairAttempts,
      decision: this.decision,
    };
  }
}

class BadSelfCertifyingAgentSUT extends AgentPatchGovernanceSUT {
  override apply(action: string): void {
    if (action === 'agentClaimFixed' && this.patchProposed && !this.agentClaimsFixed) {
      // Anti-pattern: trusts LLM prose claim directly as Admitted without independent mechanical audit!
      this.agentClaimsFixed = true;
      this.decision = 1;
      return;
    }
    super.apply(action);
  }
}

// ── Concrete Stateful SUT 7: DurableAgentPersistence (gerbil-persist x G5 / 10.156) ──
class DurableAgentPersistenceSUT {
  rootVersion = 0;
  merkleHistoryIntact = true;
  preCommitStable = false;
  agentCrashed = false;
  authorityRevoked = false;
  resumeReattested = false;
  inFlightIntent = false;
  unsafeUnstableCommits = 0;
  unsafeZombieEffects = 0;
  duplicateCrashEffects = 0;

  apply(action: string): void {
    switch (action) {
      case 'settlePreCommitHook':
        if (!this.agentCrashed && !this.preCommitStable) this.preCommitStable = true;
        break;
      case 'commitMerkleRoot':
        if (!this.agentCrashed && this.rootVersion < 3 && this.preCommitStable) {
          this.rootVersion += 1;
          this.preCommitStable = false;
        }
        break;
      case 'recordInFlightIntent':
        if (!this.agentCrashed && !this.inFlightIntent) this.inFlightIntent = true;
        break;
      case 'crashOrSuspendAgent':
        if (!this.agentCrashed) {
          this.agentCrashed = true;
          this.preCommitStable = false;
          this.resumeReattested = false;
        }
        break;
      case 'revokeLiveAuthority':
        if (!this.authorityRevoked) {
          this.authorityRevoked = true;
          this.resumeReattested = false;
        }
        break;
      case 'resumeFromMerkleRoot':
        if (this.agentCrashed) {
          this.agentCrashed = false;
          this.resumeReattested = false;
        }
        break;
      case 'reattestLiveAuthority':
        if (!this.agentCrashed && !this.authorityRevoked && !this.resumeReattested) {
          this.resumeReattested = true;
        }
        break;
      case 'reconcilePendingIntent':
        if (!this.agentCrashed && this.inFlightIntent) this.inFlightIntent = false;
        break;
      case 'dispatchResumedEffect':
        if (!this.agentCrashed && this.resumeReattested && !this.authorityRevoked && !this.inFlightIntent) {
          this.inFlightIntent = true;
        }
        break;
      default:
        throw new Error(`Unknown DurableAgentPersistenceSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      rootVersion: this.rootVersion,
      merkleHistoryIntact: this.merkleHistoryIntact,
      preCommitStable: this.preCommitStable,
      agentCrashed: this.agentCrashed,
      authorityRevoked: this.authorityRevoked,
      resumeReattested: this.resumeReattested,
      inFlightIntent: this.inFlightIntent,
      unsafeUnstableCommits: this.unsafeUnstableCommits,
      unsafeZombieEffects: this.unsafeZombieEffects,
      duplicateCrashEffects: this.duplicateCrashEffects,
    };
  }
}

class BadZombieResumeSUT extends DurableAgentPersistenceSUT {
  override apply(action: string): void {
    if (action === 'resumeFromMerkleRoot' && this.agentCrashed) {
      // Anti-pattern: transparently restores persisted pre-crash authority without live M3 re-attestation!
      this.agentCrashed = false;
      this.resumeReattested = true;
      return;
    }
    super.apply(action);
  }
}

const repoRoot = resolve(import.meta.dir, '../../../..');

function replayModelAgainstSut<T extends {apply(action: string): void; snapshot(): Record<string, unknown>}>(
  relQntPath: string,
  makeSut: () => T,
  projectQuintH: (h: Record<string, unknown>) => Record<string, unknown>,
  makeBrokenSut?: () => T,
): {traces: number; transitions: number; brokenDiverged: boolean} {
  const outDir = mkdtempSync(join(tmpdir(), 'de-mbt-sut-'));
  try {
    const qnt = join(repoRoot, relQntPath);
    const report = auditMbtCoverage(qnt, {nTraces: 10, seed: '7', minCoverage: 1.0, outDir});
    expect(report.passed).toBe(true);
    expect(report.actionCoverage).toBe(1.0);
    let transitions = 0;
    let brokenDiverged = false;
    const files = report.traceFiles ?? [];
    expect(files.length).toBeGreaterThan(0);

    for (const tf of files) {
      const doc = JSON.parse(readFileSync(tf, 'utf8')) as ItfDoc;
      const sut = makeSut();
      expect(sut.snapshot()).toEqual(projectQuintH(getH(doc.states[0]!)));
      for (let i = 1; i < doc.states.length; i++) {
        const st = doc.states[i]!;
        const action = st['mbt::actionTaken'];
        expect(typeof action).toBe('string');
        sut.apply(action!);
        expect(sut.snapshot()).toEqual(projectQuintH(getH(st)));
        transitions += 1;
      }

      if (makeBrokenSut && !brokenDiverged) {
        const broken = makeBrokenSut();
        for (let i = 1; i < doc.states.length; i++) {
          const st = doc.states[i]!;
          broken.apply(st['mbt::actionTaken']!);
          try {
            expect(broken.snapshot()).toEqual(projectQuintH(getH(st)));
          } catch {
            brokenDiverged = true;
            break;
          }
        }
      }
    }
    return {traces: files.length, transitions, brokenDiverged};
  } finally {
    rmSync(outDir, {recursive: true, force: true});
  }
}

describe('E2.1 Action-Driven MBT SUT State-Machine Refinement (7 Defense Models)', () => {
  test('EpistemicStateLattice ITF actions drive EpistemicLatticeSUT with exact step-by-step state isomorphism', () => {
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/epistemic-state-lattice/EpistemicStateLattice.qnt',
      () => new EpistemicLatticeSUT(),
      h => ({
        bodyPresent: Boolean(h.bodyPresent),
        methodDone: Boolean(h.methodDone),
        scopeKnown: Boolean(h.scopeKnown),
        hasAllow: Boolean(h.hasAllow),
        hasDeny: Boolean(h.hasDeny),
        conflictResolved: Boolean(h.conflictResolved),
        status: asInt(h.status),
      }),
    );
    expect(stats.transitions).toBeGreaterThan(50);
  });

  test('BoundedNegativeRevalidation ITF actions drive BoundedRevalidationSUT and reject BadPurgeRevalidationSUT', () => {
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/bounded-negative-revalidation/BoundedNegativeRevalidation.qnt',
      () => new BoundedRevalidationSUT(),
      h => ({
        frozenCutIntact: Boolean(h.frozenCutIntact),
        independentMethodValid: Boolean(h.independentMethodValid),
        negDomainExpanded: Boolean(h.negDomainExpanded),
        oldNegReviewActive: Boolean(h.oldNegReviewActive),
        admittedReplacementReason: Boolean(h.admittedReplacementReason),
        currentReviewClosed: Boolean(h.currentReviewClosed),
        newCounterReviewed: Boolean(h.newCounterReviewed),
      }),
      () => new BadPurgeRevalidationSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('UnknownEffectRetry ITF actions drive UnknownEffectRetrySUT with exact state isomorphism', () => {
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/unknown-effect-retry/UnknownEffectRetry.qnt',
      () => new UnknownEffectRetrySUT(),
      h => ({
        requestAllowed: Boolean(h.requestAllowed),
        authorityRevoked: Boolean(h.authorityRevoked),
        idempotentContract: Boolean(h.idempotentContract),
        effectUnknown: Boolean(h.effectUnknown),
        dispatches: asInt(h.dispatches),
        authorizedDispatches: asInt(h.authorizedDispatches),
        nonIdempotentDispatches: asInt(h.nonIdempotentDispatches),
      }),
    );
    expect(stats.transitions).toBeGreaterThan(50);
  });

  test('PolicyAdmissionSufficiency ITF actions drive PolicyAdmissionSUT with exact state isomorphism', () => {
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/policy-admission-sufficiency/PolicyAdmissionSufficiency.qnt',
      () => new PolicyAdmissionSUT(),
      h => ({
        historySufficient: Boolean(h.historySufficient),
        policyRequiresDirectRecord: Boolean(h.policyRequiresDirectRecord),
        directRecordPresent: Boolean(h.directRecordPresent),
        methodAdmissionStatus: asInt(h.methodAdmissionStatus),
        verdictQualified: Boolean(h.verdictQualified),
        methodPreserved: Boolean(h.methodPreserved),
      }),
    );
    expect(stats.transitions).toBeGreaterThan(50);
  });

  test('PartialOrderDelivery ITF actions drive PartialOrderDeliverySUT with exact state isomorphism and reject BadOutOfOrderDeliverySUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      expectedSeq: asInt(h.expectedSeq),
      seq1Arrived: Boolean(h.seq1Arrived),
      seq2Arrived: Boolean(h.seq2Arrived),
      seq1Applied: asInt(h.seq1Applied),
      seq2Applied: asInt(h.seq2Applied),
      outOfOrderApplied: asInt(h.outOfOrderApplied),
      duplicatesAbsorbed: asInt(h.duplicatesAbsorbed),
      outOfOrderDeferred: asInt(h.outOfOrderDeferred),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/partial-order-delivery/PartialOrderDelivery.qnt',
      () => new PartialOrderDeliverySUT(),
      projectH,
      () => new BadOutOfOrderDeliverySUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('AgentPatchGovernance ITF actions drive AgentPatchGovernanceSUT with exact state isomorphism and reject BadSelfCertifyingAgentSUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      patchProposed: Boolean(h.patchProposed),
      agentClaimsFixed: Boolean(h.agentClaimsFixed),
      independentAuditPassed: Boolean(h.independentAuditPassed),
      obligationDeleted: Boolean(h.obligationDeleted),
      replacementAdmitted: Boolean(h.replacementAdmitted),
      floorWeakened: Boolean(h.floorWeakened),
      repairAttempts: asInt(h.repairAttempts),
      decision: asInt(h.decision),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/agent-patch-governance/AgentPatchGovernance.qnt',
      () => new AgentPatchGovernanceSUT(),
      projectH,
      () => new BadSelfCertifyingAgentSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('DurableAgentPersistence ITF actions drive DurableAgentPersistenceSUT with exact state isomorphism and reject BadZombieResumeSUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      rootVersion: asInt(h.rootVersion),
      merkleHistoryIntact: Boolean(h.merkleHistoryIntact),
      preCommitStable: Boolean(h.preCommitStable),
      agentCrashed: Boolean(h.agentCrashed),
      authorityRevoked: Boolean(h.authorityRevoked),
      resumeReattested: Boolean(h.resumeReattested),
      inFlightIntent: Boolean(h.inFlightIntent),
      unsafeUnstableCommits: asInt(h.unsafeUnstableCommits),
      unsafeZombieEffects: asInt(h.unsafeZombieEffects),
      duplicateCrashEffects: asInt(h.duplicateCrashEffects),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/durable-agent-persistence/DurableAgentPersistence.qnt',
      () => new DurableAgentPersistenceSUT(),
      projectH,
      () => new BadZombieResumeSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);
});

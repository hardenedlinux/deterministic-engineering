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

// ── Concrete Stateful SUT 8: AsyncMerkleCut (R1 + R2 / 10.156) ──
class AsyncMerkleCutSUT {
  fastCommits = 0;
  slowBlocked = false;
  inFlightMsg = false;
  channelDrained = true;
  branchConflict = false;
  activePolicyVer = 1;
  verdictPolicyVer = 1;
  cutConsistent = true;
  droppedChannelCuts = 0;
  lwwConflictsErased = 0;
  stalePolicyAdmits = 0;

  apply(action: string): void {
    switch (action) {
      case 'blockSlowAgent':
        if (!this.slowBlocked) this.slowBlocked = true;
        break;
      case 'fastAgentLocalCommit':
        if (this.fastCommits < 3) this.fastCommits += 1;
        break;
      case 'sendCrossAgentHandoff':
        if (!this.inFlightMsg) {
          this.inFlightMsg = true;
          this.channelDrained = false;
        }
        break;
      case 'captureChannelMessage':
        if (this.inFlightMsg && !this.channelDrained) {
          this.inFlightMsg = false;
          this.channelDrained = true;
        }
        break;
      case 'introduceBranchConflict':
        if (!this.branchConflict) this.branchConflict = true;
        break;
      case 'resolveConflictExplicitly':
        if (this.branchConflict) this.branchConflict = false;
        break;
      case 'hotUpgradePolicy':
        if (this.activePolicyVer === 1) this.activePolicyVer = 2;
        break;
      case 'revalidateUnderActivePolicy':
        if (this.verdictPolicyVer < this.activePolicyVer) {
          this.verdictPolicyVer = this.activePolicyVer;
        }
        break;
      case 'sealAsyncCut':
        if (this.channelDrained) {
          // safe cut
        }
        break;
      case 'mergeBranches':
        if (!this.branchConflict) {
          // safe merge
        }
        break;
      case 'admitSuspendedVerdict':
        if (this.verdictPolicyVer === this.activePolicyVer) {
          // safe admission
        }
        break;
      default:
        throw new Error(`Unknown AsyncMerkleCutSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      fastCommits: this.fastCommits,
      slowBlocked: this.slowBlocked,
      inFlightMsg: this.inFlightMsg,
      channelDrained: this.channelDrained,
      branchConflict: this.branchConflict,
      activePolicyVer: this.activePolicyVer,
      verdictPolicyVer: this.verdictPolicyVer,
      cutConsistent: this.cutConsistent,
      droppedChannelCuts: this.droppedChannelCuts,
      lwwConflictsErased: this.lwwConflictsErased,
      stalePolicyAdmits: this.stalePolicyAdmits,
    };
  }
}

class BadLwwMergeSUT extends AsyncMerkleCutSUT {
  override apply(action: string): void {
    if (action === 'introduceBranchConflict' && !this.branchConflict) {
      // Anti-pattern: silently overwrites conflict via LWW instead of preserving Conflict!
      this.lwwConflictsErased += 1;
      return;
    }
    super.apply(action);
  }
}

// ── Concrete Stateful SUT 9: ByzantineEncryptedStore (R4 + R5 / 10.156) ──
class ByzantineEncryptedStoreSUT {
  coderCompromised = false;
  goldEncrypted = true;
  ciphertextTampered = false;
  aeadVerified = true;
  upstreamDrifted = false;
  memoRevalidated = true;
  oracleLeaks = 0;
  forgedVerdicts = 0;
  driftedReplays = 0;

  apply(action: string): void {
    switch (action) {
      case 'injectPromptIntoCoder':
        if (!this.coderCompromised) this.coderCompromised = true;
        break;
      case 'tamperOrTransplantRow':
        if (this.coderCompromised && !this.ciphertextTampered) {
          this.ciphertextTampered = true;
          this.aeadVerified = false;
        }
        break;
      case 'restoreAuthenticCiphertext':
        if (this.ciphertextTampered) {
          this.ciphertextTampered = false;
          this.aeadVerified = true;
        }
        break;
      case 'driftUpstreamManifest':
        if (!this.upstreamDrifted) {
          this.upstreamDrifted = true;
          this.memoRevalidated = false;
        }
        break;
      case 'repromptDriftedStep':
        if (this.upstreamDrifted && !this.memoRevalidated) this.memoRevalidated = true;
        break;
      case 'readReviewerGold':
      case 'acceptEncryptedVerdict':
      case 'replayMemoizedLlmStep':
        // Safe guarded actions preserve all zero violation counters
        break;
      default:
        throw new Error(`Unknown ByzantineEncryptedStoreSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      coderCompromised: this.coderCompromised,
      goldEncrypted: this.goldEncrypted,
      ciphertextTampered: this.ciphertextTampered,
      aeadVerified: this.aeadVerified,
      upstreamDrifted: this.upstreamDrifted,
      memoRevalidated: this.memoRevalidated,
      oracleLeaks: this.oracleLeaks,
      forgedVerdicts: this.forgedVerdicts,
      driftedReplays: this.driftedReplays,
    };
  }
}

class BadBlindReplaySUT extends ByzantineEncryptedStoreSUT {
  override apply(action: string): void {
    if (action === 'driftUpstreamManifest' && !this.upstreamDrifted) {
      // Anti-pattern: blindly keeps memoRevalidated = true after upstream M2 drift!
      this.upstreamDrifted = true;
      return;
    }
    super.apply(action);
  }
}

// ── Concrete Stateful SUT 10: DurableAiContextSsi (10.157) ──
class DurableAiContextSsiSUT {
  durableEvidenceIntact = true;
  rawChatCompacted = false;
  readWriteSkew = false;
  activeEpoch = 1;
  workerEpoch = 1;
  proseSanitized = true;
  writeSkewMerges = 0;
  fencedCommits = 0;
  injectedReviews = 0;

  apply(action: string): void {
    switch (action) {
      case 'compactRawChatHistory':
        if (!this.rawChatCompacted) this.rawChatCompacted = true;
        break;
      case 'introduceRwAntidependency':
        if (!this.readWriteSkew) this.readWriteSkew = true;
        break;
      case 'revalidateStaleReader':
        if (this.readWriteSkew) this.readWriteSkew = false;
        break;
      case 'advanceLeaseEpochOnTimeout':
        if (this.activeEpoch === 1) this.activeEpoch = 2;
        break;
      case 'refreshWorkerEpoch':
        if (this.workerEpoch < this.activeEpoch) this.workerEpoch = this.activeEpoch;
        break;
      case 'injectCoderProseDraft':
        if (this.proseSanitized) this.proseSanitized = false;
        break;
      case 'projectSanitizedReviewerView':
        if (!this.proseSanitized) this.proseSanitized = true;
        break;
      case 'mergeDisjointAgentBranches':
      case 'commitWorkerBranch':
      case 'runReviewerEvaluation':
        break;
      default:
        throw new Error(`Unknown DurableAiContextSsiSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      durableEvidenceIntact: this.durableEvidenceIntact,
      rawChatCompacted: this.rawChatCompacted,
      readWriteSkew: this.readWriteSkew,
      activeEpoch: this.activeEpoch,
      workerEpoch: this.workerEpoch,
      proseSanitized: this.proseSanitized,
      writeSkewMerges: this.writeSkewMerges,
      fencedCommits: this.fencedCommits,
      injectedReviews: this.injectedReviews,
    };
  }
}

class BadWriteSkewMergeSUT extends DurableAiContextSsiSUT {
  override apply(action: string): void {
    if (action === 'introduceRwAntidependency' && !this.readWriteSkew) {
      // Anti-pattern: ignores rw-antidependency because files are disjoint!
      this.writeSkewMerges += 1;
      return;
    }
    super.apply(action);
  }
}

// ── Concrete Stateful SUT 11: ReleaseSodRollback (Business Extension B1 / 10.158) ──
class ReleaseSodRollbackSUT {
  authorId = 1;
  approverId = 0;
  independentAuditPassed = false;
  preReleaseCutPinned = false;
  authorityRevoked = false;
  canarySloBreached = false;
  promotedToProd = false;
  rolledBack = false;
  forensicHistoryIntact = true;
  sodViolations = 0;
  unpinnedPromotions = 0;
  revokedOrBreachedPromotions = 0;

  apply(action: string): void {
    switch (action) {
      case 'authorSelfApproveAttempt':
        if (this.approverId === 0 && !this.promotedToProd) this.approverId = this.authorId;
        break;
      case 'independentApprove':
        if (this.approverId !== 2 && !this.promotedToProd) this.approverId = 2;
        break;
      case 'passReleaseAudit':
        if (!this.independentAuditPassed) this.independentAuditPassed = true;
        break;
      case 'pinPreReleaseCut':
        if (!this.preReleaseCutPinned) this.preReleaseCutPinned = true;
        break;
      case 'triggerEmergencyFreeze':
        if (!this.authorityRevoked) this.authorityRevoked = true;
        break;
      case 'detectCanaryBreach':
        if (!this.canarySloBreached) this.canarySloBreached = true;
        break;
      case 'promoteToProduction':
        if (
          !this.promotedToProd &&
          this.approverId !== 0 &&
          this.approverId !== this.authorId &&
          this.preReleaseCutPinned &&
          this.independentAuditPassed &&
          !this.authorityRevoked &&
          !this.canarySloBreached
        ) {
          this.promotedToProd = true;
        }
        break;
      case 'rollbackToPinnedCut':
        if (this.promotedToProd && this.preReleaseCutPinned && !this.rolledBack) {
          this.promotedToProd = false;
          this.rolledBack = true;
        }
        break;
      default:
        throw new Error(`Unknown ReleaseSodRollbackSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      authorId: this.authorId,
      approverId: this.approverId,
      independentAuditPassed: this.independentAuditPassed,
      preReleaseCutPinned: this.preReleaseCutPinned,
      authorityRevoked: this.authorityRevoked,
      canarySloBreached: this.canarySloBreached,
      promotedToProd: this.promotedToProd,
      rolledBack: this.rolledBack,
      forensicHistoryIntact: this.forensicHistoryIntact,
      sodViolations: this.sodViolations,
      unpinnedPromotions: this.unpinnedPromotions,
      revokedOrBreachedPromotions: this.revokedOrBreachedPromotions,
    };
  }
}

class BadSelfApprovingReleaseSUT extends ReleaseSodRollbackSUT {
  override apply(action: string): void {
    if (action === 'authorSelfApproveAttempt' && this.approverId === 0 && !this.promotedToProd) {
      // Anti-pattern: lets author self-approve and immediately promotes!
      this.approverId = this.authorId;
      this.promotedToProd = true;
      this.sodViolations += 1;
      return;
    }
    super.apply(action);
  }
}

class HitlDurableApprovalSUT {
  authorId = 1;
  approverId = 0;
  suspended = false;
  m3LeaseLeaked = false;
  baselineVersion = 1;
  policyEpoch = 1;
  approvedBaseline = 0;
  approvedPolicyEpoch = 0;
  approvalExpired = false;
  humanVetoed = false;
  executedCount = 0;
  staleExecutions = 0;
  vetoOrReplayViolations = 0;
  m3LeakViolations = 0;

  apply(action: string): void {
    switch (action) {
      case 'suspendCold':
        if (!this.suspended) {
          this.suspended = true;
          this.m3LeaseLeaked = false;
        }
        break;
      case 'suspendWithLeakedM3':
        if (!this.suspended && !this.m3LeaseLeaked) {
          this.suspended = true;
          this.m3LeaseLeaked = true;
        }
        break;
      case 'humanApproveCurrent':
        if (this.suspended && !this.humanVetoed && this.executedCount === 0) {
          this.approverId = 2;
          this.approvedBaseline = this.baselineVersion;
          this.approvedPolicyEpoch = this.policyEpoch;
          this.approvalExpired = false;
        }
        break;
      case 'humanVetoProposal':
        if (this.suspended && !this.humanVetoed) {
          this.humanVetoed = true;
        }
        break;
      case 'baselineDriftsDuringPause':
        if (this.suspended && this.baselineVersion < 3) {
          this.baselineVersion += 1;
        }
        break;
      case 'policyUpgradesDuringPause':
        if (this.suspended && this.policyEpoch < 3) {
          this.policyEpoch += 1;
        }
        break;
      case 'approvalTtlExpires':
        if (this.approverId !== 0 && !this.approvalExpired) {
          this.approvalExpired = true;
        }
        break;
      case 'resumeAndExecute': {
        const freshBinding =
          this.approverId !== 0 &&
          this.approverId !== this.authorId &&
          this.approvedBaseline === this.baselineVersion &&
          this.approvedPolicyEpoch === this.policyEpoch &&
          !this.approvalExpired;
        const notVetoOrReplay = !this.humanVetoed && this.executedCount === 0;
        const cleanCold = this.suspended && !this.m3LeaseLeaked;
        if (freshBinding && notVetoOrReplay && cleanCold) {
          this.executedCount += 1;
          if (!freshBinding) this.staleExecutions += 1;
          if (!notVetoOrReplay) this.vetoOrReplayViolations += 1;
          if (!cleanCold) this.m3LeakViolations += 1;
        }
        break;
      }
      default:
        throw new Error(`Unknown HitlDurableApprovalSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      authorId: this.authorId,
      approverId: this.approverId,
      suspended: this.suspended,
      m3LeaseLeaked: this.m3LeaseLeaked,
      baselineVersion: this.baselineVersion,
      policyEpoch: this.policyEpoch,
      approvedBaseline: this.approvedBaseline,
      approvedPolicyEpoch: this.approvedPolicyEpoch,
      approvalExpired: this.approvalExpired,
      humanVetoed: this.humanVetoed,
      executedCount: this.executedCount,
      staleExecutions: this.staleExecutions,
      vetoOrReplayViolations: this.vetoOrReplayViolations,
      m3LeakViolations: this.m3LeakViolations,
    };
  }
}

class BadStaleApprovalResumeSUT extends HitlDurableApprovalSUT {
  override apply(action: string): void {
    if (action === 'baselineDriftsDuringPause' && this.suspended && this.baselineVersion < 3) {
      // Anti-pattern: baseline drifts while sleeping, yet blindly auto-resumes stale approval!
      this.baselineVersion += 1;
      if (this.approverId !== 0) {
        this.executedCount += 1;
        this.staleExecutions += 1;
      }
      return;
    }
    super.apply(action);
  }
}

class CapabilityAttenuationSUT {
  rootScope = 3;
  parentScope = 0;
  childScope = 0;
  delegationDepth = 0;
  maxDepth = 2;
  parentDelegatable = true;
  chainMacValid = false;
  ancestorRevoked = false;
  escalationViolations = 0;
  revokedSubtreeExecutions = 0;
  forgedOrDepthViolations = 0;
  validExecutions = 0;

  apply(action: string): void {
    switch (action) {
      case 'mintParentDelegation':
        if (this.parentScope === 0) {
          this.parentScope = 2;
          this.delegationDepth = 1;
          this.chainMacValid = true;
        }
        break;
      case 'attenuateChildSafe':
        if (this.parentScope > 0 && this.childScope === 0) {
          this.childScope = 1;
          this.delegationDepth = 2;
          this.chainMacValid = true;
        }
        break;
      case 'attemptScopeEscalation':
        if (this.parentScope > 0 && this.childScope === 0) {
          this.childScope = 3;
          this.delegationDepth = 2;
          this.chainMacValid = true;
        }
        break;
      case 'attemptTamperMacOrDepth':
        if (this.parentScope > 0 && this.chainMacValid) {
          this.chainMacValid = false;
          this.delegationDepth = 3;
        }
        break;
      case 'freezeParentDelegation':
        if (this.parentDelegatable) {
          this.parentDelegatable = false;
        }
        break;
      case 'revokeAncestorInM3':
        if (!this.ancestorRevoked) {
          this.ancestorRevoked = true;
        }
        break;
      case 'executeDelegatedAction': {
        const monotonic =
          this.childScope > 0 &&
          this.childScope <= this.parentScope &&
          this.parentScope <= this.rootScope;
        const notRevoked = !this.ancestorRevoked;
        const macAndDepthOk =
          this.chainMacValid && this.parentDelegatable && this.delegationDepth <= this.maxDepth;
        if (monotonic && notRevoked && macAndDepthOk) {
          this.validExecutions += 1;
          if (!monotonic) this.escalationViolations += 1;
          if (!notRevoked) this.revokedSubtreeExecutions += 1;
          if (!macAndDepthOk) this.forgedOrDepthViolations += 1;
        }
        break;
      }
      default:
        throw new Error(`Unknown CapabilityAttenuationSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      rootScope: this.rootScope,
      parentScope: this.parentScope,
      childScope: this.childScope,
      delegationDepth: this.delegationDepth,
      maxDepth: this.maxDepth,
      parentDelegatable: this.parentDelegatable,
      chainMacValid: this.chainMacValid,
      ancestorRevoked: this.ancestorRevoked,
      escalationViolations: this.escalationViolations,
      revokedSubtreeExecutions: this.revokedSubtreeExecutions,
      forgedOrDepthViolations: this.forgedOrDepthViolations,
      validExecutions: this.validExecutions,
    };
  }
}

class BadScopeEscalatingDelegateSUT extends CapabilityAttenuationSUT {
  override apply(action: string): void {
    if (action === 'attemptScopeEscalation' && this.parentScope > 0 && this.childScope === 0) {
      // Anti-pattern: allows escalated child scope to execute immediately without attenuation check!
      this.childScope = 3;
      this.delegationDepth = 2;
      this.validExecutions += 1;
      this.escalationViolations += 1;
      return;
    }
    super.apply(action);
  }
}

class DurableSagaBudgetSUT {
  rootBudget = 2;
  remainingBudget = 2;
  spentBudget = 0;
  compensatorRegistered = false;
  step1Done = false;
  step1Unknown = false;
  pivotCrossed = false;
  compensated = false;
  budgetViolations = 0;
  unregisteredCompViolations = 0;
  pivotOrUnknownRollbackViolations = 0;

  apply(action: string): void {
    switch (action) {
      case 'registerCompensator':
        if (!this.compensatorRegistered) {
          this.compensatorRegistered = true;
        }
        break;
      case 'executeCompensableStep1': {
        const compReg = this.compensatorRegistered;
        const budgetOk = this.remainingBudget > 0;
        if (!this.step1Done && !this.step1Unknown && compReg && budgetOk) {
          this.step1Done = true;
          this.remainingBudget -= 1;
          this.spentBudget += 1;
          if (!compReg) this.unregisteredCompViolations += 1;
          if (!budgetOk) this.budgetViolations += 1;
        }
        break;
      }
      case 'crashStep1Unknown':
        if (!this.step1Done && !this.step1Unknown && this.compensatorRegistered && this.remainingBudget > 0) {
          this.step1Unknown = true;
          this.remainingBudget -= 1;
          this.spentBudget += 1;
        }
        break;
      case 'reconcileStep1Committed':
        if (this.step1Unknown) {
          this.step1Unknown = false;
          this.step1Done = true;
        }
        break;
      case 'crossIrreversiblePivot':
        if (this.step1Done && !this.pivotCrossed && !this.compensated && this.remainingBudget > 0) {
          this.pivotCrossed = true;
          this.remainingBudget -= 1;
          this.spentBudget += 1;
        }
        break;
      case 'spendExtraCompute':
        if (this.remainingBudget > 0) {
          this.remainingBudget -= 1;
          this.spentBudget += 1;
        }
        break;
      case 'compensateStep1': {
        const rollbackAllowed = this.step1Done && !this.pivotCrossed && !this.step1Unknown;
        if (!this.compensated && rollbackAllowed) {
          this.compensated = true;
          this.step1Done = false;
          if (!rollbackAllowed) this.pivotOrUnknownRollbackViolations += 1;
        }
        break;
      }
      default:
        throw new Error(`Unknown DurableSagaBudgetSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      rootBudget: this.rootBudget,
      remainingBudget: this.remainingBudget,
      spentBudget: this.spentBudget,
      compensatorRegistered: this.compensatorRegistered,
      step1Done: this.step1Done,
      step1Unknown: this.step1Unknown,
      pivotCrossed: this.pivotCrossed,
      compensated: this.compensated,
      budgetViolations: this.budgetViolations,
      unregisteredCompViolations: this.unregisteredCompViolations,
      pivotOrUnknownRollbackViolations: this.pivotOrUnknownRollbackViolations,
    };
  }
}

class BadPivotRollbackSagaSUT extends DurableSagaBudgetSUT {
  override apply(action: string): void {
    if (action === 'compensateStep1' && !this.compensated) {
      // Anti-pattern: drops `forbid-rollback-past-pivot-or-unknown` guard on compensation!
      const rollbackAllowed = this.step1Done && !this.pivotCrossed && !this.step1Unknown;
      this.compensated = true;
      this.step1Done = false;
      if (!rollbackAllowed) this.pivotOrUnknownRollbackViolations += 1;
      return;
    }
    super.apply(action);
  }
}

class DifcExfiltrationFenceSUT {
  secretRead = false;
  untrustedInputRead = false;
  valueTaintedSecret = false;
  controlTaintedUntrusted = false;
  hasDeclassCap = false;
  sanitizerPassed = false;
  declassifiedClean = false;
  exfiltrationViolations = 0;
  controlHijackViolations = 0;
  unauthorizedDeclassViolations = 0;
  safePublicSinks = 0;

  apply(action: string): void {
    switch (action) {
      case 'readSecretSource':
        if (!this.secretRead) {
          this.secretRead = true;
          this.valueTaintedSecret = true;
        }
        break;
      case 'readUntrustedWeb':
        if (!this.untrustedInputRead) {
          this.untrustedInputRead = true;
          this.controlTaintedUntrusted = true;
        }
        break;
      case 'grantDeclassCap':
        if (!this.hasDeclassCap) {
          this.hasDeclassCap = true;
        }
        break;
      case 'runDeterministicSanitizer':
        if (this.valueTaintedSecret && !this.sanitizerPassed) {
          this.sanitizerPassed = true;
        }
        break;
      case 'useTrustedControlTarget':
        if (this.controlTaintedUntrusted) {
          this.controlTaintedUntrusted = false;
        }
        break;
      case 'declassifyValue': {
        const capAndSan = this.hasDeclassCap && this.sanitizerPassed;
        if (this.valueTaintedSecret && !this.declassifiedClean && capAndSan) {
          this.declassifiedClean = true;
          this.valueTaintedSecret = false;
          if (!capAndSan) this.unauthorizedDeclassViolations += 1;
        }
        break;
      }
      case 'emitToPublicSink': {
        const noSecret = !this.valueTaintedSecret;
        const noHijack = !this.controlTaintedUntrusted;
        if (noSecret && noHijack) {
          this.safePublicSinks += 1;
          if (!noSecret) this.exfiltrationViolations += 1;
          if (!noHijack) this.controlHijackViolations += 1;
        }
        break;
      }
      default:
        throw new Error(`Unknown DifcExfiltrationFenceSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      secretRead: this.secretRead,
      untrustedInputRead: this.untrustedInputRead,
      valueTaintedSecret: this.valueTaintedSecret,
      controlTaintedUntrusted: this.controlTaintedUntrusted,
      hasDeclassCap: this.hasDeclassCap,
      sanitizerPassed: this.sanitizerPassed,
      declassifiedClean: this.declassifiedClean,
      exfiltrationViolations: this.exfiltrationViolations,
      controlHijackViolations: this.controlHijackViolations,
      unauthorizedDeclassViolations: this.unauthorizedDeclassViolations,
      safePublicSinks: this.safePublicSinks,
    };
  }
}

class BadExfiltratingAgentSUT extends DifcExfiltrationFenceSUT {
  override apply(action: string): void {
    if (action === 'emitToPublicSink' && !this.controlTaintedUntrusted) {
      // Anti-pattern: drops `forbid-secret-to-public-sink` guard and leaks tainted secret to public sink!
      this.safePublicSinks += 1;
      if (this.valueTaintedSecret) this.exfiltrationViolations += 1;
      return;
    }
    super.apply(action);
  }
}

class DurableMemoryTmsSUT {
  sourceTrusted = false;
  quorumMet = false;
  rootPromoted = false;
  derivedCreated = false;
  derivedActive = false;
  hasAltJustification = false;
  rootRetracted = false;
  poisonedPromotionViolations = 0;
  repoisoningViolations = 0;
  zombieDerivedViolations = 0;
  validReads = 0;

  apply(action: string): void {
    switch (action) {
      case 'markSourceTrusted':
        if (!this.sourceTrusted) this.sourceTrusted = true;
        break;
      case 'achieveIndependentQuorum':
        if (!this.quorumMet) this.quorumMet = true;
        break;
      case 'promoteRootBelief': {
        const trustedQuorum = this.sourceTrusted && this.quorumMet;
        const notRetracted = !this.rootRetracted;
        if (!this.rootPromoted && trustedQuorum && notRetracted) {
          this.rootPromoted = true;
          if (!trustedQuorum) this.poisonedPromotionViolations += 1;
          if (!notRetracted) this.repoisoningViolations += 1;
        }
        break;
      }
      case 'deriveDependentBelief':
        if (this.rootPromoted && !this.derivedCreated) {
          this.derivedCreated = true;
          this.derivedActive = true;
        }
        break;
      case 'attachAltCleanJustification':
        if (this.derivedCreated && !this.hasAltJustification) {
          this.hasAltJustification = true;
          this.derivedActive = true;
        }
        break;
      case 'retractPoisonedRoot':
        if (this.rootPromoted && !this.rootRetracted) {
          this.rootRetracted = true;
          this.rootPromoted = false;
          this.derivedActive = this.hasAltJustification ? this.derivedActive : false;
        }
        break;
      case 'readDerivedBelief': {
        const validSupport = this.derivedActive && (!this.rootRetracted || this.hasAltJustification);
        if (this.derivedCreated && validSupport) {
          this.validReads += 1;
          if (!validSupport) this.zombieDerivedViolations += 1;
        }
        break;
      }
      default:
        throw new Error(`Unknown DurableMemoryTmsSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      sourceTrusted: this.sourceTrusted,
      quorumMet: this.quorumMet,
      rootPromoted: this.rootPromoted,
      derivedCreated: this.derivedCreated,
      derivedActive: this.derivedActive,
      hasAltJustification: this.hasAltJustification,
      rootRetracted: this.rootRetracted,
      poisonedPromotionViolations: this.poisonedPromotionViolations,
      repoisoningViolations: this.repoisoningViolations,
      zombieDerivedViolations: this.zombieDerivedViolations,
      validReads: this.validReads,
    };
  }
}

class BadUnverifiedPromotionSUT extends DurableMemoryTmsSUT {
  override apply(action: string): void {
    if (action === 'promoteRootBelief' && !this.rootPromoted && !this.rootRetracted) {
      // Anti-pattern: drops `require-quorum-and-trusted-source` guard and promotes poisoned claims!
      this.rootPromoted = true;
      if (!(this.sourceTrusted && this.quorumMet)) {
        this.poisonedPromotionViolations += 1;
      }
      return;
    }
    super.apply(action);
  }
}

class TransparencyLogEquivocationSUT {
  sth1Published = false;
  sth2Published = false;
  inclusionProofValid = false;
  consistencyProofValid = false;
  equivocationDetected = false;
  unverifiedEntryAccepts = 0;
  historyRewriteAccepts = 0;
  equivocationAccepts = 0;
  verifiedAudits = 0;

  apply(action: string): void {
    switch (action) {
      case 'publishInitialSth':
        if (!this.sth1Published) this.sth1Published = true;
        break;
      case 'verifyEntryInclusion':
        if (this.sth1Published && !this.inclusionProofValid) this.inclusionProofValid = true;
        break;
      case 'appendConsistentSth2':
        if (this.sth1Published && !this.sth2Published) {
          this.sth2Published = true;
          this.consistencyProofValid = true;
        }
        break;
      case 'attemptHistoryRewrite':
        if (this.sth1Published && !this.sth2Published) {
          this.sth2Published = true;
          this.consistencyProofValid = false;
        }
        break;
      case 'emitSplitViewSth':
        if (this.sth1Published && !this.equivocationDetected) this.equivocationDetected = true;
        break;
      case 'acceptAuditSnapshot': {
        const incOk = this.inclusionProofValid;
        const consOk = this.consistencyProofValid;
        const noEquiv = !this.equivocationDetected;
        if (this.sth2Published && incOk && consOk && noEquiv) {
          this.verifiedAudits += 1;
          if (!incOk) this.unverifiedEntryAccepts += 1;
          if (!consOk) this.historyRewriteAccepts += 1;
          if (!noEquiv) this.equivocationAccepts += 1;
        }
        break;
      }
      default:
        throw new Error(`Unknown TransparencyLogEquivocationSUT action: ${action}`);
    }
  }

  snapshot() {
    return {
      sth1Published: this.sth1Published,
      sth2Published: this.sth2Published,
      inclusionProofValid: this.inclusionProofValid,
      consistencyProofValid: this.consistencyProofValid,
      equivocationDetected: this.equivocationDetected,
      unverifiedEntryAccepts: this.unverifiedEntryAccepts,
      historyRewriteAccepts: this.historyRewriteAccepts,
      equivocationAccepts: this.equivocationAccepts,
      verifiedAudits: this.verifiedAudits,
    };
  }
}

class BadSplitViewAcceptingSUT extends TransparencyLogEquivocationSUT {
  override apply(action: string): void {
    if (action === 'acceptAuditSnapshot' && this.sth2Published) {
      // Anti-pattern: blindly accepts audit snapshot without checking inclusion/consistency/equivocation!
      this.verifiedAudits += 1;
      if (!this.inclusionProofValid) this.unverifiedEntryAccepts += 1;
      if (!this.consistencyProofValid) this.historyRewriteAccepts += 1;
      if (this.equivocationDetected) this.equivocationAccepts += 1;
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

describe('E2.1 Action-Driven MBT SUT State-Machine Refinement (17 Defense Models)', () => {
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

  test('AsyncMerkleCut ITF actions drive AsyncMerkleCutSUT with exact state isomorphism and reject BadLwwMergeSUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      fastCommits: asInt(h.fastCommits),
      slowBlocked: Boolean(h.slowBlocked),
      inFlightMsg: Boolean(h.inFlightMsg),
      channelDrained: Boolean(h.channelDrained),
      branchConflict: Boolean(h.branchConflict),
      activePolicyVer: asInt(h.activePolicyVer),
      verdictPolicyVer: asInt(h.verdictPolicyVer),
      cutConsistent: Boolean(h.cutConsistent),
      droppedChannelCuts: asInt(h.droppedChannelCuts),
      lwwConflictsErased: asInt(h.lwwConflictsErased),
      stalePolicyAdmits: asInt(h.stalePolicyAdmits),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/async-merkle-cut/AsyncMerkleCut.qnt',
      () => new AsyncMerkleCutSUT(),
      projectH,
      () => new BadLwwMergeSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('ByzantineEncryptedStore ITF actions drive ByzantineEncryptedStoreSUT with exact state isomorphism and reject BadBlindReplaySUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      coderCompromised: Boolean(h.coderCompromised),
      goldEncrypted: Boolean(h.goldEncrypted),
      ciphertextTampered: Boolean(h.ciphertextTampered),
      aeadVerified: Boolean(h.aeadVerified),
      upstreamDrifted: Boolean(h.upstreamDrifted),
      memoRevalidated: Boolean(h.memoRevalidated),
      oracleLeaks: asInt(h.oracleLeaks),
      forgedVerdicts: asInt(h.forgedVerdicts),
      driftedReplays: asInt(h.driftedReplays),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/byzantine-encrypted-store/ByzantineEncryptedStore.qnt',
      () => new ByzantineEncryptedStoreSUT(),
      projectH,
      () => new BadBlindReplaySUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('DurableAiContextSsi ITF actions drive DurableAiContextSsiSUT with exact state isomorphism and reject BadWriteSkewMergeSUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      durableEvidenceIntact: Boolean(h.durableEvidenceIntact),
      rawChatCompacted: Boolean(h.rawChatCompacted),
      readWriteSkew: Boolean(h.readWriteSkew),
      activeEpoch: asInt(h.activeEpoch),
      workerEpoch: asInt(h.workerEpoch),
      proseSanitized: Boolean(h.proseSanitized),
      writeSkewMerges: asInt(h.writeSkewMerges),
      fencedCommits: asInt(h.fencedCommits),
      injectedReviews: asInt(h.injectedReviews),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/durable-ai-context-ssi/DurableAiContextSsi.qnt',
      () => new DurableAiContextSsiSUT(),
      projectH,
      () => new BadWriteSkewMergeSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('ReleaseSodRollback ITF actions drive ReleaseSodRollbackSUT with exact state isomorphism and reject BadSelfApprovingReleaseSUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      authorId: asInt(h.authorId),
      approverId: asInt(h.approverId),
      independentAuditPassed: Boolean(h.independentAuditPassed),
      preReleaseCutPinned: Boolean(h.preReleaseCutPinned),
      authorityRevoked: Boolean(h.authorityRevoked),
      canarySloBreached: Boolean(h.canarySloBreached),
      promotedToProd: Boolean(h.promotedToProd),
      rolledBack: Boolean(h.rolledBack),
      forensicHistoryIntact: Boolean(h.forensicHistoryIntact),
      sodViolations: asInt(h.sodViolations),
      unpinnedPromotions: asInt(h.unpinnedPromotions),
      revokedOrBreachedPromotions: asInt(h.revokedOrBreachedPromotions),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/release-sod-rollback/ReleaseSodRollback.qnt',
      () => new ReleaseSodRollbackSUT(),
      projectH,
      () => new BadSelfApprovingReleaseSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('HitlDurableApproval ITF actions drive HitlDurableApprovalSUT with exact state isomorphism and reject BadStaleApprovalResumeSUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      authorId: asInt(h.authorId),
      approverId: asInt(h.approverId),
      suspended: Boolean(h.suspended),
      m3LeaseLeaked: Boolean(h.m3LeaseLeaked),
      baselineVersion: asInt(h.baselineVersion),
      policyEpoch: asInt(h.policyEpoch),
      approvedBaseline: asInt(h.approvedBaseline),
      approvedPolicyEpoch: asInt(h.approvedPolicyEpoch),
      approvalExpired: Boolean(h.approvalExpired),
      humanVetoed: Boolean(h.humanVetoed),
      executedCount: asInt(h.executedCount),
      staleExecutions: asInt(h.staleExecutions),
      vetoOrReplayViolations: asInt(h.vetoOrReplayViolations),
      m3LeakViolations: asInt(h.m3LeakViolations),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/hitl-durable-approval/HitlDurableApproval.qnt',
      () => new HitlDurableApprovalSUT(),
      projectH,
      () => new BadStaleApprovalResumeSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('CapabilityAttenuation ITF actions drive CapabilityAttenuationSUT with exact state isomorphism and reject BadScopeEscalatingDelegateSUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      rootScope: asInt(h.rootScope),
      parentScope: asInt(h.parentScope),
      childScope: asInt(h.childScope),
      delegationDepth: asInt(h.delegationDepth),
      maxDepth: asInt(h.maxDepth),
      parentDelegatable: Boolean(h.parentDelegatable),
      chainMacValid: Boolean(h.chainMacValid),
      ancestorRevoked: Boolean(h.ancestorRevoked),
      escalationViolations: asInt(h.escalationViolations),
      revokedSubtreeExecutions: asInt(h.revokedSubtreeExecutions),
      forgedOrDepthViolations: asInt(h.forgedOrDepthViolations),
      validExecutions: asInt(h.validExecutions),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/capability-attenuation/CapabilityAttenuation.qnt',
      () => new CapabilityAttenuationSUT(),
      projectH,
      () => new BadScopeEscalatingDelegateSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('DurableSagaBudget ITF actions drive DurableSagaBudgetSUT with exact state isomorphism and reject BadPivotRollbackSagaSUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      rootBudget: asInt(h.rootBudget),
      remainingBudget: asInt(h.remainingBudget),
      spentBudget: asInt(h.spentBudget),
      compensatorRegistered: Boolean(h.compensatorRegistered),
      step1Done: Boolean(h.step1Done),
      step1Unknown: Boolean(h.step1Unknown),
      pivotCrossed: Boolean(h.pivotCrossed),
      compensated: Boolean(h.compensated),
      budgetViolations: asInt(h.budgetViolations),
      unregisteredCompViolations: asInt(h.unregisteredCompViolations),
      pivotOrUnknownRollbackViolations: asInt(h.pivotOrUnknownRollbackViolations),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/durable-saga-budget/DurableSagaBudget.qnt',
      () => new DurableSagaBudgetSUT(),
      projectH,
      () => new BadPivotRollbackSagaSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('DifcExfiltrationFence ITF actions drive DifcExfiltrationFenceSUT with exact state isomorphism and reject BadExfiltratingAgentSUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      secretRead: Boolean(h.secretRead),
      untrustedInputRead: Boolean(h.untrustedInputRead),
      valueTaintedSecret: Boolean(h.valueTaintedSecret),
      controlTaintedUntrusted: Boolean(h.controlTaintedUntrusted),
      hasDeclassCap: Boolean(h.hasDeclassCap),
      sanitizerPassed: Boolean(h.sanitizerPassed),
      declassifiedClean: Boolean(h.declassifiedClean),
      exfiltrationViolations: asInt(h.exfiltrationViolations),
      controlHijackViolations: asInt(h.controlHijackViolations),
      unauthorizedDeclassViolations: asInt(h.unauthorizedDeclassViolations),
      safePublicSinks: asInt(h.safePublicSinks),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/difc-exfiltration-fence/DifcExfiltrationFence.qnt',
      () => new DifcExfiltrationFenceSUT(),
      projectH,
      () => new BadExfiltratingAgentSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('DurableMemoryTms ITF actions drive DurableMemoryTmsSUT with exact state isomorphism and reject BadUnverifiedPromotionSUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      sourceTrusted: Boolean(h.sourceTrusted),
      quorumMet: Boolean(h.quorumMet),
      rootPromoted: Boolean(h.rootPromoted),
      derivedCreated: Boolean(h.derivedCreated),
      derivedActive: Boolean(h.derivedActive),
      hasAltJustification: Boolean(h.hasAltJustification),
      rootRetracted: Boolean(h.rootRetracted),
      poisonedPromotionViolations: asInt(h.poisonedPromotionViolations),
      repoisoningViolations: asInt(h.repoisoningViolations),
      zombieDerivedViolations: asInt(h.zombieDerivedViolations),
      validReads: asInt(h.validReads),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/durable-memory-tms/DurableMemoryTms.qnt',
      () => new DurableMemoryTmsSUT(),
      projectH,
      () => new BadUnverifiedPromotionSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);

  test('TransparencyLogEquivocation ITF actions drive TransparencyLogEquivocationSUT with exact state isomorphism and reject BadSplitViewAcceptingSUT', () => {
    const projectH = (h: Record<string, unknown>) => ({
      sth1Published: Boolean(h.sth1Published),
      sth2Published: Boolean(h.sth2Published),
      inclusionProofValid: Boolean(h.inclusionProofValid),
      consistencyProofValid: Boolean(h.consistencyProofValid),
      equivocationDetected: Boolean(h.equivocationDetected),
      unverifiedEntryAccepts: asInt(h.unverifiedEntryAccepts),
      historyRewriteAccepts: asInt(h.historyRewriteAccepts),
      equivocationAccepts: asInt(h.equivocationAccepts),
      verifiedAudits: asInt(h.verifiedAudits),
    });
    const stats = replayModelAgainstSut(
      'packages/quint-models/engineering/defense/transparency-log-equivocation/TransparencyLogEquivocation.qnt',
      () => new TransparencyLogEquivocationSUT(),
      projectH,
      () => new BadSplitViewAcceptingSUT(),
    );
    expect(stats.transitions).toBeGreaterThan(50);
    expect(stats.brokenDiverged).toBe(true);
  }, 30_000);
});

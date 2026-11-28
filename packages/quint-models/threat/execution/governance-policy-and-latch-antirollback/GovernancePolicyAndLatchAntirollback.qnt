// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.governance-policy-and-latch-antirollback
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-unless-missing-context-failopen step=stepForbidUnlessBypass max-steps=6 itf="h.forbidUnlessBypassed > 0"
// @countermodel forbid-same-epoch-policy-revision-rollback step=stepSameEpochRevisionRollback max-steps=6 itf="h.revisionRollbacks > 0"
// @countermodel forbid-same-epoch-estop-checkpoint-replay step=stepSameEpochEstopReplay max-steps=6 itf="h.estopLatchClearedByReplay > 0"
// @countermodel forbid-rearm-resurrecting-retracted-derivation step=stepRearmClearsRetractions max-steps=6 itf="h.retractionResurrections > 0"
// Limits: Finite bounded governance admission, Cedar policy-clause evaluator, and durable circuit-breaker state machine (revocationEpoch <= 3, policyRevision <= 3, stepCount <= 12); models fail-closed Cedar forbid-unless missing-context semantics, same-epoch policy_revision anti-rollback, same-epoch E-Stop checkpoint anti-untrip, and Bi-Temporal Truth Maintenance retraction persistence across human re-arm, without modeling cryptographic SHA-256 collision attacks or OS kernel compromise.
module execution_governance_policy_and_latch_antirollback {
  type State = { revocationEpoch: int, policyRevision: int, estopTripped: bool, retractedHeld: bool, forbidActive: bool, forbidUnlessBypassed: int, revisionRollbacks: int, estopLatchClearedByReplay: int, retractionResurrections: int, cleanGovernedOps: int, stepCount: int }
  var h: State
  action init = h' = { revocationEpoch: 1, policyRevision: 0, estopTripped: false, retractedHeld: false, forbidActive: false, forbidUnlessBypassed: 0, revisionRollbacks: 0, estopLatchClearedByReplay: 0, retractionResurrections: 0, cleanGovernedOps: 0, stepCount: 0 }
  action installForbidAndAdvanceRev = if ((h.stepCount < 12 and h.policyRevision < 3)) h' = h.with("policyRevision", (h.policyRevision + 1)).with("forbidActive", true).with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action retractDerivationAndTripEstop = if ((h.stepCount < 12 and not(h.retractedHeld))) h' = h.with("retractedHeld", true).with("estopTripped", true).with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action evalForbidMissingContextFailClosed = if ((h.stepCount < 12 and h.forbidActive)) h' = h.with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action rejectSameEpochRollbackReplay = if ((h.stepCount < 12 and h.policyRevision > 0)) h' = h.with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action humanRearmPreservingRetractions = if ((h.stepCount < 12 and h.estopTripped and h.revocationEpoch < 3)) h' = h.with("estopTripped", false).with("revocationEpoch", (h.revocationEpoch + 1)).with("policyRevision", 0).with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action restoreCheckpointMonotonic = if ((h.stepCount < 12 and not(h.estopTripped))) h' = h.with("cleanGovernedOps", (h.cleanGovernedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action tripOperatorEstop = if ((h.stepCount < 12 and not(h.estopTripped))) h' = h.with("estopTripped", true).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { installForbidAndAdvanceRev, retractDerivationAndTripEstop, evalForbidMissingContextFailClosed, rejectSameEpochRollbackReplay, humanRearmPreservingRetractions, restoreCheckpointMonotonic, tripOperatorEstop }
  val safety = (h.forbidUnlessBypassed == 0 and h.revisionRollbacks == 0 and h.estopLatchClearedByReplay == 0 and h.retractionResurrections == 0 and h.revocationEpoch >= 1 and h.revocationEpoch <= 3 and h.policyRevision >= 0 and h.policyRevision <= 3 and h.stepCount <= 12)
  // Countermodel threat.execution.governance-policy-and-latch-antirollback.forbid-unless-bypass (dropped guard: forbid-unless-missing-context-failopen)
  action exploitForbidUnlessMissingContext = if ((h.stepCount < 12 and h.forbidActive)) h' = h.with("forbidUnlessBypassed", (h.forbidUnlessBypassed + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepForbidUnlessBypass = any { step, exploitForbidUnlessMissingContext }
  // Countermodel threat.execution.governance-policy-and-latch-antirollback.same-epoch-revision-rollback (dropped guard: forbid-same-epoch-policy-revision-rollback)
  action exploitSameEpochRevisionRollback = if ((h.stepCount < 12 and h.policyRevision > 0)) h' = h.with("policyRevision", (h.policyRevision - 1)).with("forbidActive", false).with("revisionRollbacks", (h.revisionRollbacks + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepSameEpochRevisionRollback = any { step, exploitSameEpochRevisionRollback }
  // Countermodel threat.execution.governance-policy-and-latch-antirollback.same-epoch-estop-replay (dropped guard: forbid-same-epoch-estop-checkpoint-replay)
  action exploitSameEpochEstopCheckpointReplay = if ((h.stepCount < 12 and h.estopTripped)) h' = h.with("estopTripped", false).with("estopLatchClearedByReplay", (h.estopLatchClearedByReplay + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepSameEpochEstopReplay = any { step, exploitSameEpochEstopCheckpointReplay }
  // Countermodel threat.execution.governance-policy-and-latch-antirollback.rearm-clears-retractions (dropped guard: forbid-rearm-resurrecting-retracted-derivation)
  action exploitRearmClearsRetractions = if ((h.stepCount < 12 and h.estopTripped and h.retractedHeld)) h' = h.with("estopTripped", false).with("retractedHeld", false).with("retractionResurrections", (h.retractionResurrections + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepRearmClearsRetractions = any { step, exploitRearmClearsRetractions }
  action checkSm29Safe = all { assert(safety), assert(h.cleanGovernedOps > 0), h' = h }
  action checkSm29Violated = all { assert((h.forbidUnlessBypassed > 0 or h.revisionRollbacks > 0 or h.estopLatchClearedByReplay > 0 or h.retractionResurrections > 0)), assert(not(safety)), h' = h }
  run cleanGovernedLatchAndPolicySafeTest = init.then(installForbidAndAdvanceRev).then(evalForbidMissingContextFailClosed).then(rejectSameEpochRollbackReplay).then(retractDerivationAndTripEstop).then(humanRearmPreservingRetractions).then(restoreCheckpointMonotonic).then(checkSm29Safe)
  run forbidUnlessBypassRefutedTest = init.then(installForbidAndAdvanceRev).then(exploitForbidUnlessMissingContext).then(checkSm29Violated)
  run sameEpochRevisionRollbackRefutedTest = init.then(installForbidAndAdvanceRev).then(exploitSameEpochRevisionRollback).then(checkSm29Violated)
  run sameEpochEstopReplayRefutedTest = init.then(tripOperatorEstop).then(exploitSameEpochEstopCheckpointReplay).then(checkSm29Violated)
  run rearmClearsRetractionsRefutedTest = init.then(retractDerivationAndTripEstop).then(exploitRearmClearsRetractions).then(checkSm29Violated)
}

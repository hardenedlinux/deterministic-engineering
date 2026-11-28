// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.witness-epoch-reconfiguration
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-dual-quorum-handover step=stepUnilateralHandover max-steps=6 itf="h.unilateralHandoverViolations > 0"
// @countermodel require-anchor-consistency-for-epoch2 step=stepUnanchoredEpoch2 max-steps=6 itf="h.unanchoredEpoch2Violations > 0"
// @countermodel enforce-monotonic-pinned-epoch step=stepLongRangeFork max-steps=6 itf="h.longRangeRewriteViolations > 0"
// Limits: Two-epoch (Epoch 1 -> Epoch 2) dynamic committee handover abstraction; assumes offline/out-of-band verifier pinning of the handover epoch (weak subjectivity) to defeat posterior corruption of retired Epoch 1 keys.
module witness_epoch_reconfiguration {
  type State = { activeEpoch: int, pinnedEpoch: int, epoch1CheckpointCount: int, oldQuorumSignedHandover: bool, newQuorumSignedHandover: bool, oldKeysZeroized: bool, oldKeysPosteriorCompromised: bool, anchorConsistencyVerified: bool, epoch2CleanFinalized: bool, epoch1PostHandoverForkAccepted: bool, unilateralHandoverViolations: int, unanchoredEpoch2Violations: int, longRangeRewriteViolations: int }
  var h: State
  action init = h' = { activeEpoch: 1, pinnedEpoch: 1, epoch1CheckpointCount: 0, oldQuorumSignedHandover: false, newQuorumSignedHandover: false, oldKeysZeroized: false, oldKeysPosteriorCompromised: false, anchorConsistencyVerified: false, epoch2CleanFinalized: false, epoch1PostHandoverForkAccepted: false, unilateralHandoverViolations: 0, unanchoredEpoch2Violations: 0, longRangeRewriteViolations: 0 }
  action acceptEpoch1Checkpoint = if ((not(h.epoch1PostHandoverForkAccepted) and (h.epoch1CheckpointCount == 0 or h.pinnedEpoch >= 2) and h.pinnedEpoch == 1)) h' = h.with("epoch1CheckpointCount", (h.epoch1CheckpointCount + 1)).with("epoch1PostHandoverForkAccepted", if (h.pinnedEpoch == 1) h.epoch1PostHandoverForkAccepted else true).with("longRangeRewriteViolations", if (h.pinnedEpoch == 1) h.longRangeRewriteViolations else (h.longRangeRewriteViolations + 1)) else h' = h
  action oldQuorumSignHandover = if (not(h.oldQuorumSignedHandover)) h' = h.with("oldQuorumSignedHandover", true) else h' = h
  action newQuorumSignHandover = if (not(h.newQuorumSignedHandover)) h' = h.with("newQuorumSignedHandover", true) else h' = h
  action completeJointHandover = if ((h.activeEpoch == 1 and (h.oldQuorumSignedHandover and h.newQuorumSignedHandover))) h' = h.with("activeEpoch", 2).with("pinnedEpoch", 2).with("unilateralHandoverViolations", if ((h.oldQuorumSignedHandover and h.newQuorumSignedHandover)) h.unilateralHandoverViolations else (h.unilateralHandoverViolations + 1)) else h' = h
  action zeroizeRetiredOldKeys = if ((h.activeEpoch >= 2 and not(h.oldKeysZeroized))) h' = h.with("oldKeysZeroized", true) else h' = h
  action adversaryCompromiseRetiredOldKeys = if ((h.activeEpoch >= 2 and not(h.oldKeysPosteriorCompromised))) h' = h.with("oldKeysPosteriorCompromised", true) else h' = h
  action verifyEpoch2AnchorConsistency = if ((h.activeEpoch >= 2 and not(h.anchorConsistencyVerified))) h' = h.with("anchorConsistencyVerified", true) else h' = h
  action finalizeEpoch2Checkpoint = if ((h.activeEpoch >= 2 and not(h.epoch2CleanFinalized) and h.anchorConsistencyVerified)) h' = h.with("epoch2CleanFinalized", true).with("unanchoredEpoch2Violations", if (h.anchorConsistencyVerified) h.unanchoredEpoch2Violations else (h.unanchoredEpoch2Violations + 1)) else h' = h
  action step = any { acceptEpoch1Checkpoint, oldQuorumSignHandover, newQuorumSignHandover, completeJointHandover, zeroizeRetiredOldKeys, adversaryCompromiseRetiredOldKeys, verifyEpoch2AnchorConsistency, finalizeEpoch2Checkpoint }
  val safety = (not((h.epoch2CleanFinalized and h.epoch1PostHandoverForkAccepted)) and h.unilateralHandoverViolations == 0 and h.unanchoredEpoch2Violations == 0 and h.longRangeRewriteViolations == 0)
  // Countermodel engineering.defense.witness-epoch-reconfiguration.unilateral-handover (dropped guard: require-dual-quorum-handover)
  action completeUnilateralHandover = if ((h.activeEpoch == 1 and true)) h' = h.with("activeEpoch", 2).with("pinnedEpoch", 2).with("unilateralHandoverViolations", if ((h.oldQuorumSignedHandover and h.newQuorumSignedHandover)) h.unilateralHandoverViolations else (h.unilateralHandoverViolations + 1)) else h' = h
  action stepUnilateralHandover = any { step, completeUnilateralHandover }
  // Countermodel engineering.defense.witness-epoch-reconfiguration.unanchored-epoch2 (dropped guard: require-anchor-consistency-for-epoch2)
  action finalizeEpoch2Unanchored = if ((h.activeEpoch >= 2 and not(h.epoch2CleanFinalized) and true)) h' = h.with("epoch2CleanFinalized", true).with("unanchoredEpoch2Violations", if (h.anchorConsistencyVerified) h.unanchoredEpoch2Violations else (h.unanchoredEpoch2Violations + 1)) else h' = h
  action stepUnanchoredEpoch2 = any { step, finalizeEpoch2Unanchored }
  // Countermodel engineering.defense.witness-epoch-reconfiguration.long-range-fork (dropped guard: enforce-monotonic-pinned-epoch)
  action acceptEpoch1PostPin = if ((not(h.epoch1PostHandoverForkAccepted) and (h.epoch1CheckpointCount == 0 or h.pinnedEpoch >= 2) and true)) h' = h.with("epoch1CheckpointCount", (h.epoch1CheckpointCount + 1)).with("epoch1PostHandoverForkAccepted", if (h.pinnedEpoch == 1) h.epoch1PostHandoverForkAccepted else true).with("longRangeRewriteViolations", if (h.pinnedEpoch == 1) h.longRangeRewriteViolations else (h.longRangeRewriteViolations + 1)) else h' = h
  action stepLongRangeFork = any { step, acceptEpoch1PostPin }
  run jointHandoverAndForwardSealingTest = init.then(acceptEpoch1Checkpoint).then(oldQuorumSignHandover).then(newQuorumSignHandover).then(completeJointHandover).then(zeroizeRetiredOldKeys).then(adversaryCompromiseRetiredOldKeys).then(verifyEpoch2AnchorConsistency).then(finalizeEpoch2Checkpoint).then(acceptEpoch1Checkpoint).then(all { assert(safety), assert(h.activeEpoch == 2), assert(h.epoch2CleanFinalized), assert(not(h.epoch1PostHandoverForkAccepted)), h' = h })
  run unilateralHandoverViolatesSafetyTest = init.then(oldQuorumSignHandover).then(completeUnilateralHandover).then(all { assert(not(safety)), assert(h.unilateralHandoverViolations > 0), h' = h })
  run unanchoredEpoch2ViolatesSafetyTest = init.then(oldQuorumSignHandover).then(newQuorumSignHandover).then(completeJointHandover).then(finalizeEpoch2Unanchored).then(all { assert(not(safety)), assert(h.unanchoredEpoch2Violations > 0), h' = h })
  run longRangeForkViolatesSafetyTest = init.then(oldQuorumSignHandover).then(newQuorumSignHandover).then(completeJointHandover).then(adversaryCompromiseRetiredOldKeys).then(acceptEpoch1PostPin).then(all { assert(not(safety)), assert(h.longRangeRewriteViolations > 0), h' = h })
}

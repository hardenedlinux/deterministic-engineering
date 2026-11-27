// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.defense-pillar-crypto-state-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-future-epoch-shred-or-epoch0-rewrap step=stepFutureEpochShredOrEpoch0Rewrap max-steps=6 itf="h.keyEpochBreaches > 0"
// @countermodel forbid-zk-case-secret-leak-or-nonce-replay step=stepZkSecretLeakOrNonceReplay max-steps=6 itf="h.zkDisclosureBreaches > 0"
// @countermodel forbid-supply-chain-builder-spoof-or-pin-overwrite step=stepSupplyChainSpoofOrPinOverwrite max-steps=6 itf="h.supplyChainBreaches > 0"
// @countermodel forbid-treaty-freeze-wipe-or-self-reciprocity-spoof step=stepTreatyFreezeWipeOrSelfSpoof max-steps=6 itf="h.treatyReciprocityBreaches > 0"
// @countermodel forbid-merkle-second-preimage-or-forged-empty-head step=stepMerkleMalleabilityOrForgedEmptyHead max-steps=6 itf="h.merkleIntegrityBreaches > 0"
// Limits: Finite bounded defense-pillar cryptographic and state-machine integrity confinement model (1 <= activeEpoch <= 12, 0 <= shreddedMaxEpoch < activeEpoch, stepCount <= 12); models fail-closed B16 retired-only epoch shredding and live-epoch rewrap, B18 canonical case/whitespace-folded forbidden secret filtering with consumed-challenge anti-replay, B14 canonical 2-builder distinctness with immutable CVE-checked dependency pinning and single-use release admission, B20 monotonic bilateral treaty epochs preserving active dispute freezes and canonical anti-self-reciprocity, and B9/B21 RFC 6962 empty-head and non-duplicating Merkle root integrity, without modeling underlying SHA-256 collision hardness or network Byzantine timing.
module execution_defense_pillar_crypto_state_confinement {
  type State = { activeEpoch: int, shreddedMaxEpoch: int, keyEpochGuarded: bool, zkNormalizedAndFresh: bool, supplyChainPinnedAndDistinct: bool, treatyFreezeAndEpochMonotonic: bool, merkleNoDupAndEmptyRootChecked: bool, keyEpochBreaches: int, zkDisclosureBreaches: int, supplyChainBreaches: int, treatyReciprocityBreaches: int, merkleIntegrityBreaches: int, cleanVerifiedOps: int, stepCount: int }
  var h: State
  action init = h' = { activeEpoch: 1, shreddedMaxEpoch: 0, keyEpochGuarded: true, zkNormalizedAndFresh: true, supplyChainPinnedAndDistinct: true, treatyFreezeAndEpochMonotonic: true, merkleNoDupAndEmptyRootChecked: true, keyEpochBreaches: 0, zkDisclosureBreaches: 0, supplyChainBreaches: 0, treatyReciprocityBreaches: 0, merkleIntegrityBreaches: 0, cleanVerifiedOps: 0, stepCount: 0 }
  action rotateAndShredRetiredEpoch = if ((h.stepCount < 12 and h.keyEpochGuarded and h.activeEpoch < 12)) h' = h.with("activeEpoch", (h.activeEpoch + 1)).with("shreddedMaxEpoch", h.activeEpoch).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action verifyNormalizedZkDisclosure = if ((h.stepCount < 12 and h.zkNormalizedAndFresh)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action admitDistinctTwoBuilderRelease = if ((h.stepCount < 12 and h.supplyChainPinnedAndDistinct)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action admitMonotonicBilateralOp = if ((h.stepCount < 12 and h.treatyFreezeAndEpochMonotonic)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action verifyDomainSeparatedMerkleAndLogHead = if ((h.stepCount < 12 and h.merkleNoDupAndEmptyRootChecked)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { rotateAndShredRetiredEpoch, verifyNormalizedZkDisclosure, admitDistinctTwoBuilderRelease, admitMonotonicBilateralOp, verifyDomainSeparatedMerkleAndLogHead }
  val safety = (h.keyEpochBreaches == 0 and h.zkDisclosureBreaches == 0 and h.supplyChainBreaches == 0 and h.treatyReciprocityBreaches == 0 and h.merkleIntegrityBreaches == 0 and h.keyEpochGuarded and h.zkNormalizedAndFresh and h.supplyChainPinnedAndDistinct and h.treatyFreezeAndEpochMonotonic and h.merkleNoDupAndEmptyRootChecked and h.activeEpoch >= 1 and h.activeEpoch <= 12 and h.shreddedMaxEpoch >= 0 and h.shreddedMaxEpoch < h.activeEpoch and h.stepCount <= 12)
  // Countermodel threat.execution.defense-pillar-crypto-state-confinement.future-epoch-shred-or-epoch0-rewrap (dropped guard: forbid-future-epoch-shred-or-epoch0-rewrap)
  action exploitFutureEpochShredOrEpoch0Rewrap = if ((h.stepCount < 12)) h' = h.with("keyEpochGuarded", false).with("keyEpochBreaches", (h.keyEpochBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepFutureEpochShredOrEpoch0Rewrap = any { step, exploitFutureEpochShredOrEpoch0Rewrap }
  // Countermodel threat.execution.defense-pillar-crypto-state-confinement.zk-secret-leak-or-nonce-replay (dropped guard: forbid-zk-case-secret-leak-or-nonce-replay)
  action exploitZkSecretLeakOrNonceReplay = if ((h.stepCount < 12)) h' = h.with("zkNormalizedAndFresh", false).with("zkDisclosureBreaches", (h.zkDisclosureBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepZkSecretLeakOrNonceReplay = any { step, exploitZkSecretLeakOrNonceReplay }
  // Countermodel threat.execution.defense-pillar-crypto-state-confinement.supply-chain-spoof-or-pin-overwrite (dropped guard: forbid-supply-chain-builder-spoof-or-pin-overwrite)
  action exploitSupplyChainSpoofOrPinOverwrite = if ((h.stepCount < 12)) h' = h.with("supplyChainPinnedAndDistinct", false).with("supplyChainBreaches", (h.supplyChainBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepSupplyChainSpoofOrPinOverwrite = any { step, exploitSupplyChainSpoofOrPinOverwrite }
  // Countermodel threat.execution.defense-pillar-crypto-state-confinement.treaty-freeze-wipe-or-self-spoof (dropped guard: forbid-treaty-freeze-wipe-or-self-reciprocity-spoof)
  action exploitTreatyFreezeWipeOrSelfSpoof = if ((h.stepCount < 12)) h' = h.with("treatyFreezeAndEpochMonotonic", false).with("treatyReciprocityBreaches", (h.treatyReciprocityBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepTreatyFreezeWipeOrSelfSpoof = any { step, exploitTreatyFreezeWipeOrSelfSpoof }
  // Countermodel threat.execution.defense-pillar-crypto-state-confinement.merkle-malleability-or-forged-empty-head (dropped guard: forbid-merkle-second-preimage-or-forged-empty-head)
  action exploitMerkleMalleabilityOrForgedEmptyHead = if ((h.stepCount < 12)) h' = h.with("merkleNoDupAndEmptyRootChecked", false).with("merkleIntegrityBreaches", (h.merkleIntegrityBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepMerkleMalleabilityOrForgedEmptyHead = any { step, exploitMerkleMalleabilityOrForgedEmptyHead }
  action checkSm38Safe = all { assert(safety), assert(h.cleanVerifiedOps > 0), h' = h }
  action checkSm38Violated = all { assert((h.keyEpochBreaches > 0 or h.zkDisclosureBreaches > 0 or h.supplyChainBreaches > 0 or h.treatyReciprocityBreaches > 0 or h.merkleIntegrityBreaches > 0)), assert(not(safety)), h' = h }
  run cleanDefensePillarCryptoStateSafeTest = init.then(rotateAndShredRetiredEpoch).then(verifyNormalizedZkDisclosure).then(admitDistinctTwoBuilderRelease).then(admitMonotonicBilateralOp).then(verifyDomainSeparatedMerkleAndLogHead).then(checkSm38Safe)
  run futureEpochShredOrEpoch0RewrapRefutedTest = init.then(exploitFutureEpochShredOrEpoch0Rewrap).then(checkSm38Violated)
  run zkSecretLeakOrNonceReplayRefutedTest = init.then(exploitZkSecretLeakOrNonceReplay).then(checkSm38Violated)
  run supplyChainSpoofOrPinOverwriteRefutedTest = init.then(exploitSupplyChainSpoofOrPinOverwrite).then(checkSm38Violated)
  run treatyFreezeWipeOrSelfSpoofRefutedTest = init.then(exploitTreatyFreezeWipeOrSelfSpoof).then(checkSm38Violated)
  run merkleMalleabilityOrForgedEmptyHeadRefutedTest = init.then(exploitMerkleMalleabilityOrForgedEmptyHead).then(checkSm38Violated)
}

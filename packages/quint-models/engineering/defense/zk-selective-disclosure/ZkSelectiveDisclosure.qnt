// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.zk-selective-disclosure
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-no-secret-exposure step=stepOverDisclosure max-steps=6 itf="h.overDisclosureViolations > 0"
// @countermodel require-valid-sigma-proof step=stepForgedSigma max-steps=6 itf="h.forgedSigmaViolations > 0"
// @countermodel require-fresh-nullifier step=stepNullifierReplay max-steps=6 itf="h.nullifierReplayViolations > 0"
// Limits: Bounded selective-disclosure and single-slot nullifier freshness abstraction; unbounded forbidden/required attribute lists, challenge-nonce binding, and commitment roots are proved in ZeroKnowledgeSelectiveDisclosure.lean.
module zk_selective_disclosure {
  type State = { secretFieldExposed: bool, sigmaProofValid: bool, nullifierFresh: bool, verifiedDisclosures: int, overDisclosureViolations: int, forgedSigmaViolations: int, nullifierReplayViolations: int }
  var h: State
  action init = h' = { secretFieldExposed: false, sigmaProofValid: false, nullifierFresh: false, verifiedDisclosures: 0, overDisclosureViolations: 0, forgedSigmaViolations: 0, nullifierReplayViolations: 0 }
  action exposeSecretField = if (not(h.secretFieldExposed)) h' = h.with("secretFieldExposed", true) else h' = h
  action redactSecretField = if (h.secretFieldExposed) h' = h.with("secretFieldExposed", false) else h' = h
  action verifySigmaProof = if (not(h.sigmaProofValid)) h' = h.with("sigmaProofValid", true) else h' = h
  action issueFreshNullifier = if (not(h.nullifierFresh)) h' = h.with("nullifierFresh", true) else h' = h
  action admitZkDisclosure = if ((h.verifiedDisclosures < 2 and not(h.secretFieldExposed) and h.sigmaProofValid and h.nullifierFresh)) h' = h.with("verifiedDisclosures", (h.verifiedDisclosures + 1)).with("nullifierFresh", false).with("overDisclosureViolations", if (not(h.secretFieldExposed)) h.overDisclosureViolations else (h.overDisclosureViolations + 1)).with("forgedSigmaViolations", if (h.sigmaProofValid) h.forgedSigmaViolations else (h.forgedSigmaViolations + 1)).with("nullifierReplayViolations", if (h.nullifierFresh) h.nullifierReplayViolations else (h.nullifierReplayViolations + 1)) else h' = h
  action step = any { exposeSecretField, redactSecretField, verifySigmaProof, issueFreshNullifier, admitZkDisclosure }
  val safety = (h.overDisclosureViolations == 0 and h.forgedSigmaViolations == 0 and h.nullifierReplayViolations == 0)
  // Countermodel engineering.defense.zk-selective-disclosure.over-disclosure (dropped guard: require-no-secret-exposure)
  action admitDisclosureOverExposed = if ((h.verifiedDisclosures < 2 and true and h.sigmaProofValid and h.nullifierFresh)) h' = h.with("verifiedDisclosures", (h.verifiedDisclosures + 1)).with("nullifierFresh", false).with("overDisclosureViolations", if (not(h.secretFieldExposed)) h.overDisclosureViolations else (h.overDisclosureViolations + 1)).with("forgedSigmaViolations", if (h.sigmaProofValid) h.forgedSigmaViolations else (h.forgedSigmaViolations + 1)).with("nullifierReplayViolations", if (h.nullifierFresh) h.nullifierReplayViolations else (h.nullifierReplayViolations + 1)) else h' = h
  action stepOverDisclosure = any { step, admitDisclosureOverExposed }
  // Countermodel engineering.defense.zk-selective-disclosure.forged-sigma (dropped guard: require-valid-sigma-proof)
  action admitDisclosureForgedSigma = if ((h.verifiedDisclosures < 2 and not(h.secretFieldExposed) and true and h.nullifierFresh)) h' = h.with("verifiedDisclosures", (h.verifiedDisclosures + 1)).with("nullifierFresh", false).with("overDisclosureViolations", if (not(h.secretFieldExposed)) h.overDisclosureViolations else (h.overDisclosureViolations + 1)).with("forgedSigmaViolations", if (h.sigmaProofValid) h.forgedSigmaViolations else (h.forgedSigmaViolations + 1)).with("nullifierReplayViolations", if (h.nullifierFresh) h.nullifierReplayViolations else (h.nullifierReplayViolations + 1)) else h' = h
  action stepForgedSigma = any { step, admitDisclosureForgedSigma }
  // Countermodel engineering.defense.zk-selective-disclosure.nullifier-replay (dropped guard: require-fresh-nullifier)
  action admitDisclosureNullifierReplay = if ((h.verifiedDisclosures < 2 and not(h.secretFieldExposed) and h.sigmaProofValid and true)) h' = h.with("verifiedDisclosures", (h.verifiedDisclosures + 1)).with("nullifierFresh", false).with("overDisclosureViolations", if (not(h.secretFieldExposed)) h.overDisclosureViolations else (h.overDisclosureViolations + 1)).with("forgedSigmaViolations", if (h.sigmaProofValid) h.forgedSigmaViolations else (h.forgedSigmaViolations + 1)).with("nullifierReplayViolations", if (h.nullifierFresh) h.nullifierReplayViolations else (h.nullifierReplayViolations + 1)) else h' = h
  action stepNullifierReplay = any { step, admitDisclosureNullifierReplay }
  run cleanZkDisclosureTest = init.then(verifySigmaProof).then(issueFreshNullifier).then(admitZkDisclosure).then(all { assert(safety), assert(h.verifiedDisclosures == 1), assert(not(h.nullifierFresh)), h' = h })
  run overDisclosureViolatesSafetyTest = init.then(exposeSecretField).then(verifySigmaProof).then(issueFreshNullifier).then(admitDisclosureOverExposed).then(all { assert(not(safety)), assert(h.overDisclosureViolations > 0), h' = h })
  run forgedSigmaViolatesSafetyTest = init.then(issueFreshNullifier).then(admitDisclosureForgedSigma).then(all { assert(not(safety)), assert(h.forgedSigmaViolations > 0), h' = h })
  run nullifierReplayViolatesSafetyTest = init.then(verifySigmaProof).then(admitDisclosureNullifierReplay).then(all { assert(not(safety)), assert(h.nullifierReplayViolations > 0), h' = h })
}

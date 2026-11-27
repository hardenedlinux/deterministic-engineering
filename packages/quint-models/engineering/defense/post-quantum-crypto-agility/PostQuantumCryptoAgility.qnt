// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.post-quantum-crypto-agility
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-hybrid-suite-floor step=stepDowngrade max-steps=6 itf="h.downgradeViolations > 0"
// @countermodel require-dual-and-legs step=stepSingleLeg max-steps=6 itf="h.singleLegBypassViolations > 0"
// @countermodel require-fresh-ots-leaf step=stepOtsReuse max-steps=6 itf="h.otsReuseViolations > 0"
// Limits: Bounded 2-suite agility and single-slot OTS leaf freshness abstraction; arbitrary deprecated suites, domain separation tags, and unbounded Merkle OTS indices are proved in PostQuantumCryptoAgility.lean.
module post_quantum_crypto_agility {
  type State = { suiteLevel: int, classicalLegValid: bool, pqLegValid: bool, otsLeafFresh: bool, verifiedCerts: int, downgradeViolations: int, singleLegBypassViolations: int, otsReuseViolations: int }
  var h: State
  action init = h' = { suiteLevel: 2, classicalLegValid: false, pqLegValid: false, otsLeafFresh: false, verifiedCerts: 0, downgradeViolations: 0, singleLegBypassViolations: 0, otsReuseViolations: 0 }
  action attemptSuiteDowngrade = if (h.suiteLevel == 2) h' = h.with("suiteLevel", 1) else h' = h
  action restoreHybridSuite = if (h.suiteLevel == 1) h' = h.with("suiteLevel", 2) else h' = h
  action verifyClassicalLeg = if (not(h.classicalLegValid)) h' = h.with("classicalLegValid", true) else h' = h
  action verifyPqLeg = if (not(h.pqLegValid)) h' = h.with("pqLegValid", true) else h' = h
  action allocateFreshOtsLeaf = if (not(h.otsLeafFresh)) h' = h.with("otsLeafFresh", true) else h' = h
  action acceptHybridEnvelope = if ((h.verifiedCerts < 2 and h.suiteLevel >= 2 and (h.classicalLegValid and h.pqLegValid) and h.otsLeafFresh)) h' = h.with("verifiedCerts", (h.verifiedCerts + 1)).with("otsLeafFresh", false).with("downgradeViolations", if (h.suiteLevel >= 2) h.downgradeViolations else (h.downgradeViolations + 1)).with("singleLegBypassViolations", if ((h.classicalLegValid and h.pqLegValid)) h.singleLegBypassViolations else (h.singleLegBypassViolations + 1)).with("otsReuseViolations", if (h.otsLeafFresh) h.otsReuseViolations else (h.otsReuseViolations + 1)) else h' = h
  action step = any { attemptSuiteDowngrade, restoreHybridSuite, verifyClassicalLeg, verifyPqLeg, allocateFreshOtsLeaf, acceptHybridEnvelope }
  val safety = (h.downgradeViolations == 0 and h.singleLegBypassViolations == 0 and h.otsReuseViolations == 0)
  // Countermodel engineering.defense.post-quantum-crypto-agility.suite-downgrade (dropped guard: require-hybrid-suite-floor)
  action acceptEnvelopeDowngraded = if ((h.verifiedCerts < 2 and true and (h.classicalLegValid and h.pqLegValid) and h.otsLeafFresh)) h' = h.with("verifiedCerts", (h.verifiedCerts + 1)).with("otsLeafFresh", false).with("downgradeViolations", if (h.suiteLevel >= 2) h.downgradeViolations else (h.downgradeViolations + 1)).with("singleLegBypassViolations", if ((h.classicalLegValid and h.pqLegValid)) h.singleLegBypassViolations else (h.singleLegBypassViolations + 1)).with("otsReuseViolations", if (h.otsLeafFresh) h.otsReuseViolations else (h.otsReuseViolations + 1)) else h' = h
  action stepDowngrade = any { step, acceptEnvelopeDowngraded }
  // Countermodel engineering.defense.post-quantum-crypto-agility.single-leg-bypass (dropped guard: require-dual-and-legs)
  action acceptEnvelopeSingleLeg = if ((h.verifiedCerts < 2 and h.suiteLevel >= 2 and true and h.otsLeafFresh)) h' = h.with("verifiedCerts", (h.verifiedCerts + 1)).with("otsLeafFresh", false).with("downgradeViolations", if (h.suiteLevel >= 2) h.downgradeViolations else (h.downgradeViolations + 1)).with("singleLegBypassViolations", if ((h.classicalLegValid and h.pqLegValid)) h.singleLegBypassViolations else (h.singleLegBypassViolations + 1)).with("otsReuseViolations", if (h.otsLeafFresh) h.otsReuseViolations else (h.otsReuseViolations + 1)) else h' = h
  action stepSingleLeg = any { step, acceptEnvelopeSingleLeg }
  // Countermodel engineering.defense.post-quantum-crypto-agility.ots-leaf-reuse (dropped guard: require-fresh-ots-leaf)
  action acceptEnvelopeOtsReuse = if ((h.verifiedCerts < 2 and h.suiteLevel >= 2 and (h.classicalLegValid and h.pqLegValid) and true)) h' = h.with("verifiedCerts", (h.verifiedCerts + 1)).with("otsLeafFresh", false).with("downgradeViolations", if (h.suiteLevel >= 2) h.downgradeViolations else (h.downgradeViolations + 1)).with("singleLegBypassViolations", if ((h.classicalLegValid and h.pqLegValid)) h.singleLegBypassViolations else (h.singleLegBypassViolations + 1)).with("otsReuseViolations", if (h.otsLeafFresh) h.otsReuseViolations else (h.otsReuseViolations + 1)) else h' = h
  action stepOtsReuse = any { step, acceptEnvelopeOtsReuse }
  run cleanHybridEnvelopeTest = init.then(verifyClassicalLeg).then(verifyPqLeg).then(allocateFreshOtsLeaf).then(acceptHybridEnvelope).then(all { assert(safety), assert(h.verifiedCerts == 1), assert(not(h.otsLeafFresh)), h' = h })
  run downgradeViolatesSafetyTest = init.then(attemptSuiteDowngrade).then(verifyClassicalLeg).then(verifyPqLeg).then(allocateFreshOtsLeaf).then(acceptEnvelopeDowngraded).then(all { assert(not(safety)), assert(h.downgradeViolations > 0), h' = h })
  run singleLegViolatesSafetyTest = init.then(verifyClassicalLeg).then(allocateFreshOtsLeaf).then(acceptEnvelopeSingleLeg).then(all { assert(not(safety)), assert(h.singleLegBypassViolations > 0), h' = h })
  run otsReuseViolatesSafetyTest = init.then(verifyClassicalLeg).then(verifyPqLeg).then(acceptEnvelopeOtsReuse).then(all { assert(not(safety)), assert(h.otsReuseViolations > 0), h' = h })
}

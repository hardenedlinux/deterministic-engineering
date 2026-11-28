// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.durable-memory-tms
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-quorum-and-trusted-source step=stepPoisonedPromotion max-steps=7 itf="h.poisonedPromotionViolations > 0"
// @countermodel forbid-repoisoning-retracted step=stepRepoisoning max-steps=7 itf="h.repoisoningViolations > 0"
// @countermodel forbid-zombie-retracted-derived step=stepZombieDerivedRead max-steps=7 itf="h.zombieDerivedViolations > 0"
// Limits: Finite single-root and single-derived ATMS belief revision abstraction; does not model probabilistic confidence calibration, contradictory belief resolution over cycles, or natural-language semantic equivalence beyond canonical claim digests.
module durable_memory_tms {
  type State = { sourceTrusted: bool, quorumMet: bool, rootPromoted: bool, derivedCreated: bool, derivedActive: bool, hasAltJustification: bool, rootRetracted: bool, poisonedPromotionViolations: int, repoisoningViolations: int, zombieDerivedViolations: int, validReads: int }
  var h: State
  action init = h' = { sourceTrusted: false, quorumMet: false, rootPromoted: false, derivedCreated: false, derivedActive: false, hasAltJustification: false, rootRetracted: false, poisonedPromotionViolations: 0, repoisoningViolations: 0, zombieDerivedViolations: 0, validReads: 0 }
  action markSourceTrusted = if (not(h.sourceTrusted)) h' = h.with("sourceTrusted", true) else h' = h
  action achieveIndependentQuorum = if (not(h.quorumMet)) h' = h.with("quorumMet", true) else h' = h
  action promoteRootBelief = if ((not(h.rootPromoted) and (h.sourceTrusted and h.quorumMet) and not(h.rootRetracted))) h' = h.with("rootPromoted", true).with("poisonedPromotionViolations", if ((h.sourceTrusted and h.quorumMet)) h.poisonedPromotionViolations else (h.poisonedPromotionViolations + 1)).with("repoisoningViolations", if (not(h.rootRetracted)) h.repoisoningViolations else (h.repoisoningViolations + 1)) else h' = h
  action deriveDependentBelief = if ((h.rootPromoted and not(h.derivedCreated))) h' = h.with("derivedCreated", true).with("derivedActive", true) else h' = h
  action attachAltCleanJustification = if ((h.derivedCreated and not(h.hasAltJustification))) h' = h.with("hasAltJustification", true).with("derivedActive", true) else h' = h
  action retractPoisonedRoot = if ((h.rootPromoted and not(h.rootRetracted))) h' = h.with("rootRetracted", true).with("rootPromoted", false).with("derivedActive", if (h.hasAltJustification) h.derivedActive else false) else h' = h
  action readDerivedBelief = if ((h.derivedCreated and (h.derivedActive and (not(h.rootRetracted) or h.hasAltJustification)))) h' = h.with("validReads", (h.validReads + 1)).with("zombieDerivedViolations", if ((h.derivedActive and (not(h.rootRetracted) or h.hasAltJustification))) h.zombieDerivedViolations else (h.zombieDerivedViolations + 1)) else h' = h
  action step = any { markSourceTrusted, achieveIndependentQuorum, promoteRootBelief, deriveDependentBelief, attachAltCleanJustification, retractPoisonedRoot, readDerivedBelief }
  val safety = (h.poisonedPromotionViolations == 0 and h.repoisoningViolations == 0 and h.zombieDerivedViolations == 0)
  // Countermodel engineering.defense.durable-memory-tms.poisoned-promotion (dropped guard: require-quorum-and-trusted-source)
  action promoteUnverified = if ((not(h.rootPromoted) and true and not(h.rootRetracted))) h' = h.with("rootPromoted", true).with("poisonedPromotionViolations", if ((h.sourceTrusted and h.quorumMet)) h.poisonedPromotionViolations else (h.poisonedPromotionViolations + 1)).with("repoisoningViolations", if (not(h.rootRetracted)) h.repoisoningViolations else (h.repoisoningViolations + 1)) else h' = h
  action stepPoisonedPromotion = any { step, promoteUnverified }
  // Countermodel engineering.defense.durable-memory-tms.repoisoning (dropped guard: forbid-repoisoning-retracted)
  action repromoteRetracted = if ((not(h.rootPromoted) and (h.sourceTrusted and h.quorumMet) and true)) h' = h.with("rootPromoted", true).with("poisonedPromotionViolations", if ((h.sourceTrusted and h.quorumMet)) h.poisonedPromotionViolations else (h.poisonedPromotionViolations + 1)).with("repoisoningViolations", if (not(h.rootRetracted)) h.repoisoningViolations else (h.repoisoningViolations + 1)) else h' = h
  action stepRepoisoning = any { step, repromoteRetracted }
  // Countermodel engineering.defense.durable-memory-tms.zombie-derived-read (dropped guard: forbid-zombie-retracted-derived)
  action readZombieDerived = if ((h.derivedCreated and true)) h' = h.with("validReads", (h.validReads + 1)).with("zombieDerivedViolations", if ((h.derivedActive and (not(h.rootRetracted) or h.hasAltJustification))) h.zombieDerivedViolations else (h.zombieDerivedViolations + 1)) else h' = h
  action stepZombieDerivedRead = any { step, readZombieDerived }
  run atmsAltJustificationSurvivalTest = init.then(markSourceTrusted).then(achieveIndependentQuorum).then(promoteRootBelief).then(deriveDependentBelief).then(attachAltCleanJustification).then(retractPoisonedRoot).then(readDerivedBelief).then(all { assert(safety), assert(h.rootRetracted), assert(h.derivedActive), assert(h.validReads == 1), h' = h })
  run poisonedPromotionViolatesSafetyTest = init.then(promoteUnverified).then(all { assert(not(safety)), assert(h.poisonedPromotionViolations > 0), h' = h })
  run repoisoningViolatesSafetyTest = init.then(markSourceTrusted).then(achieveIndependentQuorum).then(promoteRootBelief).then(retractPoisonedRoot).then(repromoteRetracted).then(all { assert(not(safety)), assert(h.repoisoningViolations > 0), h' = h })
  run zombieDerivedReadViolatesSafetyTest = init.then(markSourceTrusted).then(achieveIndependentQuorum).then(promoteRootBelief).then(deriveDependentBelief).then(retractPoisonedRoot).then(readZombieDerived).then(all { assert(not(safety)), assert(h.zombieDerivedViolations > 0), h' = h })
}

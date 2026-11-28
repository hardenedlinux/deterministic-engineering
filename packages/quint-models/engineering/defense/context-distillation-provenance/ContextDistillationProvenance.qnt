// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.context-distillation-provenance
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-pinned-retained step=stepPinnedAmnesia max-steps=6 itf="h.amnesiaViolations > 0"
// @countermodel require-integrity-meet step=stepIntegrityLaundering max-steps=6 itf="h.launderingViolations > 0"
// @countermodel require-secrecy-preserved step=stepSecrecyStrip max-steps=6 itf="h.secrecyStripViolations > 0"
// Limits: Bounded 2-distillation abstraction over pinned constraint retention, integrity meet, and secrecy propagation; unbounded multi-item DAG and citation grounding are proved in ContextDistillationAndProvenance.lean.
module context_distillation_provenance {
  type State = { hasPinnedConstraint: bool, hasUntrustedInput: bool, hasSecretTag: bool, pinnedRetained: bool, outputMarkedUntrusted: bool, secretPreserved: bool, safeDistillations: int, amnesiaViolations: int, launderingViolations: int, secrecyStripViolations: int }
  var h: State
  action init = h' = { hasPinnedConstraint: false, hasUntrustedInput: false, hasSecretTag: false, pinnedRetained: false, outputMarkedUntrusted: false, secretPreserved: false, safeDistillations: 0, amnesiaViolations: 0, launderingViolations: 0, secrecyStripViolations: 0 }
  action ingestPinnedConstraint = if (not(h.hasPinnedConstraint)) h' = h.with("hasPinnedConstraint", true) else h' = h
  action ingestUntrustedSnippet = if (not(h.hasUntrustedInput)) h' = h.with("hasUntrustedInput", true) else h' = h
  action ingestSecretFact = if (not(h.hasSecretTag)) h' = h.with("hasSecretTag", true) else h' = h
  action copyPinnedIntoSummary = if ((h.hasPinnedConstraint and not(h.pinnedRetained))) h' = h.with("pinnedRetained", true) else h' = h
  action tagSummaryUntrusted = if ((h.hasUntrustedInput and not(h.outputMarkedUntrusted))) h' = h.with("outputMarkedUntrusted", true) else h' = h
  action propagateSecretTag = if ((h.hasSecretTag and not(h.secretPreserved))) h' = h.with("secretPreserved", true) else h' = h
  action commitDistillation = if ((h.safeDistillations < 2 and (not(h.hasPinnedConstraint) or h.pinnedRetained) and (not(h.hasUntrustedInput) or h.outputMarkedUntrusted) and (not(h.hasSecretTag) or h.secretPreserved))) h' = h.with("safeDistillations", (h.safeDistillations + 1)).with("amnesiaViolations", if ((not(h.hasPinnedConstraint) or h.pinnedRetained)) h.amnesiaViolations else (h.amnesiaViolations + 1)).with("launderingViolations", if ((not(h.hasUntrustedInput) or h.outputMarkedUntrusted)) h.launderingViolations else (h.launderingViolations + 1)).with("secrecyStripViolations", if ((not(h.hasSecretTag) or h.secretPreserved)) h.secrecyStripViolations else (h.secrecyStripViolations + 1)) else h' = h
  action step = any { ingestPinnedConstraint, ingestUntrustedSnippet, ingestSecretFact, copyPinnedIntoSummary, tagSummaryUntrusted, propagateSecretTag, commitDistillation }
  val safety = (h.amnesiaViolations == 0 and h.launderingViolations == 0 and h.secrecyStripViolations == 0)
  // Countermodel engineering.defense.context-distillation-provenance.pinned-amnesia (dropped guard: require-pinned-retained)
  action commitDistillationAmnesia = if ((h.safeDistillations < 2 and true and (not(h.hasUntrustedInput) or h.outputMarkedUntrusted) and (not(h.hasSecretTag) or h.secretPreserved))) h' = h.with("safeDistillations", (h.safeDistillations + 1)).with("amnesiaViolations", if ((not(h.hasPinnedConstraint) or h.pinnedRetained)) h.amnesiaViolations else (h.amnesiaViolations + 1)).with("launderingViolations", if ((not(h.hasUntrustedInput) or h.outputMarkedUntrusted)) h.launderingViolations else (h.launderingViolations + 1)).with("secrecyStripViolations", if ((not(h.hasSecretTag) or h.secretPreserved)) h.secrecyStripViolations else (h.secrecyStripViolations + 1)) else h' = h
  action stepPinnedAmnesia = any { step, commitDistillationAmnesia }
  // Countermodel engineering.defense.context-distillation-provenance.integrity-laundering (dropped guard: require-integrity-meet)
  action commitDistillationLaundering = if ((h.safeDistillations < 2 and (not(h.hasPinnedConstraint) or h.pinnedRetained) and true and (not(h.hasSecretTag) or h.secretPreserved))) h' = h.with("safeDistillations", (h.safeDistillations + 1)).with("amnesiaViolations", if ((not(h.hasPinnedConstraint) or h.pinnedRetained)) h.amnesiaViolations else (h.amnesiaViolations + 1)).with("launderingViolations", if ((not(h.hasUntrustedInput) or h.outputMarkedUntrusted)) h.launderingViolations else (h.launderingViolations + 1)).with("secrecyStripViolations", if ((not(h.hasSecretTag) or h.secretPreserved)) h.secrecyStripViolations else (h.secrecyStripViolations + 1)) else h' = h
  action stepIntegrityLaundering = any { step, commitDistillationLaundering }
  // Countermodel engineering.defense.context-distillation-provenance.secrecy-strip (dropped guard: require-secrecy-preserved)
  action commitDistillationSecrecyStrip = if ((h.safeDistillations < 2 and (not(h.hasPinnedConstraint) or h.pinnedRetained) and (not(h.hasUntrustedInput) or h.outputMarkedUntrusted) and true)) h' = h.with("safeDistillations", (h.safeDistillations + 1)).with("amnesiaViolations", if ((not(h.hasPinnedConstraint) or h.pinnedRetained)) h.amnesiaViolations else (h.amnesiaViolations + 1)).with("launderingViolations", if ((not(h.hasUntrustedInput) or h.outputMarkedUntrusted)) h.launderingViolations else (h.launderingViolations + 1)).with("secrecyStripViolations", if ((not(h.hasSecretTag) or h.secretPreserved)) h.secrecyStripViolations else (h.secrecyStripViolations + 1)) else h' = h
  action stepSecrecyStrip = any { step, commitDistillationSecrecyStrip }
  run cleanDistillationTest = init.then(ingestPinnedConstraint).then(ingestUntrustedSnippet).then(ingestSecretFact).then(copyPinnedIntoSummary).then(tagSummaryUntrusted).then(propagateSecretTag).then(commitDistillation).then(all { assert(safety), assert(h.safeDistillations == 1), h' = h })
  run pinnedAmnesiaViolatesSafetyTest = init.then(ingestPinnedConstraint).then(commitDistillationAmnesia).then(all { assert(not(safety)), assert(h.amnesiaViolations > 0), h' = h })
  run integrityLaunderingViolatesSafetyTest = init.then(ingestUntrustedSnippet).then(commitDistillationLaundering).then(all { assert(not(safety)), assert(h.launderingViolations > 0), h' = h })
  run secrecyStripViolatesSafetyTest = init.then(ingestSecretFact).then(commitDistillationSecrecyStrip).then(all { assert(not(safety)), assert(h.secrecyStripViolations > 0), h' = h })
}

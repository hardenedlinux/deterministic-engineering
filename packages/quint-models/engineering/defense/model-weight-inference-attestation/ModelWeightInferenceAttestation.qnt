// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.model-weight-inference-attestation
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-weight-root-pinned step=stepUnpinnedWeight max-steps=6 itf="h.unpinnedWeightViolations > 0"
// @countermodel require-adapters-allowlisted step=stepStealthLora max-steps=6 itf="h.stealthLoraViolations > 0"
// @countermodel require-deterministic-nonrevoked step=stepNondetOrRevoked max-steps=6 itf="h.nondetSamplingViolations > 0"
// Limits: Bounded deterministic model-weight pinning, LoRA adapter allowlist, and reproducible sampling state machine; arbitrary shard Merkle trees, temperature bounds, explicit PRNG seeds, and Ed25519 serving attestations are proved unboundedly in ModelWeightAndInferenceAttestation.lean.
module model_weight_inference_attestation {
  type State = { weightRootPinned: bool, adaptersAllowlisted: bool, samplingDeterministic: bool, modelRevoked: bool, admittedInferences: int, unpinnedWeightViolations: int, stealthLoraViolations: int, nondetSamplingViolations: int }
  var h: State
  action init = h' = { weightRootPinned: false, adaptersAllowlisted: false, samplingDeterministic: false, modelRevoked: false, admittedInferences: 0, unpinnedWeightViolations: 0, stealthLoraViolations: 0, nondetSamplingViolations: 0 }
  action pinWeightRoot = if (not(h.weightRootPinned)) h' = h.with("weightRootPinned", true) else h' = h
  action verifyAdapterAllowlist = if (not(h.adaptersAllowlisted)) h' = h.with("adaptersAllowlisted", true) else h' = h
  action lockDeterministicSampling = if (not(h.samplingDeterministic)) h' = h.with("samplingDeterministic", true) else h' = h
  action revokeModel = if (not(h.modelRevoked)) h' = h.with("modelRevoked", true) else h' = h
  action admitInference = if ((h.admittedInferences < 2 and h.weightRootPinned and h.adaptersAllowlisted and (h.samplingDeterministic and not(h.modelRevoked)))) h' = h.with("admittedInferences", (h.admittedInferences + 1)).with("unpinnedWeightViolations", if (h.weightRootPinned) h.unpinnedWeightViolations else (h.unpinnedWeightViolations + 1)).with("stealthLoraViolations", if (h.adaptersAllowlisted) h.stealthLoraViolations else (h.stealthLoraViolations + 1)).with("nondetSamplingViolations", if ((h.samplingDeterministic and not(h.modelRevoked))) h.nondetSamplingViolations else (h.nondetSamplingViolations + 1)) else h' = h
  action step = any { pinWeightRoot, verifyAdapterAllowlist, lockDeterministicSampling, revokeModel, admitInference }
  val safety = (h.unpinnedWeightViolations == 0 and h.stealthLoraViolations == 0 and h.nondetSamplingViolations == 0)
  // Countermodel engineering.defense.model-weight-inference-attestation.unpinned-weight (dropped guard: require-weight-root-pinned)
  action admitInferenceUnpinned = if ((h.admittedInferences < 2 and true and h.adaptersAllowlisted and (h.samplingDeterministic and not(h.modelRevoked)))) h' = h.with("admittedInferences", (h.admittedInferences + 1)).with("unpinnedWeightViolations", if (h.weightRootPinned) h.unpinnedWeightViolations else (h.unpinnedWeightViolations + 1)).with("stealthLoraViolations", if (h.adaptersAllowlisted) h.stealthLoraViolations else (h.stealthLoraViolations + 1)).with("nondetSamplingViolations", if ((h.samplingDeterministic and not(h.modelRevoked))) h.nondetSamplingViolations else (h.nondetSamplingViolations + 1)) else h' = h
  action stepUnpinnedWeight = any { step, admitInferenceUnpinned }
  // Countermodel engineering.defense.model-weight-inference-attestation.stealth-lora (dropped guard: require-adapters-allowlisted)
  action admitInferenceStealthLora = if ((h.admittedInferences < 2 and h.weightRootPinned and true and (h.samplingDeterministic and not(h.modelRevoked)))) h' = h.with("admittedInferences", (h.admittedInferences + 1)).with("unpinnedWeightViolations", if (h.weightRootPinned) h.unpinnedWeightViolations else (h.unpinnedWeightViolations + 1)).with("stealthLoraViolations", if (h.adaptersAllowlisted) h.stealthLoraViolations else (h.stealthLoraViolations + 1)).with("nondetSamplingViolations", if ((h.samplingDeterministic and not(h.modelRevoked))) h.nondetSamplingViolations else (h.nondetSamplingViolations + 1)) else h' = h
  action stepStealthLora = any { step, admitInferenceStealthLora }
  // Countermodel engineering.defense.model-weight-inference-attestation.nondet-or-revoked (dropped guard: require-deterministic-nonrevoked)
  action admitInferenceNondet = if ((h.admittedInferences < 2 and h.weightRootPinned and h.adaptersAllowlisted and true)) h' = h.with("admittedInferences", (h.admittedInferences + 1)).with("unpinnedWeightViolations", if (h.weightRootPinned) h.unpinnedWeightViolations else (h.unpinnedWeightViolations + 1)).with("stealthLoraViolations", if (h.adaptersAllowlisted) h.stealthLoraViolations else (h.stealthLoraViolations + 1)).with("nondetSamplingViolations", if ((h.samplingDeterministic and not(h.modelRevoked))) h.nondetSamplingViolations else (h.nondetSamplingViolations + 1)) else h' = h
  action stepNondetOrRevoked = any { step, admitInferenceNondet }
  run cleanInferenceAdmitTest = init.then(pinWeightRoot).then(verifyAdapterAllowlist).then(lockDeterministicSampling).then(admitInference).then(all { assert(safety), assert(h.admittedInferences == 1), h' = h })
  run unpinnedWeightViolatesSafetyTest = init.then(verifyAdapterAllowlist).then(lockDeterministicSampling).then(admitInferenceUnpinned).then(all { assert(not(safety)), assert(h.unpinnedWeightViolations > 0), h' = h })
  run stealthLoraViolatesSafetyTest = init.then(pinWeightRoot).then(lockDeterministicSampling).then(admitInferenceStealthLora).then(all { assert(not(safety)), assert(h.stealthLoraViolations > 0), h' = h })
  run nondetOrRevokedViolatesSafetyTest = init.then(pinWeightRoot).then(verifyAdapterAllowlist).then(revokeModel).then(admitInferenceNondet).then(all { assert(not(safety)), assert(h.nondetSamplingViolations > 0), h' = h })
}

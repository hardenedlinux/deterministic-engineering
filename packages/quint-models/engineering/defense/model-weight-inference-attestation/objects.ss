;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B21 (10.202 / 10.203 / 10.204): Slim .qnt-SSOT metadata descriptor.
;;; Formal state, guards, transitions, safety invariant, traces, and countermodels live
;;; EXCLUSIVELY in ModelWeightInferenceAttestation.qnt (parsed natively via grammar.ss).
;;; Sealed QuintDomainModelShape rejects any duplicated state:/guards:/transitions: slots.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ModelWeightInferenceAttestationModel)

(.def (ModelWeightInferenceAttestationModel @ ThreatModel.)
  identity: 'engineering.defense.model-weight-inference-attestation
  family: 'engineering.defense.model-weight-inference-attestation
  title: "Deterministic Model-Weight Pinning & Reproducible Inference Attestation"
  subdomain: 'quint.engineering.defense
  papers:
  '(("SLSA / Model Transparency & Tensor Shard Merkle Pinning"
     "Cryptographic binding of safetensors/GGUF base-model shards against silent weight substitution.")
    ("LoRA / PEFT Supply-Chain Governance"
     "Explicit adapter allowlisting to block stealth trojan LoRA injection while admitting zero-adapter base models.")
    ("Deterministic Engineering (10.202 / 10.203)"
     "Unbounded LeanPoo proofs (=ModelWeightAndInferenceAttestation.lean=), air-gapped Ed25519 inference trace attestation, and 60x32 ASCENT Datalog verification."))
  quint-module: "model_weight_inference_attestation"
  quint-file: "ModelWeightInferenceAttestation.qnt"
  domain-dir: "engineering/defense/model-weight-inference-attestation"
  rules:
  '((model-weight-safe DE-MWIA-SAFE quint)
    (model-weight-countermodel DE-MWIA-COUNTER quint))
  dependencies:
  '((DE-MWIA-SAFE source)
    (DE-MWIA-SAFE profile)
    (DE-MWIA-SAFE method)
    (DE-MWIA-COUNTER source)
    (DE-MWIA-COUNTER profile)
    (DE-MWIA-COUNTER method))
  invariant: "Regulated AI inference admission requires a pinned base-weight Merkle root (unpinnedWeightViolations == 0), allowlisted LoRA/PEFT adapters (stealthLoraViolations == 0), and deterministic sampling on a non-revoked model (nondetSamplingViolations == 0)."
  limits: "Bounded deterministic model-weight pinning, LoRA adapter allowlist, and reproducible sampling state machine; arbitrary shard Merkle trees, temperature bounds, explicit PRNG seeds, and Ed25519 serving attestations are proved unboundedly in ModelWeightAndInferenceAttestation.lean.")

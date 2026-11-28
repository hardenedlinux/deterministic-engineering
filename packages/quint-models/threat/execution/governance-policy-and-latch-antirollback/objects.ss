;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM29 (ADV-L4): Governance Policy-Evaluation Fail-Closed, Monotonic Revision/Latch
;;; Anti-Rollback & Causal Retraction Persistence Confinement.
;;; Formalizes five real ADV-L4 governance engine bypasses:
;;;  1. Cedar `forbid ... unless` treating missing context keys (`None`) as waiving
;;;     the `forbid` (fail-open inversion on multi-predicate exemptions).
;;;  2. Same-epoch `policy_revision` rollback in `synchronize_proof_envelope` wiping
;;;     ASCENT `fenced_actors`, `blocked_tools`, and compiled Cedar `forbid` rules.
;;;  3. Same-epoch pre-trip durable checkpoint replay in `restore_durable_state` /
;;;     `restore_durable_checkpoint_bytes` silently clearing an active E-Stop latch.
;;;  4. `rearm_by_verified_human` clearing `retracted_derivations`, resurrecting
;;;     permanently invalidated Bi-Temporal Truth Maintenance conclusions.
;;;  5. Non-constant-time SHA-256 checkpoint tag comparison & unbounded lease/derivation
;;;     registration during tripped breaker states.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export GovernancePolicyAndLatchAntirollbackModel)

(.def (GovernancePolicyAndLatchAntirollbackModel @ ThreatModel.)
  identity: 'threat.execution.governance-policy-and-latch-antirollback
  family: 'threat.execution.governance-policy-and-latch-antirollback
  title: "Governance Policy-Evaluation Fail-Closed, Monotonic Revision/Latch Anti-Rollback & Retraction Persistence (SM29)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM29 ADV-L4 fail-closed Cedar forbid-unless evaluation under missing context keys, monotonic same-epoch policy_revision anti-rollback, same-epoch E-Stop checkpoint anti-untrip, Bi-Temporal retraction persistence across human re-arm, constant-time integrity digest verification, and bounded lease registration.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-agent-kernel CompiledCedarPolicy::matches evaluated forbid-unless with != Some(false) (silently waiving forbid on None), synchronize_proof_envelope accepted same-epoch lower policy_revision wiping fences/forbids, ExecutionCircuitBreaker::restore_durable_state allowed same-epoch pre-trip replay to untrip an active E-Stop, and rearm_by_verified_human cleared retracted_derivations."))
  quint-module: "execution_governance_policy_and_latch_antirollback"
  quint-file: "GovernancePolicyAndLatchAntirollback.qnt"
  domain-dir: "threat/execution/governance-policy-and-latch-antirollback"
  rules:
  '((governance-policy-latch-safe DE-SM29-SAFE quint)
    (governance-policy-latch-countermodel DE-SM29-COUNTER quint))
  dependencies:
  '((DE-SM29-SAFE source)
    (DE-SM29-SAFE profile)
    (DE-SM29-SAFE method)
    (DE-SM29-COUNTER source)
    (DE-SM29-COUNTER profile)
    (DE-SM29-COUNTER method))
  invariant: "No missing context key silently waives a Cedar forbid-unless rule (forbidUnlessBypassed == 0), no same-epoch lower policy_revision envelope wipes active fences or forbid rules (revisionRollbacks == 0), no same-epoch pre-trip durable checkpoint replay clears an active Operator E-Stop latch (estopLatchClearedByReplay == 0), and human re-arm never resurrects permanently retracted causal derivations (retractionResurrections == 0)."
  limits: "Finite bounded governance admission, Cedar policy-clause evaluator, and durable circuit-breaker state machine (revocationEpoch <= 3, policyRevision <= 3, stepCount <= 12); models fail-closed Cedar forbid-unless missing-context semantics, same-epoch policy_revision anti-rollback, same-epoch E-Stop checkpoint anti-untrip, and Bi-Temporal Truth Maintenance retraction persistence across human re-arm, without modeling cryptographic SHA-256 collision attacks or OS kernel compromise.")

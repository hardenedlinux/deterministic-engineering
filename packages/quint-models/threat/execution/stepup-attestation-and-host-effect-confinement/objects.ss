;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM30 (ADV-L4): Step-Up MFA Attestation Integrity, Scheme Effect E-Stop/CAS
;;; Isolation, Watcher Broadcast-Lag Survival & Bounded Fact-Graph Confinement.
;;; Formalizes five real ADV-L4 vulnerabilities discovered in marlin-gerbil-scheme:
;;;  1. parse_verified_step_up_actor admitted worker-*/scheme-sandbox-* agents,
;;;     arbitrary weak acr= values (acr=none/password/fake), and duplicate actor=
;;;     parameter smuggling as VerifiedHuman for circuit-breaker re-arm.
;;;  2. run_one_atomic_effect gated SandboxRun under GovernanceHostController while
;;;     leaving LlmComplete completely ungated under active E-Stop and letting
;;;     CasPut overwrite reserved governance checkpoint keys (checkpoint:governance* / *:facts).
;;;  3. gate_watcher and ui_cmd_watcher matched Err(_) => break on broadcast channels,
;;;     permanently killing E-Stop and Step-Up Re-Arm handling on RecvError::Lagged.
;;;  4. GovernanceFactStore::mutate_facts_and_build_request inserted unboundedly past
;;;     the 4096-item MGF1 deserialization cap (self-inflicted restart DoS bomb) and
;;;     from_canonical_bytes compared SHA-256 tags via short-circuit !=.
;;;  5. handle_claimed_gate_decision_durable swallowed persist_to_cas errors via `let _ =`
;;;     leaving live re-armed state desynchronized from durable Turso CAS WAL.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export StepUpAttestationAndHostEffectConfinementModel)

(.def (StepUpAttestationAndHostEffectConfinementModel @ ThreatModel.)
  identity: 'threat.execution.stepup-attestation-and-host-effect-confinement
  family: 'threat.execution.stepup-attestation-and-host-effect-confinement
  title: "Step-Up MFA Attestation Integrity, Scheme Effect E-Stop/CAS Isolation & Host Resilience (SM30)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM30 ADV-L4 strict RFC 9470 Step-Up MFA ACR allowlist and duplicate/non-human actor refusal, Scheme LlmComplete E-Stop mediation and reserved governance CAS key confinement, broadcast RecvError::Lagged watcher survival, bounded fact-graph write parity with constant-time MGF1 verification, and fail-closed durable re-arm persistence.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-gerbil-scheme parse_verified_step_up_actor admitted worker-*/scheme-sandbox-*, acr=none, and duplicate actor= overrides as VerifiedHuman; run_one_atomic_effect left LlmComplete ungated under E-Stop and CasPut unprotected against reserved governance checkpoint overwrites; gate_watcher/ui_cmd_watcher exited on RecvError::Lagged; mutate_facts_and_build_request overflowed MGF1's 4096-entry deserialization cap."))
  quint-module: "execution_stepup_attestation_and_host_effect_confinement"
  quint-file: "StepUpAttestationAndHostEffectConfinement.qnt"
  domain-dir: "threat/execution/stepup-attestation-and-host-effect-confinement"
  rules:
  '((stepup-host-effect-safe DE-SM30-SAFE quint)
    (stepup-host-effect-countermodel DE-SM30-COUNTER quint))
  dependencies:
  '((DE-SM30-SAFE source)
    (DE-SM30-SAFE profile)
    (DE-SM30-SAFE method)
    (DE-SM30-COUNTER source)
    (DE-SM30-COUNTER profile)
    (DE-SM30-COUNTER method))
  invariant: "No spoofed non-human identity, weak ACR, or duplicate-key Step-Up note re-arms the breaker (spoofedRearms == 0), no LlmComplete executes under E-Stop or CasPut overwrites reserved governance checkpoint keys (effectOrCasBreaches == 0 and reservedCasIntact), broadcast lag never terminates gate or UI command watchers (watcherSuicides == 0 and watchersAlive), and live fact-store mutations never exceed the MGF1 deserialization cap or desynchronize durable CAS on re-arm (factBombOrDesyncs == 0 and factCount <= 3)."
  limits: "Finite bounded Scheme governance host controller & atomic-effect worker state machine (factCount <= 3, stepCount <= 12); models strict RFC 9470 Step-Up MFA ACR allowlist and agent-prefix/duplicate-param rejection, E-Stop mediation on LlmComplete plus reserved governance CAS key confinement on CasPut, broadcast-lag survival in gate/UI watchers, and fact-store capacity parity with fail-closed CAS persist handling, without modeling cryptographic SHA-256 breaks or OS process takeover.")

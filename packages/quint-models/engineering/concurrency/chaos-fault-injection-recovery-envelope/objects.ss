;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Compound chaos fault injection, open-circuit load shedding, typed fault
;;; refusal, and deterministic recovery probe model (SM14).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ChaosFaultInjectionRecoveryEnvelopeModel)

(.def (ChaosFaultInjectionRecoveryEnvelopeModel @ ThreatModel.)
  identity: 'engineering.concurrency.chaos-fault-injection-recovery-envelope
  family: 'engineering.concurrency.chaos-fault-injection-recovery-envelope
  title: "Chaos Fault Injection, Circuit Load Shedding & Typed Recovery Envelope"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("N. Bronson et al. (ACM HotOS 2021)"
     "Metastable Failures in Distributed Systems — fault bursts trigger self-sustaining overload unless circuits shed load.")
    ("A. Basiri et al. (IEEE Software 2016)"
     "Chaos Engineering — systematic fault injection verifying steady-state invariants and bounded recovery.")
    ("M. Nygard (2018)"
     "Release It! — circuit breakers, typed degraded refusals, and half-open recovery probes."))
  quint-module: "concurrency_chaos_fault_injection_recovery_envelope"
  quint-file: "ChaosFaultInjectionRecoveryEnvelope.qnt"
  domain-dir: "engineering/concurrency/chaos-fault-injection-recovery-envelope"
  rules:
  '((conc-chaos-circuit-shed CONC-CHAOS-CIRCUIT-SHED quint)
    (conc-chaos-typed-refusal CONC-CHAOS-TYPED-REFUSAL quint)
    (conc-chaos-recovery-probe CONC-CHAOS-RECOVERY-PROBE quint))
  dependencies:
  '((CONC-CHAOS-CIRCUIT-SHED source)
    (CONC-CHAOS-CIRCUIT-SHED profile)
    (CONC-CHAOS-CIRCUIT-SHED method)
    (CONC-CHAOS-TYPED-REFUSAL source)
    (CONC-CHAOS-TYPED-REFUSAL profile)
    (CONC-CHAOS-TYPED-REFUSAL method)
    (CONC-CHAOS-RECOVERY-PROBE source)
    (CONC-CHAOS-RECOVERY-PROBE profile)
    (CONC-CHAOS-RECOVERY-PROBE method))
  invariant: "Under injected faults, an open circuit sheds traffic instead of amplifying load, active faults return typed degraded refusals rather than silent empty success, and clearing a fault enables deterministic probe recovery without permanent wedge."
  limits: "Finite 2-fault trip threshold and 2-slot active load chaos abstraction; verifies open-circuit load shedding, typed degraded refusal, and deterministic recovery probing, not wall-clock exponential backoff jitter.")

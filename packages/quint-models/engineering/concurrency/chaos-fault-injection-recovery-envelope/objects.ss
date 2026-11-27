;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Compound chaos fault injection, open-circuit load shedding, typed fault
;;; refusal, and deterministic recovery probe model (SM14).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ChaosFaultInjectionRecoveryEnvelopeModel
        OpenCircuitCascadeCountermodel
        SilentFallbackCorruptionCountermodel
        StickyRecoveryWedgeCountermodel)

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
  quint-imports: '()
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
  parameters: '()
  state:
  '((faultActive "bool" "false")
    (circuitState "int" "0")
    (activeLoad "int" "0")
    (consecutiveFaults "int" "0")
    (recoveredCount "int" "0")
    (refusedDegraded "int" "0")
    (cascadeViolations "int" "0")
    (silentCorruptions "int" "0")
    (stickyWedged "int" "0"))
  guards:
  '((shed-load-on-open-circuit true)
    (typed-refusal-under-fault true)
    (half-open-probe-recovery true))
  transitions:
  '((injectFault
      (action injectFault ()
        (if (not (. h faultActive))
          (set-h (faultActive true))
          (keep-h))))
    (clearFault
      (action clearFault ()
        (if (. h faultActive)
          (set-h (faultActive false))
          (keep-h))))
    (handleRequest
      (action handleRequest ()
        (if (= (. h circuitState) 1)
          (if (guard shed-load-on-open-circuit true false)
            (set-h (refusedDegraded (+ (. h refusedDegraded) 1)))
            (set-h (activeLoad (+ (. h activeLoad) 1))
                   (cascadeViolations (+ (. h cascadeViolations) 1))))
          (if (. h faultActive)
            (if (guard typed-refusal-under-fault true false)
              (if (>= (+ (. h consecutiveFaults) 1) 2)
                (set-h (consecutiveFaults (+ (. h consecutiveFaults) 1))
                       (circuitState 1)
                       (refusedDegraded (+ (. h refusedDegraded) 1)))
                (set-h (consecutiveFaults (+ (. h consecutiveFaults) 1))
                       (refusedDegraded (+ (. h refusedDegraded) 1))))
              (set-h (silentCorruptions (+ (. h silentCorruptions) 1))))
            (if (< (. h activeLoad) 2)
              (set-h (activeLoad (+ (. h activeLoad) 1)))
              (keep-h))))))
    (finishRequest
      (action finishRequest ()
        (if (> (. h activeLoad) 0)
          (set-h (activeLoad (- (. h activeLoad) 1)))
          (keep-h))))
    (probeRecovery
      (action probeRecovery ()
        (if (and (= (. h circuitState) 1) (not (. h faultActive)))
          (if (guard half-open-probe-recovery true false)
            (set-h (circuitState 0)
                   (consecutiveFaults 0)
                   (recoveredCount (+ (. h recoveredCount) 1)))
            (set-h (stickyWedged (+ (. h stickyWedged) 1))))
          (keep-h))))
    (step
      (action step ()
        (any injectFault clearFault handleRequest finishRequest probeRecovery))))
  safety:
  '(and (<= (. h activeLoad) 2)
        (= (. h cascadeViolations) 0)
        (= (. h silentCorruptions) 0)
        (= (. h stickyWedged) 0))
  traces:
  '((checkChaosSafe
      (action checkChaosSafe ()
        (all (assert (> (. h refusedDegraded) 0))
             (assert (> (. h recoveredCount) 0))
             (assert (= (. h circuitState) 0))
             (assert (= (. h activeLoad) 0))
             (assert safety)
             (keep-h))))
    (checkChaosViolated
      (action checkChaosViolated ()
        (all (assert (or (> (. h cascadeViolations) 0)
                         (> (. h silentCorruptions) 0)
                         (> (. h stickyWedged) 0)))
             (assert (not safety))
             (keep-h))))
    (chaosRecoverySafeTest
      (run chaosRecoverySafeTest
        (then init handleRequest finishRequest injectFault handleRequest handleRequest handleRequest clearFault probeRecovery checkChaosSafe)))
    (openCircuitCascadeRefutedTest
      (run openCircuitCascadeRefutedTest
        (then init injectFault handleRequest handleRequest handleRequestCascade checkChaosViolated)))
    (silentFallbackRefutedTest
      (run silentFallbackRefutedTest
        (then init injectFault handleRequestSilent checkChaosViolated)))
    (stickyWedgeRefutedTest
      (run stickyWedgeRefutedTest
        (then init injectFault handleRequest handleRequest clearFault probeRecoveryWedged checkChaosViolated))))
  countermodels:
  (list OpenCircuitCascadeCountermodel
        SilentFallbackCorruptionCountermodel
        StickyRecoveryWedgeCountermodel)
  limits: "Finite 2-fault trip threshold and 2-slot active load chaos abstraction; verifies open-circuit load shedding, typed degraded refusal, and deterministic recovery probing, not wall-clock exponential backoff jitter.")

(.def (OpenCircuitCascadeCountermodel @ ChaosFaultInjectionRecoveryEnvelopeModel)
  identity: 'engineering.concurrency.chaos-fault-injection-recovery-envelope.open-circuit-cascade
  dropped-guard: 'shed-load-on-open-circuit
  step-action: "stepOpenCircuitCascade"
  derive-from-transition: 'handleRequest
  derive-action-name: 'handleRequestCascade
  expected-itf-predicate: "h.cascadeViolations > 0")

(.def (SilentFallbackCorruptionCountermodel @ ChaosFaultInjectionRecoveryEnvelopeModel)
  identity: 'engineering.concurrency.chaos-fault-injection-recovery-envelope.silent-fallback-corruption
  dropped-guard: 'typed-refusal-under-fault
  step-action: "stepSilentFallbackCorruption"
  derive-from-transition: 'handleRequest
  derive-action-name: 'handleRequestSilent
  expected-itf-predicate: "h.silentCorruptions > 0")

(.def (StickyRecoveryWedgeCountermodel @ ChaosFaultInjectionRecoveryEnvelopeModel)
  identity: 'engineering.concurrency.chaos-fault-injection-recovery-envelope.sticky-recovery-wedge
  dropped-guard: 'half-open-probe-recovery
  step-action: "stepStickyRecoveryWedge"
  derive-from-transition: 'probeRecovery
  derive-action-name: 'probeRecoveryWedged
  expected-itf-predicate: "h.stickyWedged > 0")

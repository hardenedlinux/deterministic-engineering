;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B13 (10.185 / 10.186): Federated Multi-Agent Arbitration,
;;; Deadlock Preemption, Bounded Retry Termination & Absorbing Terminal Phases.
;;; Proves three bounded liveness & termination safety invariants:
;;;   1. Finite Retry Cap: auto-retry never executes once attempts >= 2
;;;      (unboundedRetryViolations == 0).
;;;   2. Deadlock Preemption: auto-retry never executes once a circular wait
;;;      deadlock is detected (deadlockRetryViolations == 0).
;;;   3. Absorbing Terminal Phases: once escalated/aborted/admitted, no further
;;;      auto-retry can re-enter active execution (terminalReentryViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export FederatedArbitrationLivenessModel
        UnboundedRetryCountermodel
        DeadlockRetryCountermodel
        TerminalReentryCountermodel)

(.def (FederatedArbitrationLivenessModel @ ThreatModel.)
  identity: 'engineering.defense.federated-arbitration-liveness
  family: 'engineering.defense.federated-arbitration-liveness
  title: "Federated Multi-Agent Arbitration, Deadlock Preemption & Bounded Liveness"
  subdomain: 'quint.engineering.defense
  papers:
  '(("E. G. Coffman, M. J. Elphick & A. Shoshani (ACM Computing Surveys 1971)"
     "System Deadlocks — circular wait detection and deterministic preemption.")
    ("Deterministic Engineering (10.185 / 10.186)"
     "Bounded multi-agent retry termination, fail-closed safe abort, and absorbing terminal arbitration phases."))
  quint-module: "federated_arbitration_liveness"
  quint-file: "FederatedArbitrationLiveness.qnt"
  domain-dir: "engineering/defense/federated-arbitration-liveness"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((federated-arbitration-safe DE-FAL-SAFE quint)
    (federated-arbitration-countermodel DE-FAL-COUNTER quint))
  dependencies:
  '((DE-FAL-SAFE source)
    (DE-FAL-SAFE profile)
    (DE-FAL-SAFE method)
    (DE-FAL-COUNTER source)
    (DE-FAL-COUNTER profile)
    (DE-FAL-COUNTER method))
  invariant: "Auto-retry requires attempts < 2 (unboundedRetryViolations == 0), zero detected deadlock cycles (deadlockRetryViolations == 0), and an active non-terminal phase (terminalReentryViolations == 0)."
  parameters: '()
  state:
  '((attempts "int" "0")
    (deadlockDetected "bool" "false")
    (terminated "bool" "false")
    (escalated "bool" "false")
    (admitted "bool" "false")
    (unboundedRetryViolations "int" "0")
    (deadlockRetryViolations "int" "0")
    (terminalReentryViolations "int" "0"))
  guards:
  '((require-retry-budget (< (. h attempts) 2))
    (require-no-deadlock (not (. h deadlockDetected)))
    (require-non-terminal (not (. h terminated))))
  transitions:
  '((detectDeadlockCycle
      (action detectDeadlockCycle ()
        (if (and (not (. h terminated)) (not (. h deadlockDetected)))
          (set-h (deadlockDetected #t))
          (keep-h))))
    (attemptAutoRetry
      (action attemptAutoRetry ()
        (if (and (< (. h attempts) 3)
                 (guard require-retry-budget (< (. h attempts) 2))
                 (guard require-no-deadlock (not (. h deadlockDetected)))
                 (guard require-non-terminal (not (. h terminated))))
          (set-h (attempts (+ (. h attempts) 1))
                 (unboundedRetryViolations
                   (if (< (. h attempts) 2)
                     (. h unboundedRetryViolations)
                     (+ (. h unboundedRetryViolations) 1)))
                 (deadlockRetryViolations
                   (if (not (. h deadlockDetected))
                     (. h deadlockRetryViolations)
                     (+ (. h deadlockRetryViolations) 1)))
                 (terminalReentryViolations
                   (if (not (. h terminated))
                     (. h terminalReentryViolations)
                     (+ (. h terminalReentryViolations) 1))))
          (keep-h))))
    (escalateOrAbort
      (action escalateOrAbort ()
        (if (and (not (. h terminated))
                 (or (. h deadlockDetected) (>= (. h attempts) 2)))
          (set-h (terminated #t)
                 (escalated #t))
          (keep-h))))
    (admitClean
      (action admitClean ()
        (if (and (not (. h terminated)) (not (. h deadlockDetected)) (< (. h attempts) 2))
          (set-h (terminated #t)
                 (admitted #t))
          (keep-h))))
    (step
      (action step ()
        (any detectDeadlockCycle attemptAutoRetry escalateOrAbort admitClean))))
  safety:
  '(and (= (. h unboundedRetryViolations) 0)
        (= (. h deadlockRetryViolations) 0)
        (= (. h terminalReentryViolations) 0)
        (not (and (. h escalated) (. h admitted))))
  traces:
  '((boundedEscalationTest
      (run boundedEscalationTest
        (then init attemptAutoRetry attemptAutoRetry escalateOrAbort attemptAutoRetry
              (all (assert safety)
                   (assert (. h escalated))
                   (assert (not (. h admitted)))
                   (keep-h)))))
    (unboundedRetryViolatesSafetyTest
      (run unboundedRetryViolatesSafetyTest
        (then init attemptAutoRetry attemptAutoRetry attemptUnboundedRetry
              (all (assert (not safety))
                   (assert (> (. h unboundedRetryViolations) 0))
                   (keep-h)))))
    (deadlockRetryViolatesSafetyTest
      (run deadlockRetryViolatesSafetyTest
        (then init detectDeadlockCycle attemptDeadlockRetry
              (all (assert (not safety))
                   (assert (> (. h deadlockRetryViolations) 0))
                   (keep-h)))))
    (terminalReentryViolatesSafetyTest
      (run terminalReentryViolatesSafetyTest
        (then init admitClean attemptTerminalReentry
              (all (assert (not safety))
                   (assert (> (. h terminalReentryViolations) 0))
                   (keep-h))))))
  countermodels:
  (list UnboundedRetryCountermodel
        DeadlockRetryCountermodel
        TerminalReentryCountermodel)
  limits: "Two-attempt bounded retry abstraction; arbitrary maxAttempts and absorbing terminal phases are proved unboundedly in FederatedArbitrationLiveness.lean.")

(.def (UnboundedRetryCountermodel @ FederatedArbitrationLivenessModel)
  identity: 'engineering.defense.federated-arbitration-liveness.unbounded-retry
  dropped-guard: 'require-retry-budget
  step-action: "stepUnboundedRetry"
  derive-from-transition: 'attemptAutoRetry
  derive-action-name: 'attemptUnboundedRetry
  expected-itf-predicate: "h.unboundedRetryViolations > 0")

(.def (DeadlockRetryCountermodel @ FederatedArbitrationLivenessModel)
  identity: 'engineering.defense.federated-arbitration-liveness.deadlock-retry
  dropped-guard: 'require-no-deadlock
  step-action: "stepDeadlockRetry"
  derive-from-transition: 'attemptAutoRetry
  derive-action-name: 'attemptDeadlockRetry
  expected-itf-predicate: "h.deadlockRetryViolations > 0")

(.def (TerminalReentryCountermodel @ FederatedArbitrationLivenessModel)
  identity: 'engineering.defense.federated-arbitration-liveness.terminal-reentry
  dropped-guard: 'require-non-terminal
  step-action: "stepTerminalReentry"
  derive-from-transition: 'attemptAutoRetry
  derive-action-name: 'attemptTerminalReentry
  expected-itf-predicate: "h.terminalReentryViolations > 0")

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
(export FederatedArbitrationLivenessModel)

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
  limits: "Two-attempt bounded retry abstraction; arbitrary maxAttempts and absorbing terminal phases are proved unboundedly in FederatedArbitrationLiveness.lean.")

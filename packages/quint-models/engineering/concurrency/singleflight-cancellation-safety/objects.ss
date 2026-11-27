;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Single-flight coordinator async cancellation-safety & armed notify
;;; lost-wakeup freedom model (SM9).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SingleFlightCancellationSafetyModel
        LeaderDropLockoutCountermodel
        UnarmedNotifyLostWakeupCountermodel)

(.def (SingleFlightCancellationSafetyModel @ ThreatModel.)
  identity: 'engineering.concurrency.singleflight-cancellation-safety
  family: 'engineering.concurrency.singleflight-cancellation-safety
  title: "Single-Flight Coordinator Cancellation-Safety & Armed Notify Wakeup"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("J. Dean & L. A. Barroso (CACM 2013)"
     "The Tail at Scale — coalescing concurrent disk/index refreshes while cancelling slow requests safely.")
    ("M. Herlihy & N. Shavit (2012)"
     "The Art of Multiprocessor Programming — lost-wakeup freedom requires arming wait registration prior to state re-check.")
    ("T. Tu, X. Liu, L. Song & Y. Zhang (ACM ASPLOS 2019)"
     "Understanding Real-World Concurrency Bugs in Go — blocked-waiter leaks when leader exit skips release notification."))
  quint-module: "concurrency_singleflight_cancellation_safety"
  quint-file: "SingleFlightCancellationSafety.qnt"
  domain-dir: "engineering/concurrency/singleflight-cancellation-safety"
  quint-imports: '()
  rules:
  '((conc-sf-drop-guard CONC-SF-DROP-GUARD quint)
    (conc-sf-armed-notify CONC-SF-ARMED-NOTIFY quint))
  dependencies:
  '((CONC-SF-DROP-GUARD source)
    (CONC-SF-DROP-GUARD profile)
    (CONC-SF-DROP-GUARD method)
    (CONC-SF-ARMED-NOTIFY source)
    (CONC-SF-ARMED-NOTIFY profile)
    (CONC-SF-ARMED-NOTIFY method))
  invariant: "Whenever a single-flight leader is cancelled or dropped mid-await, its RAII drop guard resets inFlight and wakes all waiters; every waiter arms notification prior to checking inFlight so zero lost-wakeup deadlocks can occur."
  parameters: '()
  state:
  '((inFlight "bool" "false")
    (leaderActive "bool" "false")
    (armedWaiters "int" "0")
    (stuckWaiters "int" "0")
    (completedSyncs "int" "0"))
  guards:
  '((drop-guard-reset-inflight false)
    (arm-notify-before-check 0))
  transitions:
  '((acquireLeader
      (action acquireLeader ()
        (if (and (not (. h inFlight)) (< (. h completedSyncs) 3))
          (set-h (inFlight true)
                 (leaderActive true))
          (keep-h))))
    (coalesceWaiter
      (action coalesceWaiter ()
        (if (and (. h inFlight) (< (. h armedWaiters) 2))
          (set-h (armedWaiters (+ (. h armedWaiters) 1))
                 (stuckWaiters (guard arm-notify-before-check 0 (+ (. h stuckWaiters) 1))))
          (keep-h))))
    (completeLeader
      (action completeLeader ()
        (if (. h leaderActive)
          (set-h (inFlight false)
                 (leaderActive false)
                 (armedWaiters 0)
                 (completedSyncs (+ (. h completedSyncs) 1)))
          (keep-h))))
    (cancelLeader
      (action cancelLeader ()
        (if (. h leaderActive)
          (set-h (leaderActive false)
                 (inFlight (guard drop-guard-reset-inflight false true))
                 (armedWaiters (if (guard drop-guard-reset-inflight false true) (. h armedWaiters) 0)))
          (keep-h))))
    (step
      (action step ()
        (any acquireLeader coalesceWaiter completeLeader cancelLeader))))
  safety:
  '(and (or (not (. h inFlight)) (. h leaderActive))
        (= (. h stuckWaiters) 0)
        (or (. h inFlight) (= (. h armedWaiters) 0)))
  traces:
  '((checkSingleFlightSafe
      (action checkSingleFlightSafe ()
        (all (assert (not (. h inFlight)))
             (assert (= (. h armedWaiters) 0))
             (assert (= (. h stuckWaiters) 0))
             (assert (> (. h completedSyncs) 0))
             (assert safety)
             (keep-h))))
    (checkSingleFlightDeadlock
      (action checkSingleFlightDeadlock ()
        (all (assert (or (and (. h inFlight) (not (. h leaderActive))) (> (. h stuckWaiters) 0)))
             (assert (not safety))
             (keep-h))))
    (cancelAndRecoverTest
      (run cancelAndRecoverTest
        (then init acquireLeader coalesceWaiter cancelLeader acquireLeader coalesceWaiter completeLeader checkSingleFlightSafe)))
    (leaderDropLockoutRefutedTest
      (run leaderDropLockoutRefutedTest
        (then init acquireLeader coalesceWaiter cancelLeaderWithoutGuard checkSingleFlightDeadlock)))
    (unarmedLostWakeupRefutedTest
      (run unarmedLostWakeupRefutedTest
        (then init acquireLeader coalesceWaiterUnarmed checkSingleFlightDeadlock))))
  countermodels: (list LeaderDropLockoutCountermodel UnarmedNotifyLostWakeupCountermodel)
  limits: "Finite 2-waiter single-flight coordinator abstraction; verifies leader cancellation drop-guard cleanup and armed notify registration, not OS thread scheduler fairness.")

(.def (LeaderDropLockoutCountermodel @ SingleFlightCancellationSafetyModel)
  identity: 'engineering.concurrency.singleflight-cancellation-safety.leader-drop-lockout
  dropped-guard: 'drop-guard-reset-inflight
  step-action: "stepLeaderDropLockout"
  derive-from-transition: 'cancelLeader
  derive-action-name: 'cancelLeaderWithoutGuard
  expected-itf-predicate: "h.inFlight and not(h.leaderActive)")

(.def (UnarmedNotifyLostWakeupCountermodel @ SingleFlightCancellationSafetyModel)
  identity: 'engineering.concurrency.singleflight-cancellation-safety.unarmed-lost-wakeup
  dropped-guard: 'arm-notify-before-check
  step-action: "stepUnarmedLostWakeup"
  derive-from-transition: 'coalesceWaiter
  derive-action-name: 'coalesceWaiterUnarmed
  expected-itf-predicate: "h.stuckWaiters > 0")

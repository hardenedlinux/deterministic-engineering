;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Single-flight coordinator async cancellation-safety & armed notify
;;; lost-wakeup freedom model (SM9).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SingleFlightCancellationSafetyModel)

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
  limits: "Finite 2-waiter single-flight coordinator abstraction; verifies leader cancellation drop-guard cleanup and armed notify registration, not OS thread scheduler fairness.")

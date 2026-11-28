;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Chase-Lev work-stealing deque protocol abstraction with two-step thief read + CAS arbitration.
;;; Co-located Yuanxu unit: single source of truth alongside WorkStealingDeque.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export WorkStealingDequeModel)

(.def (WorkStealingDequeModel @ ThreatModel.)
  identity: 'engineering.parallel.work-stealing-deque
  family: 'engineering.parallel.work-stealing-deque
  title: "Chase-Lev Work-Stealing Deque & Last-Item CAS Arbitration"
  subdomain: 'quint.engineering.parallel
  papers:
  '(("D. Chase & Y. Lev (ACM SPAA 2005)"
     "Dynamic Circular Work-Stealing Deque: owner pop vs. thief steal CAS arbitration on the final element.")
    ("N. M. Lê, A. Pop, A. Cohen & F. Zappa Nardelli (ACM PPoPP 2013)"
     "Correct and Efficient Work-Stealing for Weak Memory Models."))
  quint-module: "parallel_work_stealing"
  quint-file: "WorkStealingDeque.qnt"
  domain-dir: "engineering/parallel/work-stealing-deque"
  rules:
  '((par-ws-once PAR-WS-ONCE quint)
    (par-ws-no-cas PAR-WS-NOCAS quint))
  dependencies:
  '((PAR-WS-ONCE source)
    (PAR-WS-ONCE profile)
    (PAR-WS-ONCE method)
    (PAR-WS-NOCAS source)
    (PAR-WS-NOCAS profile)
    (PAR-WS-NOCAS method))
  invariant: "Every pushed task is taken at most once across concurrent owner pop and thief steal operations."
  limits: "Finite 1-owner/1-thief Chase-Lev deque abstraction; does not model circular array resizing or ARMv8/TSO weak memory fences.")

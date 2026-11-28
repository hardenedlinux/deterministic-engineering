;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Lock-free RCU immutable UI snapshot publication model.
;;; Co-located Yuanxu unit: single source of truth alongside UiMainThreadRcuSnapshot.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export UiMainThreadRcuSnapshotModel)

(.def (UiMainThreadRcuSnapshotModel @ ThreatModel.)
  identity: 'engineering.concurrency.ui-mainthread-rcu-snapshot
  family: 'engineering.concurrency.ui-mainthread-rcu-snapshot
  title: "Lock-Free Main-Thread RCU UI Snapshot Publication"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("P. E. McKenney & J. D. Slingwine (PDCS 1998)"
     "Read-Copy Update: Using Execution History to Solve Concurrency Problems — zero-lock reader access to immutable snapshots.")
    ("L. Lamport (CACM 1977)"
     "Concurrent Reading and Writing — wait-free snapshot reads without reader-writer mutex contention.")
    ("M. P. Herlihy & J. M. Wing (ACM TOPLAS 1990)"
     "Linearizability: A Correctness Condition for Concurrent Objects."))
  quint-module: "concurrency_ui_rcu_snapshot"
  quint-file: "UiMainThreadRcuSnapshot.qnt"
  domain-dir: "engineering/concurrency/ui-mainthread-rcu-snapshot"
  rules:
  '((ui-rcu-nonblocking UI-RCU-NONBLOCK quint)
    (ui-rcu-linearizable UI-RCU-LINEAR quint))
  dependencies:
  '((UI-RCU-NONBLOCK source)
    (UI-RCU-NONBLOCK profile)
    (UI-RCU-NONBLOCK method)
    (UI-RCU-LINEAR source)
    (UI-RCU-LINEAR profile)
    (UI-RCU-LINEAR method))
  invariant: "The UI render main thread never blocks on a background I/O lock, observes only monotonically published complete snapshot generations (renderGen <= publishedGen), and background staging completes off-lock before atomic swap."
  limits: "Finite 4-generation single-writer RCU UI snapshot abstraction; does not model OS page faults, GPU command-buffer stalls, or multi-writer CAS contention.")

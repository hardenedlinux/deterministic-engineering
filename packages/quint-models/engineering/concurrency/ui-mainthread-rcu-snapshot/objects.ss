;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Lock-free RCU immutable UI snapshot publication model.
;;; Co-located Yuanxu unit: single source of truth alongside UiMainThreadRcuSnapshot.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export UiMainThreadRcuSnapshotModel
        BlockingIOReloadCountermodel
        TornSnapshotPublishCountermodel)

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
  quint-imports: '()
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
  parameters: '()
  state:
  '((publishedGen "int" "0")
    (stagingGen "int" "0")
    (stagingActive "bool" "false")
    (renderGen "int" "0")
    (writerHoldsLock "bool" "false")
    (mainStalled "bool" "false"))
  guards:
  '((off-thread-io-lock-free
      (not (. h writerHoldsLock)))
    (atomic-publish-after-stage
      (and (. h stagingActive) (> (. h stagingGen) (. h publishedGen)))))
  transitions:
  '((beginStageIO
      (action beginStageIO ()
        (if (and (not (. h stagingActive)) (< (. h publishedGen) 4))
          (set-h (stagingActive #t)
                 (stagingGen (+ (. h publishedGen) 1))
                 (writerHoldsLock (guard off-thread-io-lock-free #f #t)))
          (keep-h))))
    (publishSnapshot
      (action publishSnapshot ()
        (if (guard atomic-publish-after-stage
                   (and (. h stagingActive) (> (. h stagingGen) (. h publishedGen))))
          (set-h (publishedGen (. h stagingGen))
                 (stagingGen 0)
                 (stagingActive #f)
                 (writerHoldsLock #f))
          (keep-h))))
    (renderFrame
      (action renderFrame ()
        (if (. h writerHoldsLock)
          (set-h (mainStalled #t))
          (set-h (renderGen (. h publishedGen))))))
    (step
      (action step ()
        (any beginStageIO publishSnapshot renderFrame))))
  safety:
  '(and (not (. h mainStalled))
        (not (. h writerHoldsLock))
        (<= (. h renderGen) (. h publishedGen))
        (or (not (. h stagingActive)) (> (. h stagingGen) (. h publishedGen))))
  traces:
  '((checkSafeRender
      (action checkSafeRender ()
        (all (assert (not (. h mainStalled)))
             (assert (= (. h renderGen) (. h publishedGen)))
             (assert safety)
             (keep-h))))
    (nonBlockingSwapTest
      (run nonBlockingSwapTest
        (then init beginStageIO renderFrame publishSnapshot renderFrame checkSafeRender)))
    (blockingIOReloadViolatesSafetyTest
      (run blockingIOReloadViolatesSafetyTest
        (then init beginStageIOBlocking renderFrame
              (all (assert (. h mainStalled))
                   (assert (not safety))
                   (keep-h)))))
    (tornPublishViolatesSafetyTest
      (run tornPublishViolatesSafetyTest
        (then init beginStageIO publishSnapshot renderFrame publishSnapshotUnchecked
              (all (assert (not safety))
                   (keep-h))))))
  countermodels: (list BlockingIOReloadCountermodel TornSnapshotPublishCountermodel)
  limits: "Finite 4-generation single-writer RCU UI snapshot abstraction; does not model OS page faults, GPU command-buffer stalls, or multi-writer CAS contention.")

(.def (BlockingIOReloadCountermodel @ UiMainThreadRcuSnapshotModel)
  identity: 'engineering.concurrency.ui-mainthread-rcu-snapshot.blocking-io-reload
  dropped-guard: 'off-thread-io-lock-free
  step-action: "stepBlockingIOReload"
  derive-from-transition: 'beginStageIO
  derive-action-name: 'beginStageIOBlocking
  expected-itf-predicate: "h.mainStalled == true or h.writerHoldsLock == true")

(.def (TornSnapshotPublishCountermodel @ UiMainThreadRcuSnapshotModel)
  identity: 'engineering.concurrency.ui-mainthread-rcu-snapshot.torn-publish
  dropped-guard: 'atomic-publish-after-stage
  step-action: "stepTornPublish"
  derive-from-transition: 'publishSnapshot
  derive-action-name: 'publishSnapshotUnchecked
  expected-itf-predicate: "h.renderGen > h.publishedGen or (h.stagingActive == true and h.stagingGen <= h.publishedGen)")

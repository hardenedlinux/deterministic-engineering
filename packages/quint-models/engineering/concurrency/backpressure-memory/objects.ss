;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned bounded backpressure & memory ownership formal model.
;;; Co-located Yuanxu unit: single source of truth alongside BackpressureOwners.qnt and README.org.
;;; Models disjoint ownership partition conservation (queued, running, returned, cleanup),
;;; bounded admission/queue capacity, and non-abortable cleanup permit retention under cancellation.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export BackpressureOwnersModel
        BackpressureEarlyReleaseCountermodel
        BackpressureOverAdmitCountermodel
        BackpressureQueueOverflowCountermodel)

(.def (BackpressureOwnersModel @ ThreatModel.)
  identity: 'engineering.concurrency.backpressure-memory
  family: 'engineering.concurrency.backpressure-memory
  title: "Bounded Backpressure & Disjoint Memory-Ownership Conservation"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("Reactive Streams Specification (2015)"
     "Asynchronous stream processing with non-blocking bounded backpressure.")
    ("J. Mace, R. Roelke & R. Fonseca (SOSP 2015)"
     "Pivot Tracing / End-to-end bounded resource ownership and queue isolation across async boundaries.")
    ("Deterministic Engineering (10.25 / 10.77)"
     "Bounded ownership conservation across queued, running, returned, and non-abortable cleanup states."))
  quint-module: "BackpressureOwners"
  quint-file: "BackpressureOwners.qnt"
  domain-dir: "engineering/concurrency/backpressure-memory"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((backpressure-safe BP-OWN-SAFE quint)
    (backpressure-countermodel BP-OWN-COUNTER quint))
  dependencies:
  '((BP-OWN-SAFE source)
    (BP-OWN-SAFE profile)
    (BP-OWN-SAFE method)
    (BP-OWN-COUNTER source)
    (BP-OWN-COUNTER profile)
    (BP-OWN-COUNTER method))
  invariant: "Every admitted job belongs to exactly one mutually disjoint ownership state (queued, running, returned, or cleanup), total admitted permits never exceed limit, queued jobs never exceed queueLimit, and completed (done) jobs hold no active permit."
  parameters: '()
  state:
  '((limit "int" "2")
    (queueLimit "int" "1")
    (admitted "Set[int]" "Set()")
    (queued "Set[int]" "Set()")
    (running "Set[int]" "Set()")
    (returned "Set[int]" "Set()")
    (cleanup "Set[int]" "Set()")
    (done "Set[int]" "Set()"))
  guards:
  '((admit-disjoint-job
      (and (not (contains owners j))
           (not (contains (. h done) j))))
    (admit-capacity-bound
      (< (size (. h admitted)) (. h limit)))
    (admit-queue-bound
      (< (size (. h queued)) (. h queueLimit)))
    (cancel-retains-permit
      (subseteq (. h cleanup) (. h admitted))))
  transitions:
  '((jobs
      (pure-val jobs (set 0 1 2 3)))
    (owners
      (val owners
        (union (union (union (. h queued) (. h running)) (. h returned)) (. h cleanup))))
    (admitJob
      (action admitJob ((j "int")) "bool"
        (all (guard admit-disjoint-job
                    (and (not (contains owners j))
                         (not (contains (. h done) j))))
             (guard admit-capacity-bound
                    (< (size (. h admitted)) (. h limit)))
             (guard admit-queue-bound
                    (< (size (. h queued)) (. h queueLimit)))
             (set-h (admitted (union (. h admitted) (set j)))
                    (queued (union (. h queued) (set j)))))))
    (startJob
      (action startJob ((j "int")) "bool"
        (all (contains (. h queued) j)
             (set-h (queued (exclude (. h queued) (set j)))
                    (running (union (. h running) (set j)))))))
    (finishJob
      (action finishJob ((j "int")) "bool"
        (all (contains (. h running) j)
             (set-h (running (exclude (. h running) (set j)))
                    (returned (union (. h returned) (set j)))))))
    (cancelJob
      (action cancelJob ((j "int")) "bool"
        (all (contains (. h running) j)
             (set-h (running (exclude (. h running) (set j)))
                    (cleanup (union (. h cleanup) (set j)))
                    (admitted (guard cancel-retains-permit
                                     (. h admitted)
                                     (exclude (. h admitted) (set j))))))))
    (drainJob
      (action drainJob ((j "int")) "bool"
        (all (contains (. h returned) j)
             (set-h (returned (exclude (. h returned) (set j)))
                    (admitted (exclude (. h admitted) (set j)))
                    (done (union (. h done) (set j)))))))
    (cleanJob
      (action cleanJob ((j "int")) "bool"
        (all (contains (. h cleanup) j)
             (set-h (cleanup (exclude (. h cleanup) (set j)))
                    (admitted (exclude (. h admitted) (set j)))
                    (done (union (. h done) (set j)))))))
    (admit
      (action admit ()
        (nondet ((j jobs)) (call admitJob j))))
    (start
      (action start ()
        (nondet ((j jobs)) (call startJob j))))
    (finish
      (action finish ()
        (nondet ((j jobs)) (call finishJob j))))
    (cancel
      (action cancel ()
        (nondet ((j jobs)) (call cancelJob j))))
    (drain
      (action drain ()
        (nondet ((j jobs)) (call drainJob j))))
    (clean
      (action clean ()
        (nondet ((j jobs)) (call cleanJob j))))
    (step
      (action step ()
        (any admit start finish cancel drain clean (keep-h)))))
  safety:
  '(and (= owners (. h admitted))
        (<= (size (. h admitted)) (. h limit))
        (<= (size (. h queued)) (. h queueLimit))
        (= (size (intersect (. h queued) (. h running))) 0)
        (= (size (intersect (. h queued) (. h returned))) 0)
        (= (size (intersect (. h queued) (. h cleanup))) 0)
        (= (size (intersect (. h running) (. h returned))) 0)
        (= (size (intersect (. h running) (. h cleanup))) 0)
        (= (size (intersect (. h returned) (. h cleanup))) 0)
        (= (size (intersect (. h done) owners)) 0))
  traces:
  '((validLifecycleTest
      (run validLifecycleTest
        (then init (call admitJob 0) (call startJob 0) (call finishJob 0) (call drainJob 0)
              (all (assert safety)
                   (assert (= (size (. h done)) 1))
                   (assert (= (size (. h admitted)) 0))
                   (keep-h)))))
    (cancelCleanupTest
      (run cancelCleanupTest
        (then init (call admitJob 0) (call startJob 0) (call cancelJob 0)
              (all (assert safety)
                   (assert (= (size (. h cleanup)) 1))
                   (assert (subseteq (. h cleanup) (. h admitted)))
                   (keep-h))
              (call cleanJob 0)
              (all (assert safety)
                   (assert (= (size (. h done)) 1))
                   (keep-h)))))
    (earlyReleaseViolatesSafetyTest
      (run earlyReleaseViolatesSafetyTest
        (then init (call admitJob 0) (call startJob 0) (call cancelJobEarlyRelease 0)
              (all (assert (not safety))
                   (assert (> (size (. h cleanup)) 0))
                   (assert (not (subseteq (. h cleanup) (. h admitted))))
                   (keep-h)))))
    (overAdmitViolatesSafetyTest
      (run overAdmitViolatesSafetyTest
        (then init (call admitJob 0) (call startJob 0) (call admitJob 1) (call startJob 1)
              (call admitJobOverCapacity 2)
              (all (assert (not safety))
                   (assert (> (size (. h admitted)) (. h limit)))
                   (keep-h)))))
    (queueOverflowViolatesSafetyTest
      (run queueOverflowViolatesSafetyTest
        (then init (call admitJob 0) (call admitJobQueueOverflow 1)
              (all (assert (not safety))
                   (assert (> (size (. h queued)) (. h queueLimit)))
                   (keep-h))))))
  countermodels:
  (list BackpressureEarlyReleaseCountermodel
        BackpressureOverAdmitCountermodel
        BackpressureQueueOverflowCountermodel)
  limits: "Finite-state bounded ownership abstraction over 4 discrete job IDs (limit=2, queueLimit=1); makes no Rust scheduler, allocator, byte-accounting, or kernel memory-reclamation claim.")

(.def (BackpressureEarlyReleaseCountermodel @ BackpressureOwnersModel)
  identity: 'engineering.concurrency.backpressure-memory.early-release
  dropped-guard: 'cancel-retains-permit
  step-action: "stepEarlyRelease"
  derive-from-transition: 'cancelJob
  derive-action-name: 'cancelJobEarlyRelease
  derive-step-call: '(nondet ((j jobs)) (call cancelJobEarlyRelease j))
  expected-itf-predicate: "size(h.cleanup) > 0 and not(subseteq(h.cleanup, h.admitted))")

(.def (BackpressureOverAdmitCountermodel @ BackpressureOwnersModel)
  identity: 'engineering.concurrency.backpressure-memory.over-admit
  dropped-guard: 'admit-capacity-bound
  step-action: "stepOverAdmit"
  derive-from-transition: 'admitJob
  derive-action-name: 'admitJobOverCapacity
  derive-step-call: '(nondet ((j jobs)) (call admitJobOverCapacity j))
  expected-itf-predicate: "size(h.admitted) > h.limit")

(.def (BackpressureQueueOverflowCountermodel @ BackpressureOwnersModel)
  identity: 'engineering.concurrency.backpressure-memory.queue-overflow
  dropped-guard: 'admit-queue-bound
  step-action: "stepQueueOverflow"
  derive-from-transition: 'admitJob
  derive-action-name: 'admitJobQueueOverflow
  derive-step-call: '(nondet ((j jobs)) (call admitJobQueueOverflow j))
  expected-itf-predicate: "size(h.queued) > h.queueLimit")

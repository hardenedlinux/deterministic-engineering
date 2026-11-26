;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Generation-fenced coalescing async mailbox model.
;;; Co-located Yuanxu unit: single source of truth alongside FencedCoalescingMailbox.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export FencedCoalescingMailboxModel
        MailboxFloodCountermodel
        StaleAsyncOverwriteCountermodel)

(.def (FencedCoalescingMailboxModel @ ThreatModel.)
  identity: 'engineering.concurrency.fenced-coalescing-mailbox
  family: 'engineering.concurrency.fenced-coalescing-mailbox
  title: "Generation-Fenced Coalescing Async Mailbox"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("M. Kleppmann (2016)"
     "How to do distributed locking — monotonic fencing tokens rejecting stale in-flight completions.")
    ("Reactive Streams Specification (2015)"
     "Bounded non-blocking backpressure and single-slot latest-value coalescing across async boundaries.")
    ("C. Hewitt, P. Bishop & R. Steiger (IJCAI 1973)"
     "Universal Modular ACTOR Formalism — bounded mailbox isolation for concurrent message dispatch."))
  quint-module: "concurrency_fenced_mailbox"
  quint-file: "FencedCoalescingMailbox.qnt"
  domain-dir: "engineering/concurrency/fenced-coalescing-mailbox"
  quint-imports: '()
  rules:
  '((mailbox-coalesced MAILBOX-COALESCE quint)
    (mailbox-epoch-fenced MAILBOX-FENCE quint))
  dependencies:
  '((MAILBOX-COALESCE source)
    (MAILBOX-COALESCE profile)
    (MAILBOX-COALESCE method)
    (MAILBOX-FENCE source)
    (MAILBOX-FENCE profile)
    (MAILBOX-FENCE method))
  invariant: "Pending mailbox depth never exceeds 1 via latest-wins coalescing, in-flight workers stay bounded, and committed UI state epoch never regresses behind the highest committed epoch (appliedEpoch == maxAppliedEpoch <= activeEpoch)."
  parameters: '()
  state:
  '((activeEpoch "int" "0")
    (pendingSlots "int" "0")
    (inflight "int" "0")
    (jobEpoch "int" "0")
    (appliedEpoch "int" "0")
    (maxAppliedEpoch "int" "0"))
  guards:
  '((coalesce-single-slot
      (<= (. h pendingSlots) 1))
    (epoch-fence-commit
      (>= (. h jobEpoch) (. h activeEpoch))))
  transitions:
  '((triggerRequest
      (action triggerRequest ()
        (if (< (. h activeEpoch) 4)
          (set-h (activeEpoch (+ (. h activeEpoch) 1))
                 (pendingSlots (guard coalesce-single-slot
                                      (if (< (. h pendingSlots) 1) (+ (. h pendingSlots) 1) 1)
                                      (+ (. h pendingSlots) 1))))
          (keep-h))))
    (dispatchWorker
      (action dispatchWorker ()
        (if (and (> (. h pendingSlots) 0) (< (. h inflight) 2))
          (set-h (pendingSlots (- (. h pendingSlots) 1))
                 (inflight (+ (. h inflight) 1))
                 (jobEpoch (. h activeEpoch)))
          (keep-h))))
    (applyDirectEpoch
      (action applyDirectEpoch ()
        (if (and (> (. h activeEpoch) (. h maxAppliedEpoch))
                 (<= (. h activeEpoch) 4))
          (set-h (appliedEpoch (. h activeEpoch))
                 (maxAppliedEpoch (. h activeEpoch)))
          (keep-h))))
    (completeWorker
      (action completeWorker ()
        (if (> (. h inflight) 0)
          (if (guard epoch-fence-commit (>= (. h jobEpoch) (. h activeEpoch)))
            (set-h (inflight (- (. h inflight) 1))
                   (appliedEpoch (. h jobEpoch))
                   (maxAppliedEpoch (if (> (. h jobEpoch) (. h maxAppliedEpoch))
                                      (. h jobEpoch)
                                      (. h maxAppliedEpoch))))
            (set-h (inflight (- (. h inflight) 1))))
          (keep-h))))
    (step
      (action step ()
        (any triggerRequest dispatchWorker applyDirectEpoch completeWorker))))
  safety:
  '(and (<= (. h pendingSlots) 1)
        (<= (. h inflight) 2)
        (= (. h appliedEpoch) (. h maxAppliedEpoch))
        (<= (. h maxAppliedEpoch) (. h activeEpoch)))
  traces:
  '((coalescedStaleDropTest
      (run coalescedStaleDropTest
        (then init triggerRequest dispatchWorker triggerRequest applyDirectEpoch completeWorker
              (all (assert (= (. h appliedEpoch) 2))
                   (assert (= (. h inflight) 0))
                   (assert safety)
                   (keep-h)))))
    (mailboxFloodViolatesSafetyTest
      (run mailboxFloodViolatesSafetyTest
        (then init triggerRequestFlood triggerRequestFlood
              (all (assert (> (. h pendingSlots) 1))
                   (assert (not safety))
                   (keep-h)))))
    (staleOverwriteViolatesSafetyTest
      (run staleOverwriteViolatesSafetyTest
        (then init triggerRequest dispatchWorker triggerRequest applyDirectEpoch completeWorkerUnfenced
              (all (assert (< (. h appliedEpoch) (. h maxAppliedEpoch)))
                   (assert (not safety))
                   (keep-h))))))
  countermodels: (list MailboxFloodCountermodel StaleAsyncOverwriteCountermodel)
  limits: "Finite 4-epoch single-slot coalescing mailbox abstraction; does not model OS timer jitter, multi-lane priority preemption, or payload serialization sizes.")

(.def (MailboxFloodCountermodel @ FencedCoalescingMailboxModel)
  identity: 'engineering.concurrency.fenced-coalescing-mailbox.mailbox-flood
  dropped-guard: 'coalesce-single-slot
  step-action: "stepMailboxFlood"
  derive-from-transition: 'triggerRequest
  derive-action-name: 'triggerRequestFlood
  expected-itf-predicate: "h.pendingSlots > 1")

(.def (StaleAsyncOverwriteCountermodel @ FencedCoalescingMailboxModel)
  identity: 'engineering.concurrency.fenced-coalescing-mailbox.stale-overwrite
  dropped-guard: 'epoch-fence-commit
  step-action: "stepStaleOverwrite"
  derive-from-transition: 'completeWorker
  derive-action-name: 'completeWorkerUnfenced
  expected-itf-predicate: "h.appliedEpoch < h.maxAppliedEpoch")

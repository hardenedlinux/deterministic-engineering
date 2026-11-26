;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Distributed Saga Compensating Transactions & Idempotency Tombstone model.
;;; Co-located Yuanxu unit: single source of truth alongside SagaCompensationIdempotency.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SagaCompensationModel
        MissingIdempotencyDedupCountermodel
        LateRetryAfterCompensationCountermodel)

(.def (SagaCompensationModel @ ThreatModel.)
  identity: 'engineering.concurrency.saga-compensation-idempotency
  family: 'engineering.concurrency.saga-compensation-idempotency
  title: "Distributed Saga Compensation & Idempotency Tombstone Fence"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("H. Garcia-Molina & K. Salem (ACM SIGMOD 1987)"
     "Sagas: long-lived distributed transactions decomposed into compensating sub-transactions.")
    ("P. Helland (CIDR 2007 / ACM Queue 2012)"
     "Life Beyond Distributed Transactions & Idempotence Is Not a Medical Condition: duplicate-retry dedup and tombstone fencing."))
  quint-module: "concurrency_saga_compensation"
  quint-file: "SagaCompensationIdempotency.qnt"
  domain-dir: "engineering/concurrency/saga-compensation-idempotency"
  quint-imports: '()
  rules:
  '((idempotency-key-dedup SAGA-IDEMP-DEDUP quint)
    (compensation-tombstone-fence SAGA-TOMBSTONE-FENCE quint))
  dependencies:
  '((SAGA-IDEMP-DEDUP source)
    (SAGA-IDEMP-DEDUP profile)
    (SAGA-IDEMP-DEDUP method)
    (SAGA-TOMBSTONE-FENCE source)
    (SAGA-TOMBSTONE-FENCE profile)
    (SAGA-TOMBSTONE-FENCE method))
  invariant: "Step A executes at most once despite network retries, and once compensation aborts the saga, net applied effects stay strictly zero even under late in-flight deliveries."
  parameters: '()
  state:
  '((reqInFlight "bool" "false")
    (replyLost "bool" "false")
    (processedKeys "Set[int]" "Set()")
    (tombstoned "bool" "false")
    (debitCount "int" "0")
    (refundCount "int" "0")
    (stepBFailed "bool" "false")
    (sagaAborted "bool" "false"))
  guards:
  '((idempotency-key-dedup (not (contains (. h processedKeys) 1)))
    (compensation-tombstone-fence (not (. h tombstoned))))
  transitions:
  '((sendStepA
      (action sendStepA ()
        (if (and (not (. h sagaAborted)) (not (. h reqInFlight)))
          (set-h (reqInFlight #t))
          (keep-h))))
    (execStepA
      (action execStepA ()
        (if (. h reqInFlight)
          (if (and (guard idempotency-key-dedup (not (contains (. h processedKeys) 1)))
                   (guard compensation-tombstone-fence (not (. h tombstoned))))
            (set-h (processedKeys (union (. h processedKeys) (set 1)))
                   (debitCount (+ (. h debitCount) 1))
                   (reqInFlight #f))
            (set-h (reqInFlight #f)))
          (keep-h))))
    (loseReplyAndRetryA
      (action loseReplyAndRetryA ()
        (if (and (not (. h sagaAborted))
                 (contains (. h processedKeys) 1)
                 (not (. h reqInFlight)))
          (set-h (reqInFlight #t)
                 (replyLost #t))
          (keep-h))))
    (failStepB
      (action failStepB ()
        (if (and (not (. h stepBFailed)) (not (. h sagaAborted)))
          (set-h (stepBFailed #t))
          (keep-h))))
    (compensateA
      (action compensateA ()
        (if (and (. h stepBFailed) (not (. h sagaAborted)))
          (set-h (tombstoned #t)
                 (refundCount (. h debitCount))
                 (sagaAborted #t))
          (keep-h))))
    (step
      (action step ()
        (any sendStepA execStepA loseReplyAndRetryA failStepB compensateA))))
  safety:
  '(and (<= (. h debitCount) 1)
        (<= (. h refundCount) (. h debitCount))
        (or (not (. h sagaAborted)) (= (. h debitCount) (. h refundCount))))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (retryDeduplicatedAndCompensatedTest
      (run retryDeduplicatedAndCompensatedTest
        (then init sendStepA execStepA loseReplyAndRetryA execStepA failStepB compensateA
              (all (assert (= (. h debitCount) 1))
                   (assert (= (. h refundCount) 1))
                   (assert (. h sagaAborted))
                   (assert safety)
                   (keep-h)))))
    (lateRetryBlockedByTombstoneTest
      (run lateRetryBlockedByTombstoneTest
        (then init sendStepA failStepB compensateA execStepA
              (all (assert (= (. h debitCount) 0))
                   (assert (= (. h refundCount) 0))
                   (assert (. h tombstoned))
                   (assert safety)
                   (keep-h)))))
    (duplicateDebitCountermodelTest
      (run duplicateDebitCountermodelTest
        (then init sendStepA execStepA loseReplyAndRetryA execStepANoDedup checkUnsafe)))
    (lateZombieDebitCountermodelTest
      (run lateZombieDebitCountermodelTest
        (then init sendStepA failStepB compensateA execStepANoTombstone checkUnsafe))))
  countermodels:
  (list MissingIdempotencyDedupCountermodel
        LateRetryAfterCompensationCountermodel)
  limits: "Finite two-step Saga orchestrator abstraction with single idempotency key; does not model multi-service cyclic dependencies, TTL key eviction policies, or partial compensating failure.")

(.def (MissingIdempotencyDedupCountermodel @ SagaCompensationModel)
  identity: 'engineering.concurrency.saga-compensation-idempotency.missing-idempotency-dedup
  dropped-guard: 'idempotency-key-dedup
  step-action: "stepMissingIdempotency"
  derive-from-transition: 'execStepA
  derive-action-name: 'execStepANoDedup
  expected-itf-predicate: "h.debitCount >= 2")

(.def (LateRetryAfterCompensationCountermodel @ SagaCompensationModel)
  identity: 'engineering.concurrency.saga-compensation-idempotency.late-retry-after-compensation
  dropped-guard: 'compensation-tombstone-fence
  step-action: "stepLateRetryZombie"
  derive-from-transition: 'execStepA
  derive-action-name: 'execStepANoTombstone
  expected-itf-predicate: "h.sagaAborted == true and h.debitCount != h.refundCount")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Distributed Saga Compensating Transactions & Idempotency Tombstone model.
;;; Co-located Yuanxu unit: single source of truth alongside SagaCompensationIdempotency.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SagaCompensationModel)

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
  limits: "Finite two-step Saga orchestrator abstraction with single idempotency key; does not model multi-service cyclic dependencies, TTL key eviction policies, or partial compensating failure.")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Structured async task abort-on-drop, transaction-safe connection pool lease
;;; hygiene, and semaphore-bounded fan-out with panic-safe correlation IDs (SM19).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export TaskAndPoolCancellationEnvelopeModel)

(.def (TaskAndPoolCancellationEnvelopeModel @ ThreatModel.)
  identity: 'engineering.concurrency.task-and-pool-cancellation-envelope
  family: 'engineering.concurrency.task-and-pool-cancellation-envelope
  title: "Structured Task Abort-on-Drop, Transaction-Safe Pool Lease & Bounded Fan-Out Envelope"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("N. J. Smith (2018)"
     "Notes on Structured Concurrency — async scopes must abort all spawned child tasks on cancellation rather than detaching bare JoinHandles.")
    ("J. Gray & A. Reuter (1993)"
     "Transaction Processing: Concepts and Techniques — dirty uncommitted transactions cancelled mid-flight must never return poisoned connections to a shared pool.")
    ("M. Welsh, D. Culler & E. Brewer (ACM SOSP 2001)"
     "SEDA — bounded concurrency semaphores prevent unbounded parallel task fan-out while caller-owned correlation tables survive worker panics."))
  quint-module: "concurrency_task_and_pool_cancellation_envelope"
  quint-file: "TaskAndPoolCancellationEnvelope.qnt"
  domain-dir: "engineering/concurrency/task-and-pool-cancellation-envelope"
  rules:
  '((conc-cancel-abort-on-drop CONC-CANCEL-ABORT-ON-DROP quint)
    (conc-cancel-discard-dirty-lease CONC-CANCEL-DISCARD-DIRTY-LEASE quint)
    (conc-cancel-bounded-fanout-id CONC-CANCEL-BOUNDED-FANOUT-ID quint))
  dependencies:
  '((CONC-CANCEL-ABORT-ON-DROP source)
    (CONC-CANCEL-ABORT-ON-DROP profile)
    (CONC-CANCEL-ABORT-ON-DROP method)
    (CONC-CANCEL-DISCARD-DIRTY-LEASE source)
    (CONC-CANCEL-DISCARD-DIRTY-LEASE profile)
    (CONC-CANCEL-DISCARD-DIRTY-LEASE method)
    (CONC-CANCEL-BOUNDED-FANOUT-ID source)
    (CONC-CANCEL-BOUNDED-FANOUT-ID profile)
    (CONC-CANCEL-BOUNDED-FANOUT-ID method))
  invariant: "Cancelling a parent async scope aborts all child tasks (orphanTasks == 0), cancelling an uncommitted DB transaction never returns a poisoned connection to the pool (poisonedPoolConns == 0), and parallel effect batches respect maxConcurrency while preserving exact correlation IDs across worker panics (fanoutBreaches == 0 and lostCorrelationIds == 0)."
  limits: "Finite 2-lane pool and 2-permit semaphore abstraction; verifies abort-on-drop task containment, dirty-lease pool isolation, and bounded panic-safe correlation, not OS thread scheduling fairness or SQLite B-tree locking internals.")

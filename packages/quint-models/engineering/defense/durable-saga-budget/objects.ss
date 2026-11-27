;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B6 (10.163): Durable Compensable Multi-Agent Sagas,
;;; Irreversible Pivot Boundaries, and Linear Resource/Budget Conservation.
;;; Proves three invariants for external-world agent tool orchestration:
;;;   1. Linear Budget Conservation: spentBudget + remainingBudget == rootBudget
;;;      and remainingBudget >= 0 (budgetViolations == 0).
;;;   2. Write-Ahead Compensation: no compensable external side effect executes
;;;      before its M1 compensator spec is durably registered (unregisteredCompViolations == 0).
;;;   3. Pivot Point-of-No-Return & UnknownEffect Fence: backward compensation is
;;;      strictly forbidden once the irreversible pivot is crossed or while an
;;;      external step outcome is PendingUnknownEffect (pivotOrUnknownRollbackViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export DurableSagaBudgetModel)

(.def (DurableSagaBudgetModel @ ThreatModel.)
  identity: 'engineering.defense.durable-saga-budget
  family: 'engineering.defense.durable-saga-budget
  title: "Durable Compensable Agent Sagas, Pivot Boundaries & Linear Budget Conservation"
  subdomain: 'quint.engineering.defense
  papers:
  '(("H. Garcia-Molina & K. Salem (ACM SIGMOD 1987)"
     "Sagas: Long-lived transactions with compensating actions and pivot boundaries.")
    ("P. Helland (CIDR 2007)"
     "Life Beyond Distributed Transactions: an Apostate's Opinion (idempotent forward & compensating effects).")
    ("Deterministic Engineering (10.156 / 10.163)"
     "Write-ahead M1 compensation logging, PendingUnknownEffect fencing, and linear M3 compute-budget conservation."))
  quint-module: "durable_saga_budget"
  quint-file: "DurableSagaBudget.qnt"
  domain-dir: "engineering/defense/durable-saga-budget"
  rules:
  '((durable-saga-budget-safe DE-SAGA-SAFE quint)
    (durable-saga-budget-countermodel DE-SAGA-COUNTER quint))
  dependencies:
  '((DE-SAGA-SAFE source)
    (DE-SAGA-SAFE profile)
    (DE-SAGA-SAFE method)
    (DE-SAGA-COUNTER source)
    (DE-SAGA-COUNTER profile)
    (DE-SAGA-COUNTER method))
  invariant: "Linear budget conservation holds (spentBudget + remainingBudget == rootBudget and remainingBudget >= 0), no step executes over budget (budgetViolations == 0) or without a write-ahead compensator (unregisteredCompViolations == 0), and no backward rollback executes past an irreversible pivot or unresolved PendingUnknownEffect (pivotOrUnknownRollbackViolations == 0)."
  limits: "Finite single-compensable-step + single-pivot Saga and integer compute-budget abstraction; does not model arbitrary multi-currency exchange fluctuation, external vendor compensation outage retries beyond idempotency keys, or continuous real-time GPU metering.")

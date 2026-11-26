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
(export DurableSagaBudgetModel
        BudgetOverrunCountermodel
        UnregisteredCompensatorCountermodel
        PivotRollbackViolationCountermodel)

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
  verify-depth: 10
  countermodel-depth: 6
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
  parameters: '()
  state:
  '((rootBudget "int" "2")
    (remainingBudget "int" "2")
    (spentBudget "int" "0")
    (compensatorRegistered "bool" "false")
    (step1Done "bool" "false")
    (step1Unknown "bool" "false")
    (pivotCrossed "bool" "false")
    (compensated "bool" "false")
    (budgetViolations "int" "0")
    (unregisteredCompViolations "int" "0")
    (pivotOrUnknownRollbackViolations "int" "0"))
  guards:
  '((require-write-ahead-compensator (. h compensatorRegistered))
    (enforce-budget-conservation (> (. h remainingBudget) 0))
    (forbid-rollback-past-pivot-or-unknown
      (and (. h step1Done) (not (. h pivotCrossed)) (not (. h step1Unknown)))))
  transitions:
  '((registerCompensator
      (action registerCompensator ()
        (if (not (. h compensatorRegistered))
          (set-h (compensatorRegistered #t))
          (keep-h))))
    (executeCompensableStep1
      (action executeCompensableStep1 ()
        (if (and (not (. h step1Done))
                 (not (. h step1Unknown))
                 (guard require-write-ahead-compensator (. h compensatorRegistered))
                 (guard enforce-budget-conservation (> (. h remainingBudget) 0)))
          (set-h (step1Done #t)
                 (remainingBudget (- (. h remainingBudget) 1))
                 (spentBudget (+ (. h spentBudget) 1))
                 (unregisteredCompViolations
                   (if (. h compensatorRegistered)
                     (. h unregisteredCompViolations)
                     (+ (. h unregisteredCompViolations) 1)))
                 (budgetViolations
                   (if (> (. h remainingBudget) 0)
                     (. h budgetViolations)
                     (+ (. h budgetViolations) 1))))
          (keep-h))))
    (crashStep1Unknown
      (action crashStep1Unknown ()
        (if (and (not (. h step1Done))
                 (not (. h step1Unknown))
                 (. h compensatorRegistered)
                 (> (. h remainingBudget) 0))
          (set-h (step1Unknown #t)
                 (remainingBudget (- (. h remainingBudget) 1))
                 (spentBudget (+ (. h spentBudget) 1)))
          (keep-h))))
    (reconcileStep1Committed
      (action reconcileStep1Committed ()
        (if (. h step1Unknown)
          (set-h (step1Unknown #f) (step1Done #t))
          (keep-h))))
    (crossIrreversiblePivot
      (action crossIrreversiblePivot ()
        (if (and (. h step1Done)
                 (not (. h pivotCrossed))
                 (not (. h compensated))
                 (> (. h remainingBudget) 0))
          (set-h (pivotCrossed #t)
                 (remainingBudget (- (. h remainingBudget) 1))
                 (spentBudget (+ (. h spentBudget) 1)))
          (keep-h))))
    (spendExtraCompute
      (action spendExtraCompute ()
        (if (> (. h remainingBudget) 0)
          (set-h (remainingBudget (- (. h remainingBudget) 1))
                 (spentBudget (+ (. h spentBudget) 1)))
          (keep-h))))
    (compensateStep1
      (action compensateStep1 ()
        (if (and (not (. h compensated))
                 (guard forbid-rollback-past-pivot-or-unknown
                   (and (. h step1Done) (not (. h pivotCrossed)) (not (. h step1Unknown)))))
          (set-h (compensated #t)
                 (step1Done #f)
                 (pivotOrUnknownRollbackViolations
                   (if (and (. h step1Done) (not (. h pivotCrossed)) (not (. h step1Unknown)))
                     (. h pivotOrUnknownRollbackViolations)
                     (+ (. h pivotOrUnknownRollbackViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any registerCompensator executeCompensableStep1 crashStep1Unknown
             reconcileStep1Committed crossIrreversiblePivot spendExtraCompute
             compensateStep1))))
  safety:
  '(and (= (+ (. h spentBudget) (. h remainingBudget)) (. h rootBudget))
        (>= (. h remainingBudget) 0)
        (= (. h budgetViolations) 0)
        (= (. h unregisteredCompViolations) 0)
        (= (. h pivotOrUnknownRollbackViolations) 0))
  traces:
  '((reconcileAndSafeCompensateTest
      (run reconcileAndSafeCompensateTest
        (then init registerCompensator crashStep1Unknown reconcileStep1Committed compensateStep1
              (all (assert safety)
                   (assert (. h compensated))
                   (assert (= (. h spentBudget) 1))
                   (assert (= (. h remainingBudget) 1))
                   (keep-h)))))
    (budgetOverrunViolatesSafetyTest
      (run budgetOverrunViolatesSafetyTest
        (then init registerCompensator spendExtraCompute spendExtraCompute executeStep1OverBudget
              (all (assert (not safety))
                   (assert (> (. h budgetViolations) 0))
                   (keep-h)))))
    (unregisteredCompViolatesSafetyTest
      (run unregisteredCompViolatesSafetyTest
        (then init executeStep1Unregistered
              (all (assert (not safety))
                   (assert (> (. h unregisteredCompViolations) 0))
                   (keep-h)))))
    (pivotRollbackViolatesSafetyTest
      (run pivotRollbackViolatesSafetyTest
        (then init registerCompensator executeCompensableStep1 crossIrreversiblePivot compensatePastPivot
              (all (assert (not safety))
                   (assert (> (. h pivotOrUnknownRollbackViolations) 0))
                   (keep-h))))))
  countermodels:
  (list BudgetOverrunCountermodel
        UnregisteredCompensatorCountermodel
        PivotRollbackViolationCountermodel)
  limits: "Finite single-compensable-step + single-pivot Saga and integer compute-budget abstraction; does not model arbitrary multi-currency exchange fluctuation, external vendor compensation outage retries beyond idempotency keys, or continuous real-time GPU metering.")

(.def (BudgetOverrunCountermodel @ DurableSagaBudgetModel)
  identity: 'engineering.defense.durable-saga-budget.budget-overrun
  dropped-guard: 'enforce-budget-conservation
  step-action: "stepBudgetOverrun"
  derive-from-transition: 'executeCompensableStep1
  derive-action-name: 'executeStep1OverBudget
  expected-itf-predicate: "h.budgetViolations > 0")

(.def (UnregisteredCompensatorCountermodel @ DurableSagaBudgetModel)
  identity: 'engineering.defense.durable-saga-budget.unregistered-compensator
  dropped-guard: 'require-write-ahead-compensator
  step-action: "stepUnregisteredComp"
  derive-from-transition: 'executeCompensableStep1
  derive-action-name: 'executeStep1Unregistered
  expected-itf-predicate: "h.unregisteredCompViolations > 0")

(.def (PivotRollbackViolationCountermodel @ DurableSagaBudgetModel)
  identity: 'engineering.defense.durable-saga-budget.pivot-rollback
  dropped-guard: 'forbid-rollback-past-pivot-or-unknown
  step-action: "stepPivotRollback"
  derive-from-transition: 'compensateStep1
  derive-action-name: 'compensatePastPivot
  expected-itf-predicate: "h.pivotOrUnknownRollbackViolations > 0")

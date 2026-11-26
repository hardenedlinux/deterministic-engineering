// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.durable-saga-budget
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel enforce-budget-conservation step=stepBudgetOverrun max-steps=6 itf="h.budgetViolations > 0"
// @countermodel require-write-ahead-compensator step=stepUnregisteredComp max-steps=6 itf="h.unregisteredCompViolations > 0"
// @countermodel forbid-rollback-past-pivot-or-unknown step=stepPivotRollback max-steps=6 itf="h.pivotOrUnknownRollbackViolations > 0"
// Limits: Finite single-compensable-step + single-pivot Saga and integer compute-budget abstraction; does not model arbitrary multi-currency exchange fluctuation, external vendor compensation outage retries beyond idempotency keys, or continuous real-time GPU metering.
module durable_saga_budget {
  type State = { rootBudget: int, remainingBudget: int, spentBudget: int, compensatorRegistered: bool, step1Done: bool, step1Unknown: bool, pivotCrossed: bool, compensated: bool, budgetViolations: int, unregisteredCompViolations: int, pivotOrUnknownRollbackViolations: int }
  var h: State
  action init = h' = { rootBudget: 2, remainingBudget: 2, spentBudget: 0, compensatorRegistered: false, step1Done: false, step1Unknown: false, pivotCrossed: false, compensated: false, budgetViolations: 0, unregisteredCompViolations: 0, pivotOrUnknownRollbackViolations: 0 }
  action registerCompensator = if (not(h.compensatorRegistered)) h' = h.with("compensatorRegistered", true) else h' = h
  action executeCompensableStep1 = if ((not(h.step1Done) and not(h.step1Unknown) and h.compensatorRegistered and h.remainingBudget > 0)) h' = h.with("step1Done", true).with("remainingBudget", (h.remainingBudget - 1)).with("spentBudget", (h.spentBudget + 1)).with("unregisteredCompViolations", if (h.compensatorRegistered) h.unregisteredCompViolations else (h.unregisteredCompViolations + 1)).with("budgetViolations", if (h.remainingBudget > 0) h.budgetViolations else (h.budgetViolations + 1)) else h' = h
  action crashStep1Unknown = if ((not(h.step1Done) and not(h.step1Unknown) and h.compensatorRegistered and h.remainingBudget > 0)) h' = h.with("step1Unknown", true).with("remainingBudget", (h.remainingBudget - 1)).with("spentBudget", (h.spentBudget + 1)) else h' = h
  action reconcileStep1Committed = if (h.step1Unknown) h' = h.with("step1Unknown", false).with("step1Done", true) else h' = h
  action crossIrreversiblePivot = if ((h.step1Done and not(h.pivotCrossed) and not(h.compensated) and h.remainingBudget > 0)) h' = h.with("pivotCrossed", true).with("remainingBudget", (h.remainingBudget - 1)).with("spentBudget", (h.spentBudget + 1)) else h' = h
  action spendExtraCompute = if (h.remainingBudget > 0) h' = h.with("remainingBudget", (h.remainingBudget - 1)).with("spentBudget", (h.spentBudget + 1)) else h' = h
  action compensateStep1 = if ((not(h.compensated) and (h.step1Done and not(h.pivotCrossed) and not(h.step1Unknown)))) h' = h.with("compensated", true).with("step1Done", false).with("pivotOrUnknownRollbackViolations", if ((h.step1Done and not(h.pivotCrossed) and not(h.step1Unknown))) h.pivotOrUnknownRollbackViolations else (h.pivotOrUnknownRollbackViolations + 1)) else h' = h
  action step = any { registerCompensator, executeCompensableStep1, crashStep1Unknown, reconcileStep1Committed, crossIrreversiblePivot, spendExtraCompute, compensateStep1 }
  val safety = ((h.spentBudget + h.remainingBudget) == h.rootBudget and h.remainingBudget >= 0 and h.budgetViolations == 0 and h.unregisteredCompViolations == 0 and h.pivotOrUnknownRollbackViolations == 0)
  // Countermodel engineering.defense.durable-saga-budget.budget-overrun (dropped guard: enforce-budget-conservation)
  action executeStep1OverBudget = if ((not(h.step1Done) and not(h.step1Unknown) and h.compensatorRegistered and true)) h' = h.with("step1Done", true).with("remainingBudget", (h.remainingBudget - 1)).with("spentBudget", (h.spentBudget + 1)).with("unregisteredCompViolations", if (h.compensatorRegistered) h.unregisteredCompViolations else (h.unregisteredCompViolations + 1)).with("budgetViolations", if (h.remainingBudget > 0) h.budgetViolations else (h.budgetViolations + 1)) else h' = h
  action stepBudgetOverrun = any { step, executeStep1OverBudget }
  // Countermodel engineering.defense.durable-saga-budget.unregistered-compensator (dropped guard: require-write-ahead-compensator)
  action executeStep1Unregistered = if ((not(h.step1Done) and not(h.step1Unknown) and true and h.remainingBudget > 0)) h' = h.with("step1Done", true).with("remainingBudget", (h.remainingBudget - 1)).with("spentBudget", (h.spentBudget + 1)).with("unregisteredCompViolations", if (h.compensatorRegistered) h.unregisteredCompViolations else (h.unregisteredCompViolations + 1)).with("budgetViolations", if (h.remainingBudget > 0) h.budgetViolations else (h.budgetViolations + 1)) else h' = h
  action stepUnregisteredComp = any { step, executeStep1Unregistered }
  // Countermodel engineering.defense.durable-saga-budget.pivot-rollback (dropped guard: forbid-rollback-past-pivot-or-unknown)
  action compensatePastPivot = if ((not(h.compensated) and true)) h' = h.with("compensated", true).with("step1Done", false).with("pivotOrUnknownRollbackViolations", if ((h.step1Done and not(h.pivotCrossed) and not(h.step1Unknown))) h.pivotOrUnknownRollbackViolations else (h.pivotOrUnknownRollbackViolations + 1)) else h' = h
  action stepPivotRollback = any { step, compensatePastPivot }
  run reconcileAndSafeCompensateTest = init.then(registerCompensator).then(crashStep1Unknown).then(reconcileStep1Committed).then(compensateStep1).then(all { assert(safety), assert(h.compensated), assert(h.spentBudget == 1), assert(h.remainingBudget == 1), h' = h })
  run budgetOverrunViolatesSafetyTest = init.then(registerCompensator).then(spendExtraCompute).then(spendExtraCompute).then(executeStep1OverBudget).then(all { assert(not(safety)), assert(h.budgetViolations > 0), h' = h })
  run unregisteredCompViolatesSafetyTest = init.then(executeStep1Unregistered).then(all { assert(not(safety)), assert(h.unregisteredCompViolations > 0), h' = h })
  run pivotRollbackViolatesSafetyTest = init.then(registerCompensator).then(executeCompensableStep1).then(crossIrreversiblePivot).then(compensatePastPivot).then(all { assert(not(safety)), assert(h.pivotOrUnknownRollbackViolations > 0), h' = h })
}

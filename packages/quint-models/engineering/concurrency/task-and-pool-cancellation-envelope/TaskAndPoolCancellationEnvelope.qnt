// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.task-and-pool-cancellation-envelope
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel abort-children-on-cancel step=stepDetachedJoinHandleLeak max-steps=6 itf="h.orphanTasks > 0"
// @countermodel rollback-or-discard-dirty-lease step=stepPoisonedTxLeaseReturn max-steps=6 itf="h.poisonedPoolConns > 0"
// @countermodel bound-fanout-and-preserve-id step=stepUnboundedFanoutAndLostCorrelation max-steps=6 itf="h.fanoutBreaches > 0 or h.lostCorrelationIds > 0"
// Limits: Finite 2-lane pool and 2-permit semaphore abstraction; verifies abort-on-drop task containment, dirty-lease pool isolation, and bounded panic-safe correlation, not OS thread scheduling fairness or SQLite B-tree locking internals.
module concurrency_task_and_pool_cancellation_envelope {
  type State = { maxConcurrency: int, activeChildren: int, orphanTasks: int, txDirty: bool, poisonedPoolConns: int, fanoutBreaches: int, lostCorrelationIds: int, completedBatches: int, cleanCancels: int }
  var h: State
  action init = h' = { maxConcurrency: 2, activeChildren: 0, orphanTasks: 0, txDirty: false, poisonedPoolConns: 0, fanoutBreaches: 0, lostCorrelationIds: 0, completedBatches: 0, cleanCancels: 0 }
  action spawnBoundedChild = if (h.activeChildren < h.maxConcurrency) h' = h.with("activeChildren", (h.activeChildren + 1)) else h' = h
  action beginTransaction = if (not(h.txDirty)) h' = h.with("txDirty", true) else h' = h
  action commitTransaction = if (h.txDirty) h' = h.with("txDirty", false).with("completedBatches", (h.completedBatches + 1)) else h' = h
  action cancelScopeClean = if (h.activeChildren > 0 or h.txDirty) h' = h.with("activeChildren", 0).with("txDirty", false).with("cleanCancels", (h.cleanCancels + 1)) else h' = h
  action handleWorkerPanicSafe = if (h.activeChildren > 0) h' = h.with("activeChildren", (h.activeChildren - 1)).with("completedBatches", (h.completedBatches + 1)) else h' = h
  action step = any { spawnBoundedChild, beginTransaction, commitTransaction, cancelScopeClean, handleWorkerPanicSafe }
  val safety = (h.activeChildren <= h.maxConcurrency and h.activeChildren >= 0 and h.orphanTasks == 0 and h.poisonedPoolConns == 0 and h.fanoutBreaches == 0 and h.lostCorrelationIds == 0)
  // Countermodel engineering.concurrency.task-and-pool-cancellation-envelope.detached-joinhandle-leak (dropped guard: abort-children-on-cancel)
  action cancelScopeDetachedLeak = if (h.activeChildren > 0) h' = h.with("orphanTasks", (h.orphanTasks + h.activeChildren)).with("activeChildren", 0) else h' = h
  action stepDetachedJoinHandleLeak = any { step, cancelScopeDetachedLeak }
  // Countermodel engineering.concurrency.task-and-pool-cancellation-envelope.poisoned-tx-lease-return (dropped guard: rollback-or-discard-dirty-lease)
  action cancelTxReturnPoisoned = if (h.txDirty) h' = h.with("txDirty", false).with("poisonedPoolConns", (h.poisonedPoolConns + 1)) else h' = h
  action stepPoisonedTxLeaseReturn = any { step, cancelTxReturnPoisoned }
  // Countermodel engineering.concurrency.task-and-pool-cancellation-envelope.unbounded-fanout-and-lost-correlation (dropped guard: bound-fanout-and-preserve-id)
  action spawnUnboundedAndLoseId = h' = h.with("activeChildren", (h.maxConcurrency + 3)).with("fanoutBreaches", (h.fanoutBreaches + 1)).with("lostCorrelationIds", (h.lostCorrelationIds + 1))
  action stepUnboundedFanoutAndLostCorrelation = any { step, spawnUnboundedAndLoseId }
  action checkCancellationEnvelopeSafe = all { assert(h.cleanCancels > 0), assert(h.completedBatches > 0), assert(h.orphanTasks == 0), assert(h.poisonedPoolConns == 0), assert(h.fanoutBreaches == 0), assert(h.lostCorrelationIds == 0), assert(safety), h' = h }
  action checkCancellationEnvelopeViolated = all { assert((h.orphanTasks > 0 or h.poisonedPoolConns > 0 or h.fanoutBreaches > 0 or h.lostCorrelationIds > 0)), assert(not(safety)), h' = h }
  run cancellationEnvelopeSafeTest = init.then(spawnBoundedChild).then(beginTransaction).then(cancelScopeClean).then(spawnBoundedChild).then(handleWorkerPanicSafe).then(beginTransaction).then(commitTransaction).then(checkCancellationEnvelopeSafe)
  run detachedJoinHandleLeakRefutedTest = init.then(spawnBoundedChild).then(cancelScopeDetachedLeak).then(checkCancellationEnvelopeViolated)
  run poisonedTxLeaseRefutedTest = init.then(beginTransaction).then(cancelTxReturnPoisoned).then(checkCancellationEnvelopeViolated)
  run unboundedFanoutAndLostIdRefutedTest = init.then(spawnUnboundedAndLoseId).then(checkCancellationEnvelopeViolated)
}

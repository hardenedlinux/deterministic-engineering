// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.saga-compensation-idempotency
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel idempotency-key-dedup step=stepMissingIdempotency max-steps=6 itf="h.debitCount >= 2"
// @countermodel compensation-tombstone-fence step=stepLateRetryZombie max-steps=6 itf="h.sagaAborted == true and h.debitCount != h.refundCount"
// Limits: Finite two-step Saga orchestrator abstraction with single idempotency key; does not model multi-service cyclic dependencies, TTL key eviction policies, or partial compensating failure.
module concurrency_saga_compensation {
  type State = { reqInFlight: bool, replyLost: bool, processedKeys: Set[int], tombstoned: bool, debitCount: int, refundCount: int, stepBFailed: bool, sagaAborted: bool }
  var h: State
  action init = h' = { reqInFlight: false, replyLost: false, processedKeys: Set(), tombstoned: false, debitCount: 0, refundCount: 0, stepBFailed: false, sagaAborted: false }
  action sendStepA = if ((not(h.sagaAborted) and not(h.reqInFlight))) h' = h.with("reqInFlight", true) else h' = h
  action execStepA = if (h.reqInFlight) if ((not(h.processedKeys.contains(1)) and not(h.tombstoned))) h' = h.with("processedKeys", h.processedKeys.union(Set(1))).with("debitCount", (h.debitCount + 1)).with("reqInFlight", false) else h' = h.with("reqInFlight", false) else h' = h
  action loseReplyAndRetryA = if ((not(h.sagaAborted) and h.processedKeys.contains(1) and not(h.reqInFlight))) h' = h.with("reqInFlight", true).with("replyLost", true) else h' = h
  action failStepB = if ((not(h.stepBFailed) and not(h.sagaAborted))) h' = h.with("stepBFailed", true) else h' = h
  action compensateA = if ((h.stepBFailed and not(h.sagaAborted))) h' = h.with("tombstoned", true).with("refundCount", h.debitCount).with("sagaAborted", true) else h' = h
  action step = any { sendStepA, execStepA, loseReplyAndRetryA, failStepB, compensateA }
  val safety = (h.debitCount <= 1 and h.refundCount <= h.debitCount and (not(h.sagaAborted) or h.debitCount == h.refundCount))
  // Countermodel engineering.concurrency.saga-compensation-idempotency.missing-idempotency-dedup (dropped guard: idempotency-key-dedup)
  action execStepANoDedup = if (h.reqInFlight) if ((true and not(h.tombstoned))) h' = h.with("processedKeys", h.processedKeys.union(Set(1))).with("debitCount", (h.debitCount + 1)).with("reqInFlight", false) else h' = h.with("reqInFlight", false) else h' = h
  action stepMissingIdempotency = any { step, execStepANoDedup }
  // Countermodel engineering.concurrency.saga-compensation-idempotency.late-retry-after-compensation (dropped guard: compensation-tombstone-fence)
  action execStepANoTombstone = if (h.reqInFlight) if ((not(h.processedKeys.contains(1)) and true)) h' = h.with("processedKeys", h.processedKeys.union(Set(1))).with("debitCount", (h.debitCount + 1)).with("reqInFlight", false) else h' = h.with("reqInFlight", false) else h' = h
  action stepLateRetryZombie = any { step, execStepANoTombstone }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run retryDeduplicatedAndCompensatedTest = init.then(sendStepA).then(execStepA).then(loseReplyAndRetryA).then(execStepA).then(failStepB).then(compensateA).then(all { assert(h.debitCount == 1), assert(h.refundCount == 1), assert(h.sagaAborted), assert(safety), h' = h })
  run lateRetryBlockedByTombstoneTest = init.then(sendStepA).then(failStepB).then(compensateA).then(execStepA).then(all { assert(h.debitCount == 0), assert(h.refundCount == 0), assert(h.tombstoned), assert(safety), h' = h })
  run duplicateDebitCountermodelTest = init.then(sendStepA).then(execStepA).then(loseReplyAndRetryA).then(execStepANoDedup).then(checkUnsafe)
  run lateZombieDebitCountermodelTest = init.then(sendStepA).then(failStepB).then(compensateA).then(execStepANoTombstone).then(checkUnsafe)
}

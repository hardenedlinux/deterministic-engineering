// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.slow-consumer-eviction
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel slow-consumer-evict-cap step=stepUnboundedSlowQueue max-steps=6 itf="h.slowBuf > 2"
// @countermodel evicted-buffer-drain step=stepEvictedBufferLeak max-steps=6 itf="h.orphanedBuf > 0"
// Limits: Finite 2-frame slow-subscriber fan-out abstraction; models per-subscriber bounded buffering and eviction cleanup, not kernel TCP send-window dynamics or OS socket teardown latency.
module concurrency_slow_consumer {
  type State = { slowConnected: bool, slowBuf: int, fastDelivered: int, orphanedBuf: int }
  var h: State
  action init = h' = { slowConnected: true, slowBuf: 0, fastDelivered: 0, orphanedBuf: 0 }
  action publishFrame = if ((h.fastDelivered < 4 and not(h.slowConnected))) h' = h.with("fastDelivered", (h.fastDelivered + 1)) else if ((h.fastDelivered < 4 and h.slowConnected and h.slowBuf < 3 and h.slowBuf < 2)) h' = h.with("slowBuf", (h.slowBuf + 1)).with("fastDelivered", (h.fastDelivered + 1)) else h' = h
  action slowConsumeOne = if ((h.slowConnected and h.slowBuf > 0)) h' = h.with("slowBuf", (h.slowBuf - 1)) else h' = h
  action evictSlowConsumer = if ((h.slowConnected and h.slowBuf >= 2)) h' = h.with("slowConnected", false).with("slowBuf", 0).with("orphanedBuf", 0) else h' = h
  action reconnectSlow = if ((not(h.slowConnected) and h.orphanedBuf == 0 and h.fastDelivered < 4)) h' = h.with("slowConnected", true) else h' = h
  action step = any { publishFrame, slowConsumeOne, evictSlowConsumer, reconnectSlow }
  val safety = (h.slowBuf <= 2 and h.orphanedBuf == 0 and (h.slowConnected or h.slowBuf == 0))
  // Countermodel engineering.concurrency.slow-consumer-eviction.unbounded-slow-queue (dropped guard: slow-consumer-evict-cap)
  action publishFrameUnbounded = if ((h.fastDelivered < 4 and not(h.slowConnected))) h' = h.with("fastDelivered", (h.fastDelivered + 1)) else if ((h.fastDelivered < 4 and h.slowConnected and h.slowBuf < 3 and true)) h' = h.with("slowBuf", (h.slowBuf + 1)).with("fastDelivered", (h.fastDelivered + 1)) else h' = h
  action stepUnboundedSlowQueue = any { step, publishFrameUnbounded }
  // Countermodel engineering.concurrency.slow-consumer-eviction.evicted-buffer-leak (dropped guard: evicted-buffer-drain)
  action evictSlowConsumerLeaky = if ((h.slowConnected and h.slowBuf >= 2)) h' = h.with("slowConnected", false).with("slowBuf", 0).with("orphanedBuf", h.slowBuf) else h' = h
  action stepEvictedBufferLeak = any { step, evictSlowConsumerLeaky }
  action checkIsolatedHealthy = all { assert(not(h.slowConnected)), assert(h.slowBuf == 0), assert(h.orphanedBuf == 0), assert(h.fastDelivered > 2), assert(safety), h' = h }
  action checkSlowViolation = all { assert((h.slowBuf > 2 or h.orphanedBuf > 0)), assert(not(safety)), h' = h }
  run slowEvictionPreservesFastProgressTest = init.then(publishFrame).then(publishFrame).then(evictSlowConsumer).then(publishFrame).then(checkIsolatedHealthy)
  run unboundedSlowQueueRefutedTest = init.then(publishFrame).then(publishFrame).then(publishFrameUnbounded).then(checkSlowViolation)
  run evictedBufferLeakRefutedTest = init.then(publishFrame).then(publishFrame).then(evictSlowConsumerLeaky).then(checkSlowViolation)
}

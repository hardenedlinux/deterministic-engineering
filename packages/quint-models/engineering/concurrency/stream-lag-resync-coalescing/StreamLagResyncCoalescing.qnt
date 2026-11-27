// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.stream-lag-resync-coalescing
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel resync-snapshot-on-lag step=stepSilentLagDisconnect max-steps=6 itf="h.streamAlive == false"
// @countermodel coalesce-batch-flush step=stepPerTokenWriteAmp max-steps=6 itf="h.uncoalescedFlushes > 0"
// Limits: Finite 6-generation broadcast-lag and 2-token batch-flush abstraction; models snapshot resync continuity and write-amplification coalescing, not kernel TCP flow control or filesystem fsync latency.
module concurrency_stream_lag_resync {
  type State = { serverGen: int, clientGen: int, lagged: bool, streamAlive: bool, dirtyBatch: int, flushedBatches: int, uncoalescedFlushes: int }
  var h: State
  action init = h' = { serverGen: 0, clientGen: 0, lagged: false, streamAlive: true, dirtyBatch: 0, flushedBatches: 0, uncoalescedFlushes: 0 }
  action emitDelta = if ((h.serverGen < 6 and h.dirtyBatch < 2)) h' = h.with("serverGen", (h.serverGen + 1)).with("dirtyBatch", (h.dirtyBatch + 1)).with("lagged", (h.lagged or ((h.serverGen + 1) - h.clientGen) > 2)) else h' = h
  action consumeDelta = if ((h.streamAlive and not(h.lagged) and h.clientGen < h.serverGen)) h' = h.with("clientGen", (h.clientGen + 1)) else h' = h
  action resyncOnLag = if ((h.streamAlive and h.lagged)) h' = h.with("clientGen", h.serverGen).with("lagged", false).with("streamAlive", h.streamAlive) else h' = h
  action flushCheckpoint = if ((h.dirtyBatch > 0 and h.dirtyBatch >= 2)) h' = h.with("dirtyBatch", 0).with("flushedBatches", (h.flushedBatches + 1)).with("uncoalescedFlushes", if (h.dirtyBatch < 2) (h.uncoalescedFlushes + 1) else h.uncoalescedFlushes) else h' = h
  action step = any { emitDelta, consumeDelta, resyncOnLag, flushCheckpoint }
  val safety = (h.streamAlive and h.clientGen <= h.serverGen and h.dirtyBatch <= 2 and h.uncoalescedFlushes == 0 and (h.lagged or (h.serverGen - h.clientGen) <= 2))
  // Countermodel engineering.concurrency.stream-lag-resync-coalescing.silent-lag-disconnect (dropped guard: resync-snapshot-on-lag)
  action resyncOnLagDropStream = if ((h.streamAlive and h.lagged)) h' = h.with("clientGen", h.serverGen).with("lagged", false).with("streamAlive", false) else h' = h
  action stepSilentLagDisconnect = any { step, resyncOnLagDropStream }
  // Countermodel engineering.concurrency.stream-lag-resync-coalescing.per-token-write-amp (dropped guard: coalesce-batch-flush)
  action flushCheckpointPerToken = if ((h.dirtyBatch > 0 and true)) h' = h.with("dirtyBatch", 0).with("flushedBatches", (h.flushedBatches + 1)).with("uncoalescedFlushes", if (h.dirtyBatch < 2) (h.uncoalescedFlushes + 1) else h.uncoalescedFlushes) else h' = h
  action stepPerTokenWriteAmp = any { step, flushCheckpointPerToken }
  action checkResyncHealthy = all { assert(h.streamAlive), assert(not(h.lagged)), assert(h.clientGen == h.serverGen), assert(h.uncoalescedFlushes == 0), assert(h.flushedBatches > 0), assert(safety), h' = h }
  action checkStreamViolation = all { assert((not(h.streamAlive) or h.uncoalescedFlushes > 0)), assert(not(safety)), h' = h }
  run lagResyncAndCoalescedFlushTest = init.then(emitDelta).then(emitDelta).then(flushCheckpoint).then(emitDelta).then(resyncOnLag).then(checkResyncHealthy)
  run silentLagDisconnectRefutedTest = init.then(emitDelta).then(emitDelta).then(flushCheckpoint).then(emitDelta).then(resyncOnLagDropStream).then(checkStreamViolation)
  run perTokenWriteAmpRefutedTest = init.then(emitDelta).then(flushCheckpointPerToken).then(checkStreamViolation)
}

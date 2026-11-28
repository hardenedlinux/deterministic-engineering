// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.ipc-half-open-reconnect-idempotency
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel retire-stale-stream-on-reconnect step=stepHalfOpenStreamLeak max-steps=6 itf="h.activeStreams > 1"
// @countermodel dedup-idempotent-replay step=stepDuplicateReplayEffect max-steps=6 itf="h.duplicateEffects > 0"
// @countermodel fence-stale-epoch-frame step=stepStaleEpochFrameInterleave max-steps=6 itf="h.staleFramesApplied > 0"
// Limits: Finite 3-reconnect, single-key idempotency and epoch-fencing abstraction; verifies stream retirement, replay deduplication, and stale-frame rejection across half-open drops, not TLS handshake or TCP congestion control.
module concurrency_ipc_half_open_reconnect_idempotency {
  type State = { sessionEpoch: int, activeStreams: int, inFlightKey: int, committedKey1: bool, duplicateEffects: int, staleFramesApplied: int, reconnectCount: int }
  var h: State
  action init = h' = { sessionEpoch: 1, activeStreams: 1, inFlightKey: 0, committedKey1: false, duplicateEffects: 0, staleFramesApplied: 0, reconnectCount: 0 }
  action sendRequest = if (h.inFlightKey == 0) h' = h.with("inFlightKey", 1) else h' = h
  action commitRequest = if (h.inFlightKey == 1) if (not(h.committedKey1)) h' = h.with("committedKey1", true).with("inFlightKey", 0) else if (true) h' = h.with("inFlightKey", 0) else h' = h.with("duplicateEffects", (h.duplicateEffects + 1)).with("inFlightKey", 0) else h' = h
  action reconnectHalfOpen = if (h.reconnectCount < 3) if (true) h' = h.with("sessionEpoch", (h.sessionEpoch + 1)).with("activeStreams", 1).with("reconnectCount", (h.reconnectCount + 1)) else h' = h.with("sessionEpoch", (h.sessionEpoch + 1)).with("activeStreams", (h.activeStreams + 1)).with("reconnectCount", (h.reconnectCount + 1)) else h' = h
  action receiveStaleFrame = if (h.sessionEpoch > 1) if (true) h' = h else h' = h.with("staleFramesApplied", (h.staleFramesApplied + 1)) else h' = h
  action step = any { sendRequest, commitRequest, reconnectHalfOpen, receiveStaleFrame }
  val safety = (h.activeStreams <= 1 and h.duplicateEffects == 0 and h.staleFramesApplied == 0 and h.sessionEpoch >= 1)
  // Countermodel engineering.concurrency.ipc-half-open-reconnect-idempotency.half-open-stream-leak (dropped guard: retire-stale-stream-on-reconnect)
  action reconnectHalfOpenLeak = if (h.reconnectCount < 3) if (false) h' = h.with("sessionEpoch", (h.sessionEpoch + 1)).with("activeStreams", 1).with("reconnectCount", (h.reconnectCount + 1)) else h' = h.with("sessionEpoch", (h.sessionEpoch + 1)).with("activeStreams", (h.activeStreams + 1)).with("reconnectCount", (h.reconnectCount + 1)) else h' = h
  action stepHalfOpenStreamLeak = any { step, reconnectHalfOpenLeak }
  // Countermodel engineering.concurrency.ipc-half-open-reconnect-idempotency.duplicate-replay-effect (dropped guard: dedup-idempotent-replay)
  action commitRequestDuplicate = if (h.inFlightKey == 1) if (not(h.committedKey1)) h' = h.with("committedKey1", true).with("inFlightKey", 0) else if (false) h' = h.with("inFlightKey", 0) else h' = h.with("duplicateEffects", (h.duplicateEffects + 1)).with("inFlightKey", 0) else h' = h
  action stepDuplicateReplayEffect = any { step, commitRequestDuplicate }
  // Countermodel engineering.concurrency.ipc-half-open-reconnect-idempotency.stale-epoch-frame-interleave (dropped guard: fence-stale-epoch-frame)
  action receiveStaleFrameUnfenced = if (h.sessionEpoch > 1) if (false) h' = h else h' = h.with("staleFramesApplied", (h.staleFramesApplied + 1)) else h' = h
  action stepStaleEpochFrameInterleave = any { step, receiveStaleFrameUnfenced }
  action checkIpcSafe = all { assert(h.committedKey1), assert(h.reconnectCount > 0), assert(h.activeStreams == 1), assert(h.duplicateEffects == 0), assert(h.staleFramesApplied == 0), assert(safety), h' = h }
  action checkIpcViolated = all { assert((h.activeStreams > 1 or h.duplicateEffects > 0 or h.staleFramesApplied > 0)), assert(not(safety)), h' = h }
  run reconnectIdempotentSafeTest = init.then(sendRequest).then(commitRequest).then(reconnectHalfOpen).then(sendRequest).then(commitRequest).then(receiveStaleFrame).then(checkIpcSafe)
  run halfOpenStreamLeakRefutedTest = init.then(reconnectHalfOpenLeak).then(checkIpcViolated)
  run duplicateReplayRefutedTest = init.then(sendRequest).then(commitRequest).then(sendRequest).then(commitRequestDuplicate).then(checkIpcViolated)
  run staleFrameInterleaveRefutedTest = init.then(reconnectHalfOpen).then(receiveStaleFrameUnfenced).then(checkIpcViolated)
}

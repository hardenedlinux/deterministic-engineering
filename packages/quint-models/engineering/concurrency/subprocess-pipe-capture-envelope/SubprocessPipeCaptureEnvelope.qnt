// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.subprocess-pipe-capture-envelope
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel precap-before-retain step=stepBufferBeforeTruncate max-steps=6 itf="h.peakRetainedBytes > h.maxRetainBytes"
// @countermodel drain-pipe-to-sink-after-cap step=stepStopReadingPipeDeadlock max-steps=6 itf="h.pipeDeadlocks > 0"
// @countermodel bound-line-frame-read step=stepUnboundedReadLineBomb max-steps=6 itf="h.lineCapBreaches > 0"
// Limits: Finite 4-unit retained pipe budget and 3-unit single-line frame cap abstraction; verifies pre-allocation retain capping, drain-to-sink pipe liveness past OS pipe capacity, and bounded line framing, not kernel splice/zero-copy syscall internals or PTY line disciplines.
module concurrency_subprocess_pipe_capture_envelope {
  type State = { maxRetainBytes: int, maxLineBytes: int, childRunning: bool, retainedBytes: int, peakRetainedBytes: int, discardedBytes: int, pipeDeadlocks: int, lineCapBreaches: int, cleanExits: int }
  var h: State
  action init = h' = { maxRetainBytes: 4, maxLineBytes: 3, childRunning: false, retainedBytes: 0, peakRetainedBytes: 0, discardedBytes: 0, pipeDeadlocks: 0, lineCapBreaches: 0, cleanExits: 0 }
  action spawnChild = if (not(h.childRunning)) h' = h.with("childRunning", true).with("retainedBytes", 0).with("discardedBytes", 0) else h' = h
  action captureBoundedChunk = if (h.childRunning and h.retainedBytes < h.maxRetainBytes) h' = h.with("retainedBytes", (h.retainedBytes + 1)).with("peakRetainedBytes", if ((h.retainedBytes + 1) > h.peakRetainedBytes) (h.retainedBytes + 1) else h.peakRetainedBytes) else h' = h
  action drainExcessToSink = if (h.childRunning and h.retainedBytes == h.maxRetainBytes) h' = h.with("discardedBytes", (h.discardedBytes + 1)) else h' = h
  action readBoundedLineFrame = if (h.childRunning) h' = h.with("peakRetainedBytes", if (h.maxLineBytes > h.peakRetainedBytes) h.maxLineBytes else h.peakRetainedBytes) else h' = h
  action finishChildClean = if (h.childRunning) h' = h.with("childRunning", false).with("retainedBytes", 0).with("cleanExits", (h.cleanExits + 1)) else h' = h
  action step = any { spawnChild, captureBoundedChunk, drainExcessToSink, readBoundedLineFrame, finishChildClean }
  val safety = (h.retainedBytes <= h.maxRetainBytes and h.peakRetainedBytes <= h.maxRetainBytes and h.retainedBytes >= 0 and h.discardedBytes >= 0 and h.pipeDeadlocks == 0 and h.lineCapBreaches == 0)
  // Countermodel engineering.concurrency.subprocess-pipe-capture-envelope.buffer-before-truncate (dropped guard: precap-before-retain)
  action bufferFullThenTruncate = if (h.childRunning) h' = h.with("peakRetainedBytes", (h.maxRetainBytes + 4)).with("retainedBytes", h.maxRetainBytes) else h' = h
  action stepBufferBeforeTruncate = any { step, bufferFullThenTruncate }
  // Countermodel engineering.concurrency.subprocess-pipe-capture-envelope.stop-reading-pipe-deadlock (dropped guard: drain-pipe-to-sink-after-cap)
  action stopReadingAfterCap = if (h.childRunning and h.retainedBytes == h.maxRetainBytes) h' = h.with("pipeDeadlocks", (h.pipeDeadlocks + 1)) else h' = h
  action stepStopReadingPipeDeadlock = any { step, stopReadingAfterCap }
  // Countermodel engineering.concurrency.subprocess-pipe-capture-envelope.unbounded-read-line-bomb (dropped guard: bound-line-frame-read)
  action readUnboundedSingleLine = if (h.childRunning) h' = h.with("peakRetainedBytes", (h.maxRetainBytes + 5)).with("lineCapBreaches", (h.lineCapBreaches + 1)) else h' = h
  action stepUnboundedReadLineBomb = any { step, readUnboundedSingleLine }
  action checkPipeCaptureSafe = all { assert(h.cleanExits > 0), assert(h.discardedBytes > 0), assert(h.peakRetainedBytes <= h.maxRetainBytes), assert(h.pipeDeadlocks == 0), assert(h.lineCapBreaches == 0), assert(safety), h' = h }
  action checkPipeCaptureViolated = all { assert((h.peakRetainedBytes > h.maxRetainBytes or h.pipeDeadlocks > 0 or h.lineCapBreaches > 0)), assert(not(safety)), h' = h }
  run pipeCaptureSafeTest = init.then(spawnChild).then(captureBoundedChunk).then(captureBoundedChunk).then(captureBoundedChunk).then(captureBoundedChunk).then(drainExcessToSink).then(readBoundedLineFrame).then(finishChildClean).then(checkPipeCaptureSafe)
  run bufferBeforeTruncateRefutedTest = init.then(spawnChild).then(bufferFullThenTruncate).then(checkPipeCaptureViolated)
  run stopReadingPipeDeadlockRefutedTest = init.then(spawnChild).then(captureBoundedChunk).then(captureBoundedChunk).then(captureBoundedChunk).then(captureBoundedChunk).then(stopReadingAfterCap).then(checkPipeCaptureViolated)
  run unboundedReadLineRefutedTest = init.then(spawnChild).then(readUnboundedSingleLine).then(checkPipeCaptureViolated)
}

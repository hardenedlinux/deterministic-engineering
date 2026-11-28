// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.streaming-output-budget-envelope
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel precheck-chunk-before-buffer step=stepCheckAfterBuffering max-steps=6 itf="h.peakRetainedBytes > h.budgetLimit"
// @countermodel account-thinking-in-budget step=stepUnaccountedThinkingFlood max-steps=6 itf="h.thinkingBytes > h.budgetLimit"
// @countermodel enforce-limit-on-sse-complete step=stepSseCompleteBudgetBypass max-steps=6 itf="h.budgetBypassCount > 0"
// Limits: Finite 4-unit cumulative byte-budget abstraction; verifies pre-allocation chunk cap checks, unified text+thinking budget accounting, SSE completion path parity, and buffer release on refusal/completion, not TCP windowing or TLS record framing.
module concurrency_streaming_output_budget_envelope {
  type State = { budgetLimit: int, streamOpen: bool, textBytes: int, thinkingBytes: int, peakRetainedBytes: int, overflowRefusals: int, completedResponses: int, budgetBypassCount: int, streamReleased: bool }
  var h: State
  action init = h' = { budgetLimit: 4, streamOpen: false, textBytes: 0, thinkingBytes: 0, peakRetainedBytes: 0, overflowRefusals: 0, completedResponses: 0, budgetBypassCount: 0, streamReleased: true }
  action openStream = if (not(h.streamOpen)) h' = h.with("streamOpen", true).with("textBytes", 0).with("thinkingBytes", 0).with("streamReleased", false) else h' = h
  action receiveBoundedText = if ((h.streamOpen and (h.textBytes + h.thinkingBytes) < h.budgetLimit)) h' = h.with("textBytes", (h.textBytes + 1)).with("peakRetainedBytes", if (((h.textBytes + h.thinkingBytes) + 1) > h.peakRetainedBytes) ((h.textBytes + h.thinkingBytes) + 1) else h.peakRetainedBytes) else h' = h
  action receiveThinkingDelta = if (h.streamOpen) if (true) if ((h.textBytes + h.thinkingBytes) < h.budgetLimit) h' = h.with("thinkingBytes", (h.thinkingBytes + 1)).with("peakRetainedBytes", if (((h.textBytes + h.thinkingBytes) + 1) > h.peakRetainedBytes) ((h.textBytes + h.thinkingBytes) + 1) else h.peakRetainedBytes) else h' = h.with("streamOpen", false).with("textBytes", 0).with("thinkingBytes", 0).with("overflowRefusals", (h.overflowRefusals + 1)).with("streamReleased", true) else h' = h.with("thinkingBytes", (h.budgetLimit + 3)).with("peakRetainedBytes", (h.budgetLimit + 3)).with("budgetBypassCount", (h.budgetBypassCount + 1)) else h' = h
  action refuseOversizeChunk = if (h.streamOpen) if (true) h' = h.with("streamOpen", false).with("textBytes", 0).with("thinkingBytes", 0).with("overflowRefusals", (h.overflowRefusals + 1)).with("streamReleased", true) else h' = h.with("textBytes", (h.budgetLimit + 4)).with("peakRetainedBytes", (h.budgetLimit + 4)).with("budgetBypassCount", (h.budgetBypassCount + 1)) else h' = h
  action completeSseTurn = if (h.streamOpen) if (true) h' = h.with("streamOpen", false).with("textBytes", 0).with("thinkingBytes", 0).with("completedResponses", (h.completedResponses + 1)).with("streamReleased", true) else h' = h.with("streamOpen", false).with("textBytes", (h.budgetLimit + 4)).with("peakRetainedBytes", (h.budgetLimit + 4)).with("budgetBypassCount", (h.budgetBypassCount + 1)).with("streamReleased", false) else h' = h
  action step = any { openStream, receiveBoundedText, receiveThinkingDelta, refuseOversizeChunk, completeSseTurn }
  val safety = ((h.textBytes + h.thinkingBytes) <= h.budgetLimit and h.peakRetainedBytes <= h.budgetLimit and h.textBytes >= 0 and h.thinkingBytes >= 0 and (h.streamOpen or (h.textBytes == 0 and h.thinkingBytes == 0 and h.streamReleased)) and h.budgetBypassCount == 0)
  // Countermodel engineering.concurrency.streaming-output-budget-envelope.check-after-buffering (dropped guard: precheck-chunk-before-buffer)
  action bufferOversizeBeforeCheck = if (h.streamOpen) if (false) h' = h.with("streamOpen", false).with("textBytes", 0).with("thinkingBytes", 0).with("overflowRefusals", (h.overflowRefusals + 1)).with("streamReleased", true) else h' = h.with("textBytes", (h.budgetLimit + 4)).with("peakRetainedBytes", (h.budgetLimit + 4)).with("budgetBypassCount", (h.budgetBypassCount + 1)) else h' = h
  action stepCheckAfterBuffering = any { step, bufferOversizeBeforeCheck }
  // Countermodel engineering.concurrency.streaming-output-budget-envelope.unaccounted-thinking-flood (dropped guard: account-thinking-in-budget)
  action receiveThinkingUnaccounted = if (h.streamOpen) if (false) if ((h.textBytes + h.thinkingBytes) < h.budgetLimit) h' = h.with("thinkingBytes", (h.thinkingBytes + 1)).with("peakRetainedBytes", if (((h.textBytes + h.thinkingBytes) + 1) > h.peakRetainedBytes) ((h.textBytes + h.thinkingBytes) + 1) else h.peakRetainedBytes) else h' = h.with("streamOpen", false).with("textBytes", 0).with("thinkingBytes", 0).with("overflowRefusals", (h.overflowRefusals + 1)).with("streamReleased", true) else h' = h.with("thinkingBytes", (h.budgetLimit + 3)).with("peakRetainedBytes", (h.budgetLimit + 3)).with("budgetBypassCount", (h.budgetBypassCount + 1)) else h' = h
  action stepUnaccountedThinkingFlood = any { step, receiveThinkingUnaccounted }
  // Countermodel engineering.concurrency.streaming-output-budget-envelope.sse-complete-budget-bypass (dropped guard: enforce-limit-on-sse-complete)
  action completeSseBypassLimit = if (h.streamOpen) if (false) h' = h.with("streamOpen", false).with("textBytes", 0).with("thinkingBytes", 0).with("completedResponses", (h.completedResponses + 1)).with("streamReleased", true) else h' = h.with("streamOpen", false).with("textBytes", (h.budgetLimit + 4)).with("peakRetainedBytes", (h.budgetLimit + 4)).with("budgetBypassCount", (h.budgetBypassCount + 1)).with("streamReleased", false) else h' = h
  action stepSseCompleteBudgetBypass = any { step, completeSseBypassLimit }
  action checkBudgetEnvelopeSafe = all { assert(h.overflowRefusals > 0), assert(h.completedResponses > 0), assert(h.peakRetainedBytes <= h.budgetLimit), assert((h.textBytes + h.thinkingBytes) <= h.budgetLimit), assert(h.budgetBypassCount == 0), assert(safety), h' = h }
  action checkBudgetEnvelopeViolated = all { assert(((h.textBytes + h.thinkingBytes) > h.budgetLimit or h.peakRetainedBytes > h.budgetLimit or h.budgetBypassCount > 0)), assert(not(safety)), h' = h }
  run streamingBudgetSafeTest = init.then(openStream).then(receiveBoundedText).then(receiveThinkingDelta).then(completeSseTurn).then(openStream).then(receiveBoundedText).then(refuseOversizeChunk).then(checkBudgetEnvelopeSafe)
  run checkAfterBufferingRefutedTest = init.then(openStream).then(bufferOversizeBeforeCheck).then(checkBudgetEnvelopeViolated)
  run unaccountedThinkingFloodRefutedTest = init.then(openStream).then(receiveThinkingUnaccounted).then(checkBudgetEnvelopeViolated)
  run sseCompleteBypassRefutedTest = init.then(openStream).then(completeSseBypassLimit).then(checkBudgetEnvelopeViolated)
}

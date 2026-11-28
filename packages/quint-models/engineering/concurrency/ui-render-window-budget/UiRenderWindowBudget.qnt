// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.ui-render-window-budget
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel dom-window-cap step=stepUnboundedDomGrowth max-steps=6 itf="h.mountedNodes > 3"
// @countermodel incremental-block-render step=stepFullReparseStall max-steps=6 itf="h.frameWorkUnits > 2"
// Limits: Finite 3-node viewport window and 2-unit frame-budget abstraction; models DOM virtualization, rAF coalescing, and O(1) incremental rendering vs. O(N) full re-parse, not browser CSS layout engines or GPU compositor shaders.
module concurrency_ui_render_window {
  type State = { totalTurns: int, mountedNodes: int, pendingRafs: int, frameWorkUnits: int }
  var h: State
  action init = h' = { totalTurns: 0, mountedNodes: 0, pendingRafs: 0, frameWorkUnits: 0 }
  action appendTurnDelta = if (h.totalTurns < 6) h' = h.with("totalTurns", (h.totalTurns + 1)).with("mountedNodes", if (h.mountedNodes < 3) (h.mountedNodes + 1) else h.mountedNodes).with("pendingRafs", 1) else h' = h
  action flushFrame = if (h.pendingRafs > 0) h' = h.with("pendingRafs", 0).with("frameWorkUnits", 1) else h' = h
  action switchSessionReset = if ((h.totalTurns > 0 and h.pendingRafs == 0)) h' = h.with("mountedNodes", if (h.totalTurns > 3) 3 else h.totalTurns).with("pendingRafs", 1).with("frameWorkUnits", 0) else h' = h
  action step = any { appendTurnDelta, flushFrame, switchSessionReset }
  val safety = (h.mountedNodes <= 3 and h.pendingRafs <= 1 and h.frameWorkUnits <= 2)
  // Countermodel engineering.concurrency.ui-render-window-budget.unbounded-dom-growth (dropped guard: dom-window-cap)
  action appendTurnDeltaUnbounded = if (h.totalTurns < 6) h' = h.with("totalTurns", (h.totalTurns + 1)).with("mountedNodes", if (true) (h.mountedNodes + 1) else h.mountedNodes).with("pendingRafs", 1) else h' = h
  action stepUnboundedDomGrowth = any { step, appendTurnDeltaUnbounded }
  // Countermodel engineering.concurrency.ui-render-window-budget.full-reparse-stall (dropped guard: incremental-block-render)
  action flushFrameFullReparse = if (h.pendingRafs > 0) h' = h.with("pendingRafs", 0).with("frameWorkUnits", h.totalTurns) else h' = h
  action stepFullReparseStall = any { step, flushFrameFullReparse }
  action checkSteadyUiFrame = all { assert(h.mountedNodes <= 3), assert(h.pendingRafs <= 1), assert(h.frameWorkUnits <= 2), assert(h.totalTurns > 3), assert(safety), h' = h }
  action checkUiRenderViolation = all { assert((h.mountedNodes > 3 or h.frameWorkUnits > 2)), assert(not(safety)), h' = h }
  run windowedIncrementalRenderTest = init.then(appendTurnDelta).then(appendTurnDelta).then(appendTurnDelta).then(appendTurnDelta).then(flushFrame).then(switchSessionReset).then(flushFrame).then(checkSteadyUiFrame)
  run unboundedDomGrowthRefutedTest = init.then(appendTurnDelta).then(appendTurnDelta).then(appendTurnDelta).then(appendTurnDeltaUnbounded).then(checkUiRenderViolation)
  run fullReparseStallRefutedTest = init.then(appendTurnDelta).then(appendTurnDelta).then(appendTurnDelta).then(flushFrameFullReparse).then(checkUiRenderViolation)
}

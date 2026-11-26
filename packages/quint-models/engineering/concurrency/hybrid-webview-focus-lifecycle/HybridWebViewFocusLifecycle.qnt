// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.hybrid-webview-focus-lifecycle
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel async-warmup-off-render step=stepSyncMountStall max-steps=6 itf="h.renderBlocked == true"
// @countermodel revoke-focus-on-hide step=stepHiddenFocusLeak max-steps=6 itf="h.wvShown == false and h.wvFocused == true"
// @countermodel tier0-rpc-capability-gate step=stepUntrustedRpcEscalation max-steps=6 itf="h.rpcInvokedByTier == 2"
// Limits: Finite single-island hybrid WebView lifecycle abstraction; does not model multi-window AppKit responder chains, OS-level OOM kills, or WebKit internal IPC queuing.
module concurrency_hybrid_webview {
  type State = { wvState: int, wvShown: bool, wvFocused: bool, renderBlocked: bool, tier: int, rpcInvokedByTier: int }
  var h: State
  action init = h' = { wvState: 0, wvShown: false, wvFocused: false, renderBlocked: false, tier: 2, rpcInvokedByTier: 0 }
  action selectTier0 = if (h.wvState == 0) h' = h.with("tier", 0) else h' = h
  action requestMount = if (h.wvState == 0) h' = h.with("wvState", 1).with("wvShown", true).with("renderBlocked", false) else h' = h
  action finishWarmup = if (h.wvState == 1) h' = h.with("wvState", 2) else h' = h
  action focusWebView = if ((h.wvState == 2 and h.wvShown)) h' = h.with("wvFocused", true) else h' = h
  action hideTab = if (h.wvShown) h' = h.with("wvShown", false).with("wvFocused", false) else h' = h
  action showTab = if ((not(h.wvShown) and h.wvState == 2)) h' = h.with("wvShown", true) else h' = h
  action crashWebContent = if (h.wvState == 2) h' = h.with("wvState", 3).with("wvFocused", false) else h' = h
  action recoverWebContent = if (h.wvState == 3) h' = h.with("wvState", 1) else h' = h
  action invokeHostRpc = if ((h.wvState == 2 and h.tier == 0)) h' = h.with("rpcInvokedByTier", h.tier) else h' = h
  action step = any { selectTier0, requestMount, finishWarmup, focusWebView, hideTab, showTab, crashWebContent, recoverWebContent, invokeHostRpc }
  val safety = (not(h.renderBlocked) and (h.wvShown or not(h.wvFocused)) and h.rpcInvokedByTier == 0)
  // Countermodel engineering.concurrency.hybrid-webview-focus-lifecycle.sync-mount-stall (dropped guard: async-warmup-off-render)
  action requestMountSync = if (h.wvState == 0) h' = h.with("wvState", 1).with("wvShown", true).with("renderBlocked", true) else h' = h
  action stepSyncMountStall = any { step, requestMountSync }
  // Countermodel engineering.concurrency.hybrid-webview-focus-lifecycle.hidden-focus-leak (dropped guard: revoke-focus-on-hide)
  action hideTabLeaky = if (h.wvShown) h' = h.with("wvShown", false).with("wvFocused", h.wvFocused) else h' = h
  action stepHiddenFocusLeak = any { step, hideTabLeaky }
  // Countermodel engineering.concurrency.hybrid-webview-focus-lifecycle.untrusted-rpc-escalation (dropped guard: tier0-rpc-capability-gate)
  action invokeHostRpcUnchecked = if ((h.wvState == 2 and true)) h' = h.with("rpcInvokedByTier", h.tier) else h' = h
  action stepUntrustedRpcEscalation = any { step, invokeHostRpcUnchecked }
  run safeLifecycleAndRecoveryTest = init.then(selectTier0).then(requestMount).then(finishWarmup).then(focusWebView).then(invokeHostRpc).then(hideTab).then(crashWebContent).then(recoverWebContent).then(finishWarmup).then(all { assert(not(h.wvFocused)), assert(h.rpcInvokedByTier == 0), assert(safety), h' = h })
  run syncMountStallViolatesSafetyTest = init.then(requestMountSync).then(all { assert(h.renderBlocked), assert(not(safety)), h' = h })
  run hiddenFocusLeakViolatesSafetyTest = init.then(requestMount).then(finishWarmup).then(focusWebView).then(hideTabLeaky).then(all { assert(not(h.wvShown)), assert(h.wvFocused), assert(not(safety)), h' = h })
  run untrustedRpcViolatesSafetyTest = init.then(requestMount).then(finishWarmup).then(invokeHostRpcUnchecked).then(all { assert(h.rpcInvokedByTier == 2), assert(not(safety)), h' = h })
}

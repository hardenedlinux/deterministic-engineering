// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.tool-sandbox-rpc-boundary
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel require-pinned-schema-intact step=stepSchemaRugPull max-steps=6 itf="h.rugPullViolations > 0"
// @countermodel require-sandbox-scope-valid step=stepSandboxScopeEscape max-steps=6 itf="h.scopeEscapeViolations > 0"
// @countermodel require-no-pending-timeout step=stepBlindRpcRetry max-steps=6 itf="h.blindRetryViolations > 0"
// Limits: Single-tool bounded execution counter (safeExecutions < 3) over pinned schema integrity, sandbox scope validity, and PendingUnknownEffect timeout fencing; unbounded multi-tool and response-firewall properties are proved in ToolSandboxAndRpcBoundary.lean.
module tool_sandbox_rpc_boundary {
  type State = { manifestPinned: bool, schemaRugPulled: bool, scopeValid: bool, rpcTimeoutPending: bool, safeExecutions: int, rugPullViolations: int, scopeEscapeViolations: int, blindRetryViolations: int }
  var h: State
  action init = h' = { manifestPinned: false, schemaRugPulled: false, scopeValid: false, rpcTimeoutPending: false, safeExecutions: 0, rugPullViolations: 0, scopeEscapeViolations: 0, blindRetryViolations: 0 }
  action pinToolManifest = if (not(h.manifestPinned)) h' = h.with("manifestPinned", true) else h' = h
  action grantValidScope = if (not(h.scopeValid)) h' = h.with("scopeValid", true) else h' = h
  action mutateSchemaRugPull = if ((h.manifestPinned and not(h.schemaRugPulled))) h' = h.with("schemaRugPulled", true) else h' = h
  action triggerAmbiguousTimeout = if ((h.manifestPinned and not(h.rpcTimeoutPending))) h' = h.with("rpcTimeoutPending", true) else h' = h
  action reconcileTimeout = if (h.rpcTimeoutPending) h' = h.with("rpcTimeoutPending", false) else h' = h
  action invokeToolSafe = if ((h.safeExecutions < 3 and (h.manifestPinned and not(h.schemaRugPulled)) and h.scopeValid and not(h.rpcTimeoutPending))) h' = h.with("safeExecutions", (h.safeExecutions + 1)).with("rugPullViolations", if ((h.manifestPinned and not(h.schemaRugPulled))) h.rugPullViolations else (h.rugPullViolations + 1)).with("scopeEscapeViolations", if (h.scopeValid) h.scopeEscapeViolations else (h.scopeEscapeViolations + 1)).with("blindRetryViolations", if (not(h.rpcTimeoutPending)) h.blindRetryViolations else (h.blindRetryViolations + 1)) else h' = h
  action step = any { pinToolManifest, grantValidScope, mutateSchemaRugPull, triggerAmbiguousTimeout, reconcileTimeout, invokeToolSafe }
  val safety = (h.rugPullViolations == 0 and h.scopeEscapeViolations == 0 and h.blindRetryViolations == 0)
  // Countermodel engineering.defense.tool-sandbox-rpc-boundary.schema-rug-pull (dropped guard: require-pinned-schema-intact)
  action invokeToolRugPull = if ((h.safeExecutions < 3 and true and h.scopeValid and not(h.rpcTimeoutPending))) h' = h.with("safeExecutions", (h.safeExecutions + 1)).with("rugPullViolations", if ((h.manifestPinned and not(h.schemaRugPulled))) h.rugPullViolations else (h.rugPullViolations + 1)).with("scopeEscapeViolations", if (h.scopeValid) h.scopeEscapeViolations else (h.scopeEscapeViolations + 1)).with("blindRetryViolations", if (not(h.rpcTimeoutPending)) h.blindRetryViolations else (h.blindRetryViolations + 1)) else h' = h
  action stepSchemaRugPull = any { step, invokeToolRugPull }
  // Countermodel engineering.defense.tool-sandbox-rpc-boundary.sandbox-scope-escape (dropped guard: require-sandbox-scope-valid)
  action invokeToolScopeEscape = if ((h.safeExecutions < 3 and (h.manifestPinned and not(h.schemaRugPulled)) and true and not(h.rpcTimeoutPending))) h' = h.with("safeExecutions", (h.safeExecutions + 1)).with("rugPullViolations", if ((h.manifestPinned and not(h.schemaRugPulled))) h.rugPullViolations else (h.rugPullViolations + 1)).with("scopeEscapeViolations", if (h.scopeValid) h.scopeEscapeViolations else (h.scopeEscapeViolations + 1)).with("blindRetryViolations", if (not(h.rpcTimeoutPending)) h.blindRetryViolations else (h.blindRetryViolations + 1)) else h' = h
  action stepSandboxScopeEscape = any { step, invokeToolScopeEscape }
  // Countermodel engineering.defense.tool-sandbox-rpc-boundary.blind-rpc-retry (dropped guard: require-no-pending-timeout)
  action invokeToolBlindRetry = if ((h.safeExecutions < 3 and (h.manifestPinned and not(h.schemaRugPulled)) and h.scopeValid and true)) h' = h.with("safeExecutions", (h.safeExecutions + 1)).with("rugPullViolations", if ((h.manifestPinned and not(h.schemaRugPulled))) h.rugPullViolations else (h.rugPullViolations + 1)).with("scopeEscapeViolations", if (h.scopeValid) h.scopeEscapeViolations else (h.scopeEscapeViolations + 1)).with("blindRetryViolations", if (not(h.rpcTimeoutPending)) h.blindRetryViolations else (h.blindRetryViolations + 1)) else h' = h
  action stepBlindRpcRetry = any { step, invokeToolBlindRetry }
  run cleanMcpInvocationAndReconcileTest = init.then(pinToolManifest).then(grantValidScope).then(invokeToolSafe).then(triggerAmbiguousTimeout).then(invokeToolSafe).then(reconcileTimeout).then(invokeToolSafe).then(all { assert(safety), assert(h.safeExecutions == 2), h' = h })
  run schemaRugPullViolatesSafetyTest = init.then(pinToolManifest).then(grantValidScope).then(mutateSchemaRugPull).then(invokeToolRugPull).then(all { assert(not(safety)), assert(h.rugPullViolations > 0), h' = h })
  run scopeEscapeViolatesSafetyTest = init.then(pinToolManifest).then(invokeToolScopeEscape).then(all { assert(not(safety)), assert(h.scopeEscapeViolations > 0), h' = h })
  run blindRetryViolatesSafetyTest = init.then(pinToolManifest).then(grantValidScope).then(triggerAmbiguousTimeout).then(invokeToolBlindRetry).then(all { assert(not(safety)), assert(h.blindRetryViolations > 0), h' = h })
}

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B11 (10.182 / 10.183): Deterministic MCP / Tool-Sandbox
;;; & RPC Schema-Boundary Safety.
;;; Proves three MCP / RPC tool execution boundary invariants:
;;;   1. Pinned Manifest & Anti-Rug-Pull Integrity: tool execution never proceeds
;;;      if the tool is unpinned or its observed schema mutated from the M1 pinned
;;;      manifest (rugPullViolations == 0).
;;;   2. Sandbox Scope Confinement: tool execution never escapes its narrowed M3
;;;      sandbox capability scopes (scopeEscapeViolations == 0).
;;;   3. Ambiguous RPC Timeout Fence: an unreconciled PendingUnknownEffect timeout
;;;      unconditionally blocks blind side-effect retry until reconciled
;;;      (blindRetryViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ToolSandboxRpcBoundaryModel
        SchemaRugPullCountermodel
        SandboxScopeEscapeCountermodel
        BlindRpcRetryCountermodel)

(.def (ToolSandboxRpcBoundaryModel @ ThreatModel.)
  identity: 'engineering.defense.tool-sandbox-rpc-boundary
  family: 'engineering.defense.tool-sandbox-rpc-boundary
  title: "Deterministic MCP / Tool-Sandbox & RPC Schema-Boundary Safety"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Model Context Protocol Security Advisory & Tool-Poisoning Literature (2025)"
     "MCP tool-description rug-pull, shadow tool injection, and cross-tool privilege escalation.")
    ("E. Debenedetti et al. (2025)"
     "CaMeL: Defeating Prompt Injections by Design — isolating untrusted tool outputs from control flow.")
    ("Deterministic Engineering (10.182 / 10.183)"
     "Immutable M1 MCP tool manifest pinning, R3 ToolSandboxCapability confinement, and PendingUnknownEffect RPC timeout fencing."))
  quint-module: "tool_sandbox_rpc_boundary"
  quint-file: "ToolSandboxRpcBoundary.qnt"
  domain-dir: "engineering/defense/tool-sandbox-rpc-boundary"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((tool-sandbox-rpc-safe DE-TSR-SAFE quint)
    (tool-sandbox-rpc-countermodel DE-TSR-COUNTER quint))
  dependencies:
  '((DE-TSR-SAFE source)
    (DE-TSR-SAFE profile)
    (DE-TSR-SAFE method)
    (DE-TSR-COUNTER source)
    (DE-TSR-COUNTER profile)
    (DE-TSR-COUNTER method))
  invariant: "Tool execution requires an intact M1-pinned schema (rugPullViolations == 0), valid M3 sandbox scope containment (scopeEscapeViolations == 0), and zero unreconciled PendingUnknownEffect RPC timeouts (blindRetryViolations == 0)."
  parameters: '()
  state:
  '((manifestPinned "bool" "false")
    (schemaRugPulled "bool" "false")
    (scopeValid "bool" "false")
    (rpcTimeoutPending "bool" "false")
    (safeExecutions "int" "0")
    (rugPullViolations "int" "0")
    (scopeEscapeViolations "int" "0")
    (blindRetryViolations "int" "0"))
  guards:
  '((require-pinned-schema-intact (and (. h manifestPinned) (not (. h schemaRugPulled))))
    (require-sandbox-scope-valid (. h scopeValid))
    (require-no-pending-timeout (not (. h rpcTimeoutPending))))
  transitions:
  '((pinToolManifest
      (action pinToolManifest ()
        (if (not (. h manifestPinned))
          (set-h (manifestPinned #t))
          (keep-h))))
    (grantValidScope
      (action grantValidScope ()
        (if (not (. h scopeValid))
          (set-h (scopeValid #t))
          (keep-h))))
    (mutateSchemaRugPull
      (action mutateSchemaRugPull ()
        (if (and (. h manifestPinned) (not (. h schemaRugPulled)))
          (set-h (schemaRugPulled #t))
          (keep-h))))
    (triggerAmbiguousTimeout
      (action triggerAmbiguousTimeout ()
        (if (and (. h manifestPinned) (not (. h rpcTimeoutPending)))
          (set-h (rpcTimeoutPending #t))
          (keep-h))))
    (reconcileTimeout
      (action reconcileTimeout ()
        (if (. h rpcTimeoutPending)
          (set-h (rpcTimeoutPending #f))
          (keep-h))))
    (invokeToolSafe
      (action invokeToolSafe ()
        (if (and (< (. h safeExecutions) 3)
                 (guard require-pinned-schema-intact (and (. h manifestPinned) (not (. h schemaRugPulled))))
                 (guard require-sandbox-scope-valid (. h scopeValid))
                 (guard require-no-pending-timeout (not (. h rpcTimeoutPending))))
          (set-h (safeExecutions (+ (. h safeExecutions) 1))
                 (rugPullViolations
                   (if (and (. h manifestPinned) (not (. h schemaRugPulled)))
                     (. h rugPullViolations)
                     (+ (. h rugPullViolations) 1)))
                 (scopeEscapeViolations
                   (if (. h scopeValid)
                     (. h scopeEscapeViolations)
                     (+ (. h scopeEscapeViolations) 1)))
                 (blindRetryViolations
                   (if (not (. h rpcTimeoutPending))
                     (. h blindRetryViolations)
                     (+ (. h blindRetryViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any pinToolManifest grantValidScope mutateSchemaRugPull
             triggerAmbiguousTimeout reconcileTimeout invokeToolSafe))))
  safety:
  '(and (= (. h rugPullViolations) 0)
        (= (. h scopeEscapeViolations) 0)
        (= (. h blindRetryViolations) 0))
  traces:
  '((cleanMcpInvocationAndReconcileTest
      (run cleanMcpInvocationAndReconcileTest
        (then init pinToolManifest grantValidScope invokeToolSafe
              triggerAmbiguousTimeout invokeToolSafe reconcileTimeout invokeToolSafe
              (all (assert safety)
                   (assert (= (. h safeExecutions) 2))
                   (keep-h)))))
    (schemaRugPullViolatesSafetyTest
      (run schemaRugPullViolatesSafetyTest
        (then init pinToolManifest grantValidScope mutateSchemaRugPull invokeToolRugPull
              (all (assert (not safety))
                   (assert (> (. h rugPullViolations) 0))
                   (keep-h)))))
    (scopeEscapeViolatesSafetyTest
      (run scopeEscapeViolatesSafetyTest
        (then init pinToolManifest invokeToolScopeEscape
              (all (assert (not safety))
                   (assert (> (. h scopeEscapeViolations) 0))
                   (keep-h)))))
    (blindRetryViolatesSafetyTest
      (run blindRetryViolatesSafetyTest
        (then init pinToolManifest grantValidScope triggerAmbiguousTimeout invokeToolBlindRetry
              (all (assert (not safety))
                   (assert (> (. h blindRetryViolations) 0))
                   (keep-h))))))
  countermodels:
  (list SchemaRugPullCountermodel
        SandboxScopeEscapeCountermodel
        BlindRpcRetryCountermodel)
  limits: "Single-tool bounded execution counter (safeExecutions < 3) over pinned schema integrity, sandbox scope validity, and PendingUnknownEffect timeout fencing; unbounded multi-tool and response-firewall properties are proved in ToolSandboxAndRpcBoundary.lean.")

(.def (SchemaRugPullCountermodel @ ToolSandboxRpcBoundaryModel)
  identity: 'engineering.defense.tool-sandbox-rpc-boundary.schema-rug-pull
  dropped-guard: 'require-pinned-schema-intact
  step-action: "stepSchemaRugPull"
  derive-from-transition: 'invokeToolSafe
  derive-action-name: 'invokeToolRugPull
  expected-itf-predicate: "h.rugPullViolations > 0")

(.def (SandboxScopeEscapeCountermodel @ ToolSandboxRpcBoundaryModel)
  identity: 'engineering.defense.tool-sandbox-rpc-boundary.sandbox-scope-escape
  dropped-guard: 'require-sandbox-scope-valid
  step-action: "stepSandboxScopeEscape"
  derive-from-transition: 'invokeToolSafe
  derive-action-name: 'invokeToolScopeEscape
  expected-itf-predicate: "h.scopeEscapeViolations > 0")

(.def (BlindRpcRetryCountermodel @ ToolSandboxRpcBoundaryModel)
  identity: 'engineering.defense.tool-sandbox-rpc-boundary.blind-rpc-retry
  dropped-guard: 'require-no-pending-timeout
  step-action: "stepBlindRpcRetry"
  derive-from-transition: 'invokeToolSafe
  derive-action-name: 'invokeToolBlindRetry
  expected-itf-predicate: "h.blindRetryViolations > 0")

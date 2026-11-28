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
(export ToolSandboxRpcBoundaryModel)

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
  limits: "Single-tool bounded execution counter (safeExecutions < 3) over pinned schema integrity, sandbox scope validity, and PendingUnknownEffect timeout fencing; unbounded multi-tool and response-firewall properties are proved in ToolSandboxAndRpcBoundary.lean.")

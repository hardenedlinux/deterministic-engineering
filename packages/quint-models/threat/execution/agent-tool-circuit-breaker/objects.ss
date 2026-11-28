;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; AI Agent & Tool Execution Circuit Breaker ("E-Stop / Trip-Wire") threat model.
;;; Co-located Yuanxu unit: single source of truth alongside AgentToolCircuitBreaker.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export AgentToolCircuitBreakerModel)

(.def (AgentToolCircuitBreakerModel @ AuthorityCurrentnessModel)
  identity: 'threat.execution.agent-tool-circuit-breaker
  family: 'threat.execution.agent-tool-circuit-breaker
  title: "Agent & Tool Execution Circuit Breaker, Lease Epoch Fencing, and Human-Only Re-Arm"
  subdomain: 'quint.threat.execution
  papers:
  '(("N. Leveson (MIT Press, 2011)"
     "Engineering a Safer World: fail-safe latched trip-wires, independent interlocks, and non-self-resetting emergency stops.")
    ("E. Debenedetti et al. (2025)"
     "Defeating Prompt Injections by Design (CaMeL): deterministic runtime control-plane enforcement outside the AI agent's authority."))
  quint-module: "agent_tool_circuit_breaker"
  quint-file: "AgentToolCircuitBreaker.qnt"
  domain-dir: "threat/execution/agent-tool-circuit-breaker"
  rules:
  '((breaker-closed-at-commit ATCB-BREAKER-CLOSED quint)
    (lease-epoch-current ATCB-LEASE-EPOCH quint)
    (human-only-rearm ATCB-HUMAN-REARM quint)
    (tool-budget-bounded ATCB-BUDGET-CAP quint))
  dependencies:
  '((ATCB-BREAKER-CLOSED source)
    (ATCB-BREAKER-CLOSED profile)
    (ATCB-BREAKER-CLOSED method)
    (ATCB-LEASE-EPOCH source)
    (ATCB-LEASE-EPOCH profile)
    (ATCB-LEASE-EPOCH method)
    (ATCB-HUMAN-REARM source)
    (ATCB-HUMAN-REARM profile)
    (ATCB-HUMAN-REARM method)
    (ATCB-BUDGET-CAP source)
    (ATCB-BUDGET-CAP profile)
    (ATCB-BUDGET-CAP method))
  invariant: "Tool execution effects never commit while the circuit breaker is tripped or via a pre-trip stale lease after re-arm, AI agents never self-rearm a tripped breaker, and execution never exceeds the armed budget cap."
  limits: "Finite single-lease execution breaker and armed-window budget abstraction; does not model OS process SIGKILL signal delivery latencies, hardware watchdogs, or distributed consensus across multi-region executors.")

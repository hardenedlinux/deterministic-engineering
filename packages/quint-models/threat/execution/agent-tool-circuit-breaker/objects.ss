;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; AI Agent & Tool Execution Circuit Breaker ("E-Stop / Trip-Wire") threat model.
;;; Co-located Yuanxu unit: single source of truth alongside AgentToolCircuitBreaker.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export AgentToolCircuitBreakerModel
        ExecWhileTrippedCountermodel
        StaleLeaseAfterTripCountermodel
        AgentSelfRearmCountermodel
        BudgetRunawayCountermodel)

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
  quint-imports:
  '(("authority_currentness" "../../zero-trust/authority-currentness/AuthorityCurrentness"))
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
  parameters: '()
  state:
  '((breakerTripped "bool" "false")
    (tripEpoch "int" "1")
    (budgetUsed "int" "0")
    (leaseActive "bool" "false")
    (leaseEpoch "int" "0")
    (execWhileTripped "bool" "false")
    (staleLeaseCommit "bool" "false")
    (agentSelfRearmed "bool" "false")
    (budgetOverrun "bool" "false"))
  guards:
  '((breaker-closed-at-commit (not (. h breakerTripped)))
    (lease-epoch-current (call epochCurrent (. h tripEpoch) (. h leaseEpoch)))
    (human-only-rearm (and (not isAgent) verifiedHuman))
    (tool-budget-bounded (< (. h budgetUsed) 1)))
  transitions:
  '((acquireToolLease
      (action acquireToolLease ()
        (if (and (not (. h breakerTripped)) (not (. h leaseActive)))
          (set-h (leaseActive #t)
                 (leaseEpoch (. h tripEpoch)))
          (keep-h))))
    (commitToolEffect
      (action commitToolEffect ()
        (if (and (. h leaseActive)
                 (guard breaker-closed-at-commit (not (. h breakerTripped)))
                 (guard lease-epoch-current (call epochCurrent (. h tripEpoch) (. h leaseEpoch)))
                 (guard tool-budget-bounded (< (. h budgetUsed) 1)))
          (set-h (leaseActive #f)
                 (leaseEpoch 0)
                 (budgetUsed (+ (. h budgetUsed) 1))
                 (execWhileTripped (or (. h execWhileTripped) (. h breakerTripped)))
                 (staleLeaseCommit (or (. h staleLeaseCommit) (!= (. h tripEpoch) (. h leaseEpoch))))
                 (budgetOverrun (or (. h budgetOverrun) (>= (. h budgetUsed) 1))))
          (keep-h))))
    (tripBreaker
      (action tripBreaker ()
        (if (not (. h breakerTripped))
          (set-h (breakerTripped #t))
          (keep-h))))
    (rearmBreakerAs
      (action rearmBreakerAs ((isAgent "bool") (verifiedHuman "bool")) "bool"
        (if (and (. h breakerTripped)
                 (< (. h tripEpoch) 4)
                 (guard human-only-rearm (and (not isAgent) verifiedHuman)))
          (set-h (breakerTripped #f)
                 (tripEpoch (+ (. h tripEpoch) 1))
                 (budgetUsed 0)
                 (agentSelfRearmed (or (. h agentSelfRearmed) isAgent (not verifiedHuman))))
          (keep-h))))
    (rearmBreaker
      (action rearmBreaker ()
        (nondet ((isAgent (set #f #t))
                 (verifiedHuman (set #f #t)))
          (call rearmBreakerAs isAgent verifiedHuman))))
    (cancelStaleLease
      (action cancelStaleLease ()
        (if (and (. h leaseActive)
                 (or (. h breakerTripped) (!= (. h leaseEpoch) (. h tripEpoch))))
          (set-h (leaseActive #f)
                 (leaseEpoch 0))
          (keep-h))))
    (step
      (action step ()
        (any acquireToolLease commitToolEffect tripBreaker rearmBreaker cancelStaleLease))))
  safety:
  '(and (not (. h execWhileTripped))
        (not (. h staleLeaseCommit))
        (not (. h agentSelfRearmed))
        (not (. h budgetOverrun))
        (<= (. h budgetUsed) 1))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (validLeaseCommitTripAndRearmTest
      (run validLeaseCommitTripAndRearmTest
        (then init
              acquireToolLease
              commitToolEffect
              tripBreaker
              (call rearmBreakerAs #f #t)
              acquireToolLease
              commitToolEffect
              (all (assert (= (. h tripEpoch) 2))
                   (assert (= (. h budgetUsed) 1))
                   (assert safety)
                   (keep-h)))))
    (tripBlocksInFlightLeaseAndAgentRearmTest
      (run tripBlocksInFlightLeaseAndAgentRearmTest
        (then init
              acquireToolLease
              tripBreaker
              commitToolEffect
              (call rearmBreakerAs #t #f)
              (call rearmBreakerAs #f #t)
              commitToolEffect
              (all (assert (= (. h budgetUsed) 0))
                   (assert (not (. h execWhileTripped)))
                   (assert (not (. h staleLeaseCommit)))
                   (assert (not (. h agentSelfRearmed)))
                   (assert safety)
                   (keep-h)))))
    (budgetCapBlocksRunawayToolTest
      (run budgetCapBlocksRunawayToolTest
        (then init
              acquireToolLease
              commitToolEffect
              acquireToolLease
              commitToolEffect
              (all (assert (= (. h budgetUsed) 1))
                   (assert (not (. h budgetOverrun)))
                   (assert safety)
                   (keep-h)))))
    (execWhileTrippedCountermodelTest
      (run execWhileTrippedCountermodelTest
        (then init
              acquireToolLease
              tripBreaker
              commitToolWhileTripped
              checkUnsafe)))
    (staleLeaseAfterTripCountermodelTest
      (run staleLeaseAfterTripCountermodelTest
        (then init
              acquireToolLease
              tripBreaker
              (call rearmBreakerAs #f #t)
              commitToolStaleLease
              checkUnsafe)))
    (agentSelfRearmCountermodelTest
      (run agentSelfRearmCountermodelTest
        (then init
              tripBreaker
              (call rearmBreakerUnchecked #t #f)
              checkUnsafe)))
    (budgetRunawayCountermodelTest
      (run budgetRunawayCountermodelTest
        (then init
              acquireToolLease
              commitToolEffect
              acquireToolLease
              commitToolNoBudgetCap
              checkUnsafe))))
  countermodels:
  (list ExecWhileTrippedCountermodel
        StaleLeaseAfterTripCountermodel
        AgentSelfRearmCountermodel
        BudgetRunawayCountermodel)
  limits: "Finite single-lease execution breaker and armed-window budget abstraction; does not model OS process SIGKILL signal delivery latencies, hardware watchdogs, or distributed consensus across multi-region executors.")

(.def (ExecWhileTrippedCountermodel @ AgentToolCircuitBreakerModel)
  identity: 'threat.execution.agent-tool-circuit-breaker.exec-while-tripped
  dropped-guard: 'breaker-closed-at-commit
  step-action: "stepExecWhileTripped"
  derive-from-transition: 'commitToolEffect
  derive-action-name: 'commitToolWhileTripped
  expected-itf-predicate: "h.execWhileTripped == true")

(.def (StaleLeaseAfterTripCountermodel @ AgentToolCircuitBreakerModel)
  identity: 'threat.execution.agent-tool-circuit-breaker.stale-lease-after-trip
  dropped-guard: 'lease-epoch-current
  step-action: "stepStaleLeaseAfterTrip"
  derive-from-transition: 'commitToolEffect
  derive-action-name: 'commitToolStaleLease
  expected-itf-predicate: "h.staleLeaseCommit == true")

(.def (AgentSelfRearmCountermodel @ AgentToolCircuitBreakerModel)
  identity: 'threat.execution.agent-tool-circuit-breaker.agent-self-rearm
  dropped-guard: 'human-only-rearm
  step-action: "stepAgentSelfRearm"
  derive-from-transition: 'rearmBreakerAs
  derive-action-name: 'rearmBreakerUnchecked
  derive-step-call: '(nondet ((isAgent (set #f #t)) (verifiedHuman (set #f #t)))
                       (call rearmBreakerUnchecked isAgent verifiedHuman))
  expected-itf-predicate: "h.agentSelfRearmed == true")

(.def (BudgetRunawayCountermodel @ AgentToolCircuitBreakerModel)
  identity: 'threat.execution.agent-tool-circuit-breaker.budget-runaway
  dropped-guard: 'tool-budget-bounded
  step-action: "stepBudgetRunaway"
  derive-from-transition: 'commitToolEffect
  derive-action-name: 'commitToolNoBudgetCap
  expected-itf-predicate: "h.budgetOverrun == true")

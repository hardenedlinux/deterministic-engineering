;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Adversarial (ADV-L4) single-owner GraphEngine execution convergence and
;;; production-reachable governance confinement defeating AI additive legacy
;;; dual-engine accretion and disconnected governance bypasses (SM25, 103rd Quint model).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SingleOwnerGraphGovernanceConfinementModel)

(.def (SingleOwnerGraphGovernanceConfinementModel @ ThreatModel.)
  identity: 'threat.execution.single-owner-graph-governance-confinement
  family: 'threat.execution.single-owner-graph-governance-confinement
  title: "Adversarial (ADV-L4) Single-Owner Graph Execution Convergence & Reachable Production Governance Confinement"
  subdomain: 'quint.threat.execution
  papers:
  '(("Saltzer & Schroeder (1975) Complete Mediation & Economy of Mechanism"
     "Every production physical side effect (sandbox command, CAS write, LLM dispatch) must pass through one authoritative governance mediation point; keeping an unretired shadow Loop engine creates split-brain bypasses and governance theater.")
    ("Miller (2006) Robust Composition & Single Authoritative Owner Principle"
     "Attaching Cedar/ASCENT governance gates and E-Stop circuit breakers solely to a legacy Loop engine while the production GraphEngine (TaskActorControlPlane + CompositeAtomicEffectExecutor) executes ungated breaks complete mediation.")
    ("AI Defensive Programming Anti-Pattern: Additive Defensive Accretion (Real-Repo Marlin Case)"
     "When AI coding agents migrate from a legacy Loop FSM to a GraphEngine without retiring the legacy engine or wiring governance into the new production binary, unit tests pass green while live production tools bypass E-Stop and Cedar forbid rules."))
  quint-module: "execution_single_owner_graph_governance_confinement"
  quint-file: "SingleOwnerGraphGovernanceConfinement.qnt"
  domain-dir: "threat/execution/single-owner-graph-governance-confinement"
  rules:
  '((exec-graph-prod-gov-wired EXEC-GRAPH-PROD-GOV-WIRED quint)
    (exec-graph-retire-shadow-loop EXEC-GRAPH-RETIRE-SHADOW-LOOP quint)
    (exec-graph-breaker-fail-closed EXEC-GRAPH-BREAKER-FAIL-CLOSED quint)
    (exec-graph-epoch-bound EXEC-GRAPH-EPOCH-BOUND quint))
  dependencies:
  '((EXEC-GRAPH-PROD-GOV-WIRED source)
    (EXEC-GRAPH-PROD-GOV-WIRED profile)
    (EXEC-GRAPH-PROD-GOV-WIRED method)
    (EXEC-GRAPH-RETIRE-SHADOW-LOOP source)
    (EXEC-GRAPH-RETIRE-SHADOW-LOOP profile)
    (EXEC-GRAPH-RETIRE-SHADOW-LOOP method)
    (EXEC-GRAPH-BREAKER-FAIL-CLOSED source)
    (EXEC-GRAPH-BREAKER-FAIL-CLOSED profile)
    (EXEC-GRAPH-BREAKER-FAIL-CLOSED method)
    (EXEC-GRAPH-EPOCH-BOUND source)
    (EXEC-GRAPH-EPOCH-BOUND profile)
    (EXEC-GRAPH-EPOCH-BOUND method))
  invariant: "Under ADV-L4 hostile split-brain and governance-evasion probes, every production GraphEngine effect and TaskActor dispatch traverses the active GovernanceAdmissionGate and ExecutionCircuitBreaker fail-closed (disconnectedGovBypasses == 0 and trippedBreakerBypasses == 0), unretired legacy shadow loops cannot execute production side effects (shadowLegacyExecutions == 0), and superseded fencing/governance epochs are deterministically rejected (staleEpochDualDispatches == 0)."
  limits: "Finite single-owner GraphEngine execution convergence and production-reachable governance admission abstraction (ADV-L4 hostile attack tier); proves every production atomic effect and TaskActor dispatch traverses the active GovernanceAdmissionGate/ExecutionCircuitBreaker with zero legacy-loop shadow execution, not arbitrary OS kernel bypasses.")

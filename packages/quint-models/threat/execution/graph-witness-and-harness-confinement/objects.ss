;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM35 (ADV-L4): AgentGraph Sealed-Witness/Routing Integrity & Live Harness
;;; Cedar Governance, Artifact Confinement & Config Route Hygiene.
;;; Formalizes five real ADV-L4 vulnerabilities discovered in
;;; marlin-agent-graph and marlin-agent-harness (plus marlin-agent-harness-types):
;;;  1. AdmittedGovernedContext, AdmittedMarlinDispatch, and FencingEpoch
;;;     derived Serde Deserialize directly, letting forged JSON bypass
;;;     admit_governed_context_capsule, admit_marlin_dispatch, and
;;;     FencingEpoch::new(0); reconcile_marlin_execution_receipt accepted
;;;     Settled receipts on Detached scopes and stalled on u64::MAX epoch;
;;;     graph semantic IDs admitted control characters.
;;;  2. edge_condition_matches returned true unconditionally for
;;;     AgentEdgeCondition::PolicyDecision(_) even in Deterministic and
;;;     CapabilityFirst graphs without any policy receipt; policy_scoped
;;;     planning and candidate routing projection accepted duplicate edges
;;;     and omitted GerbilPolicyReceipt evidence & target capability checks.
;;;  3. CompiledHarnessGovernanceGate::evaluate_tool_call let substring
;;;     "search" in destructive tool names (search_exec) or caller-supplied
;;;     declared_capability=Some("search") classify exec/shell/rm tools as
;;;     non-write "search", used case-sensitive tool/capability matching,
;;;     and accepted empty or contradictory Cedar policy sets at compile().
;;;  4. materialize_gerbil_scripted_intent_case_artifact_bundle relied on
;;;     lexical-only safe_relative_path (which also accepted "" and ".")
;;;     and non-atomic fs::write without symlink confinement, duplicate
;;;     path rejection, or manifest artifact capacity caps.
;;;  5. LiveWeaverTomlConfig::load performed unbounded fs::read_to_string
;;;     without symlink checks, accepted zero/unbounded timeout_seconds and
;;;     max_stream_bytes, and permitted dangerous ambient credential_env
;;;     names such as PATH, HOME, or LD_PRELOAD.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export GraphWitnessAndHarnessConfinementModel)

(.def (GraphWitnessAndHarnessConfinementModel @ ThreatModel.)
  identity: 'threat.execution.graph-witness-and-harness-confinement
  family: 'threat.execution.graph-witness-and-harness-confinement
  title: "AgentGraph Witness/Routing & Harness Governance Confinement (SM35)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM35 ADV-L4 custom validated Deserialize parity on AdmittedGovernedContext, AdmittedMarlinDispatch, and FencingEpoch with Detached-settlement and epoch-exhaustion reconciliation guards, PolicyDecision evidence and duplicate-edge confinement in AgentGraph planning/projection, fail-closed destructive-tool classification and case-insensitive Cedar enforcement in CompiledHarnessGovernanceGate, symlink-safe atomic intent-case artifact materialization, and bounded non-symlink Weaver TOML route loading with timeout and credential_env allowlist hygiene.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-agent-graph allowed Serde forgery of AdmittedGovernedContext/AdmittedMarlinDispatch/FencingEpoch(0), Detached settlement reconciliation, and unguarded PolicyDecision edge routing with duplicate candidate edges; marlin-agent-harness suffered capability-spoofing and substring/case bypasses in CompiledHarnessGovernanceGate, symlink overwrite escapes and empty-path bugs in intent_case_artifact materialization, and unbounded TOML reads with unsafe credential_env extraction in LiveWeaverTomlConfig."))
  quint-module: "execution_graph_witness_and_harness_confinement"
  quint-file: "GraphWitnessAndHarnessConfinement.qnt"
  domain-dir: "threat/execution/graph-witness-and-harness-confinement"
  rules:
  '((graph-witness-harness-safe DE-SM35-SAFE quint)
    (graph-witness-harness-countermodel DE-SM35-COUNTER quint))
  dependencies:
  '((DE-SM35-SAFE source)
    (DE-SM35-SAFE profile)
    (DE-SM35-SAFE method)
    (DE-SM35-COUNTER source)
    (DE-SM35-COUNTER profile)
    (DE-SM35-COUNTER method))
  invariant: "Sealed AgentGraph witnesses and fencing epochs enforce admission invariants across Serde deserialization and reconciliation (witnessForgeryBreaches == 0 and witnessSerdeEnforced and fencingEpoch >= 1 and contextCut >= 1), PolicyDecision graph edges require policy-scoped receipts with deduplicated candidates (routingPolicyBreaches == 0 and routingPolicyEnforced), harness Cedar tool governance prevents destructive-tool capability spoofing and case-mismatch bypasses (cedarSpoofBreaches == 0 and cedarGateHardened), and intent-case artifact materialization plus Weaver TOML config loading enforce symlink, byte, timeout, and credential_env confinement (artifactConfigBreaches == 0 and artifactAndConfigConfined)."
  limits: "Finite bounded AgentGraph witness/routing & live-harness governance/artifact confinement state machine (fencingEpoch <= 12, contextCut <= 12, stepCount <= 12); models custom validated Deserialize parity on AdmittedGovernedContext, AdmittedMarlinDispatch & FencingEpoch with Detached-settlement/overflow reconciliation guards, PolicyDecision evidence + duplicate-edge rejection in AgentGraph planning/projection, destructive-tool precedence & case-insensitive Cedar gate admission in CompiledHarnessGovernanceGate, symlink-safe atomic intent-case artifact materialization, and bounded non-symlink Weaver TOML route loading with timeout & credential_env allowlist hygiene, without modeling OS kernel VFS races or remote LLM wire transport.")

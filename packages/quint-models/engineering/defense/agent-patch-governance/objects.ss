;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; G2 / G5 / M3: AI Agent Patch Admission & Bounded Anti-Evasion Repair Loop (10.155).
;;; Proves that an AI Agent's prose claim never substitutes for independent mechanical audit,
;;; that deleting a verification obligation in a diff blocks admission unless a replacement
;;; witness is admitted, that floor weakening during retry is refused, and that retry exhaustion
;;; escalates to human review rather than silently admitting.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export AgentPatchGovernanceModel)

(.def (AgentPatchGovernanceModel @ ThreatModel.)
  identity: 'engineering.defense.agent-patch-governance
  family: 'engineering.defense.agent-patch-governance
  title: "AI Agent Patch Admission & Bounded Anti-Evasion Repair Loop"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Deterministic Engineering (10.18 / 10.153 / 10.155)"
     "Agent prose claims are assertions, never evidence; independent audit, obligation preservation, monotonic floors, and bounded human escalation.")
    ("Deterministic Engineering (30.05)"
     "Thirty-two-case five-language AI Agent defensive hallucination and anti-evasion benchmark."))
  quint-module: "agent_patch_governance"
  quint-file: "AgentPatchGovernance.qnt"
  domain-dir: "engineering/defense/agent-patch-governance"
  rules:
  '((agent-patch-safe DE-AGT-SAFE quint)
    (agent-patch-countermodel DE-AGT-COUNTER quint))
  dependencies:
  '((DE-AGT-SAFE source)
    (DE-AGT-SAFE profile)
    (DE-AGT-SAFE method)
    (DE-AGT-COUNTER source)
    (DE-AGT-COUNTER profile)
    (DE-AGT-COUNTER method))
  invariant: "Repair attempts stay within bound (repairAttempts <= 2), and no AI Agent patch reaches Admitted (decision == 1) without independent mechanical audit, intact Band-5 floors (not floorWeakened), and preserved or explicitly replaced verification obligations."
  limits: "Finite single-patch governance loop with bounded retry budget (max 2 retries); does not model multi-PR merge conflicts, compromised CI runners, or adversarial oracle poisoning.")

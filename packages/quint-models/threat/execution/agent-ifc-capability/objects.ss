;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; AI Agent Control/Data Flow Segregation & Capability-Based IFC threat model.
;;; Co-located Yuanxu unit: single source of truth alongside AgentIfcCapability.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export AgentIfcCapabilityModel)

(.def (AgentIfcCapabilityModel @ AuthorityCurrentnessModel)
  identity: 'threat.execution.agent-ifc-capability
  family: 'threat.execution.agent-ifc-capability
  title: "AI Agent Control/Data Segregation & Capability-Based IFC"
  subdomain: 'quint.threat.execution
  papers:
  '(("E. Debenedetti, I. Shumailov, T. Fan, J. Hayes, N. Carlini et al. (2025)"
     "Defeating Prompt Injections by Design (CaMeL): dual-LLM control/data-flow segregation and capability labels.")
    ("M. Costa et al. (NeurIPS 2025)"
     "FIDES: Securing AI Agents with Information-Flow Control (integrity and confidentiality lattice labels)."))
  quint-module: "agent_ifc_capability"
  quint-file: "AgentIfcCapability.qnt"
  domain-dir: "threat/execution/agent-ifc-capability"
  rules:
  '((control-data-segregation AGENT-IFC-CTRL quint)
    (capability-ifc-egress AGENT-IFC-EGRESS quint))
  dependencies:
  '((AGENT-IFC-CTRL source)
    (AGENT-IFC-CTRL profile)
    (AGENT-IFC-CTRL method)
    (AGENT-IFC-EGRESS source)
    (AGENT-IFC-EGRESS profile)
    (AGENT-IFC-EGRESS method))
  invariant: "Untrusted data-plane content never steers privileged tool control flow, and confidential data never exits to an untrusted sink without explicit declassification."
  limits: "Finite lattice-label IFC abstraction (CaMeL/FIDES); does not model semantic prompt classification, covert timing channels, or LLM token probabilities.")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; AI Agent Control/Data Flow Segregation & Capability-Based IFC threat model.
;;; Co-located Yuanxu unit: single source of truth alongside AgentIfcCapability.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export AgentIfcCapabilityModel
        PromptInjectionControlHijackCountermodel
        ConfidentialExfiltrationCountermodel)

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
  quint-imports:
  '(("authority_currentness" "../../zero-trust/authority-currentness/AuthorityCurrentness"))
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
  parameters: '()
  state:
  '((planIntegrityHigh "bool" "true")
    (dataTainted "bool" "false")
    (taintedPlanReady "bool" "false")
    (dataConfidential "bool" "false")
    (declassified "bool" "false")
    (toolInvoked "bool" "false")
    (toolControlledByTainted "bool" "false")
    (sinkObservedSecret "bool" "false")
    (sinkObservedDeclassified "bool" "false"))
  guards:
  '((control-data-segregation (. h planIntegrityHigh))
    (capability-ifc-egress (or (not (. h dataConfidential)) (. h declassified))))
  transitions:
  '((ingestUntrustedData
      (action ingestUntrustedData ()
        (set-h (dataTainted #t)
               (taintedPlanReady #t))))
    (readConfidentialSecret
      (action readConfidentialSecret ()
        (set-h (dataConfidential #t)
               (declassified #f))))
    (approveDeclassification
      (action approveDeclassification ()
        (if (and (. h planIntegrityHigh) (. h dataConfidential))
          (set-h (declassified #t))
          (keep-h))))
    (invokeTrustedTool
      (action invokeTrustedTool ()
        (if (and (. h planIntegrityHigh)
                 (guard capability-ifc-egress
                        (or (not (. h dataConfidential)) (. h declassified))))
          (set-h (toolInvoked #t)
                 (toolControlledByTainted (guard control-data-segregation
                                                 #f
                                                 (. h taintedPlanReady)))
                 (sinkObservedSecret (. h dataConfidential))
                 (sinkObservedDeclassified (. h declassified)))
          (keep-h))))
    (step
      (action step ()
        (any ingestUntrustedData readConfidentialSecret
             approveDeclassification invokeTrustedTool))))
  safety:
  '(or (not (. h toolInvoked))
       (and (not (. h toolControlledByTainted))
            (or (not (. h sinkObservedSecret))
                (. h sinkObservedDeclassified))))
  traces:
  '((checkSafe
      (action checkSafe ()
        (all (assert safety) (keep-h))))
    (checkUnsafe
      (action checkUnsafe ()
        (all (assert (not safety)) (keep-h))))
    (quarantinedUntrustedDataSafeTest
      (run quarantinedUntrustedDataSafeTest
        (then init ingestUntrustedData invokeTrustedTool
              (all (assert (. h toolInvoked))
                   (assert (not (. h toolControlledByTainted)))
                   (assert safety)
                   (keep-h)))))
    (confidentialBlockedWithoutDeclassTest
      (run confidentialBlockedWithoutDeclassTest
        (then init readConfidentialSecret invokeTrustedTool
              (all (assert (not (. h toolInvoked)))
                   (assert safety)
                   (keep-h)))))
    (declassifiedEgressAllowedTest
      (run declassifiedEgressAllowedTest
        (then init readConfidentialSecret approveDeclassification invokeTrustedTool
              (all (assert (. h toolInvoked))
                   (assert safety)
                   (keep-h)))))
    (promptInjectionHijackCountermodelTest
      (run promptInjectionHijackCountermodelTest
        (then init ingestUntrustedData invokeToolFromTaintedData checkUnsafe)))
    (confidentialExfiltrationCountermodelTest
      (run confidentialExfiltrationCountermodelTest
        (then init readConfidentialSecret invokeToolNoIfcEgress checkUnsafe))))
  countermodels:
  (list PromptInjectionControlHijackCountermodel
        ConfidentialExfiltrationCountermodel)
  limits: "Finite lattice-label IFC abstraction (CaMeL/FIDES); does not model semantic prompt classification, covert timing channels, or LLM token probabilities.")

(.def (PromptInjectionControlHijackCountermodel @ AgentIfcCapabilityModel)
  identity: 'threat.execution.agent-ifc-capability.prompt-injection-control-hijack
  dropped-guard: 'control-data-segregation
  step-action: "stepPromptInjectionHijack"
  derive-from-transition: 'invokeTrustedTool
  derive-action-name: 'invokeToolFromTaintedData
  expected-itf-predicate: "h.toolInvoked == true and h.toolControlledByTainted == true")

(.def (ConfidentialExfiltrationCountermodel @ AgentIfcCapabilityModel)
  identity: 'threat.execution.agent-ifc-capability.confidential-exfiltration
  dropped-guard: 'capability-ifc-egress
  step-action: "stepConfidentialExfiltration"
  derive-from-transition: 'invokeTrustedTool
  derive-action-name: 'invokeToolNoIfcEgress
  expected-itf-predicate: "h.toolInvoked == true and h.sinkObservedSecret == true and not(h.sinkObservedDeclassified)")

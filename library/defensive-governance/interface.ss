;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o)
        "types.ss"
        "objects.ss"
        "func.ss")
(export DefensiveGovernance)

(.def DefensiveGovernance
  identity: 'defensive-governance
  tags: '(engineering
          governance
          defense
          de.layer.governance
          defense.property.multi-valued
          defense.property.bounded-revalidation)
  core:
  (.o
    admissions: (.o)
    scope-contract: DefensiveGovernanceScopeType
    exports:
    (.o admit-guard: admit-guard-five-tuple
        audit-submission: audit-agent-defensive-submission
        audit-scheme-datums: audit-scheme-defensive-datums
        hallucination-controls: AgentDefensiveHallucinationControls
        revalidation-program: BoundedRevalidationProgram
        reason-revalidation: reason-bounded-revalidation
        transcript-audit-program: AgentTranscriptAuditProgram
        reason-transcript: reason-agent-transcript
        contracts: (.o witness-kind: GuardWitnessKindType
                       guard-admission: GuardAdmissionFiveTupleType
                       hallucination-class: AgentHallucinationClassType
                       hallucination-control: AgentHallucinationControlType
                       review-tier: ReviewTierType
                       scope: DefensiveGovernanceScopeType)))
  features: (.o))

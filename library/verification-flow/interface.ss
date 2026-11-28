;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o)
        "types.ss"
        "objects.ss"
        "config.ss"
        "func.ss"
        "ascent-rules.ss"
        "sysml-projection.ss"
        "sysml-compiler.ss"
        "rules.ss"
        "methods.ss"
        "syntax.ss")
(export VerificationFlow)

(.def VerificationFlow
  identity: 'verification-flow
  tags: '(engineering method verification funflow ascent sysml de.layer.method)
  core:
  (.o
    admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
    scope-contract: VerificationFlowScopeType
    exports:
    (.o config: Config
        config-type: VerificationFlowConfigType
        registry: DeVerificationTaskFamilyRegistry
        families: DeVerificationMethodFamilies
        prototypes: (.o base: RunnableTarget.
                        quint: QuintRunnableTarget.
                        lean-poo: LeanPooRunnableTarget.
                        source-contract: SourceContractRunnableTarget.
                        native-oracle: NativeOracleRunnableTarget.)
        governance-program: MultiMethodGovernanceProgram
        reason-governance: reason-multi-method-governance
        governance-sources: subject->governance-sources
        evidence-admission-program: VerificationEvidenceAdmissionProgram
        reason-evidence-admission: reason-verification-evidence-admission
        admission-sources: governance+evidence->admission-sources
        incremental-reuse-program: IncrementalReuseProgram
        evaluate-incremental-reuse: reason-incremental-reuse
        ai-governance-program: AiSecurityGovernanceProgram
        reason-ai-governance: reason-ai-security-governance
        evaluate-ai-patch: evaluate-ai-patch-admission
        evaluate-ai-changeset: evaluate-ai-changeset-admission
        ai-security-posture: project-ai-security-posture
        reuse-sources: build-incremental-reuse-sources
        reuse-plan: reuse-result->plan
        project-sysml-json: sysml-api-json->governance-facts
        compile-sysml-subject: compile-sysml-subject-spec
        compile-sysml-subjects: sysml-projected->compiled-subjects
        inputs: runnable-inputs
        flow: runnable-flow
        admit: runnable-admit
        unwrap-adapter-result: adapter-result->raw-receipt
        receipt-tree->evidence: receipt-tree->evidence-records
        dag-receipt: subject->dag-receipt
        dag-runtime-manifest: subject->dag-runtime-manifest
        contracts: (.o claim-kind: VerificationClaimKind
                       method-family-id: VerificationMethodFamilyId
                       method-family: VerificationMethodFamilyType
                       step: VerificationStepType
                       subject: VerificationSubjectType
                       input-envelope: VerificationInputEnvelopeType
                       raw-receipt: VerificationRawReceiptType
                       evidence-record: VerificationEvidenceRecordType
                       evidence-bundle: VerificationEvidenceBundleType
                       config: VerificationFlowConfigType
                       scope: VerificationFlowScopeType)))
  features: (.o))

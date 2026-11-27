;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure sealed contracts for the Multi-Method Fun-Flow Runnable control plane
;;; and ASCENT MR01-MR06 governance (10.154). Zero I/O, zero subprocesses.
(import
  :clan/poo/object
  (only-in :clan/poo/type define-type Any Object Function Type Type. Bool
           Record Symbol String List Exactly Or element?)
  (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
           FlowContract TaskContract)
  (only-in :deterministic-engineering/types LibraryNonemptyString))
(export
  VerificationClaimKind
  VerificationMethodFamilyId
  VerificationOutcome
  VerificationMethodFamilyType
  VerificationStepType
  VerificationSubjectType
  VerificationInputEnvelopeType
  VerificationRawReceiptType
  VerificationEvidenceRecordType
  VerificationEvidenceBundleType
  VerificationFlowConfigType
  VerificationFlowScopeType)

(define-type VerificationClaimKind
  (Or (Exactly 'bounded-interleaving)
      (Exactly 'fault-race)
      (Exactly 'guard-countermodel)
      (Exactly 'mbt-trace)
      (Exactly 'unbounded-invariant)
      (Exactly 'algebraic-bound)
      (Exactly 'contract-refinement)
      (Exactly 'proof-transport)
      (Exactly 'source-memory-ub)
      (Exactly 'drop-unwind-safety)
      (Exactly 'api-ban-lint)
      (Exactly 'empirical-mbt-replay)
      (Exactly 'os-sigkill-oracle)
      (Exactly 'zero-leak-assertion)))

(define-type VerificationMethodFamilyId
  (Or (Exactly 'de-quint)
      (Exactly 'de-lean-poo)
      (Exactly 'de-source-contract)
      (Exactly 'de-native-oracle)))

(define-type VerificationOutcome
  (Or (Exactly 'pass)
      (Exactly 'fail)
      (Exactly 'refused)
      (Exactly 'pending)))

(define-type
  (VerificationMethodFamilyType @
   (Record identity: [VerificationMethodFamilyId]
           descriptor: [Object]
           claim-kinds: [(List VerificationClaimKind)]))
  sealed: #t)

(define-type
  (VerificationStepType @
   (Record identity: [Symbol]
           family: [VerificationMethodFamilyType]
           obligation: [Symbol]
           claim-kind: [VerificationClaimKind]
           produces: [(List Symbol)]
           consumes: [(List Symbol)]
           requires-premises: [(List Symbol)]
           supports-premises: [(List Symbol)]
           stateful-quint?: [Bool]
           countermodels: [(List Symbol)]
           flow: [FlowContract]))
  sealed: #t)

(define-type
  (VerificationSubjectType @
   (Record identity: [Symbol]
           factors: [(List Symbol)]
           obligations: [(List Any)]
           os-containment: [(List Any)]
           steps: [(List VerificationStepType)]
           dag-edges: [(List Any)]
           correspondence-bridges: [(List Any)]
           dag-flow: [FlowContract]))
  sealed: #t)

(define-type
  (VerificationInputEnvelopeType @
   (Record subject: [Symbol]
           profile: [Symbol]
           input-digests: [(List Any)]))
  sealed: #t)

(define-type (VerificationExitCode @ Type.)
  identity: 'verification-flow/exit-code
  .element?: exact-integer?)

(define-type
  (VerificationRawReceiptType @
   (Record step: [Symbol]
           exit-code: [VerificationExitCode]
           artifacts: [(List Any)]
           summary: [LibraryNonemptyString]))
  sealed: #t)

(define-type
  (VerificationEvidenceRecordType @
   (Record step: [Symbol]
           obligation: [Symbol]
           method: [VerificationMethodFamilyId]
           claim-kind: [VerificationClaimKind]
           outcome: [VerificationOutcome]
           detail: [LibraryNonemptyString]))
  sealed: #t)

(define-type VerificationEvidenceBundleType
  (List VerificationEvidenceRecordType))

(define-type
  (VerificationFlowConfigType @
   (Record schema: [LibraryNonemptyString]
           require-mr-admission?: [Bool]
           require-countermodel-floor?: [Bool]))
  sealed: #t)

(define-type VerificationFlowScopeType
  (.cc
    (Record config: [VerificationFlowConfigType]
            config-type: [Type]
            registry: [Object]
            families: [Object]
            prototypes: [Object]
            governance-program: [Object]
            reason-governance: [(Function (list Any) (list Object))]
            governance-sources: [(Function (list Object) (list Any))]
            evidence-admission-program: [Object]
            reason-evidence-admission: [(Function (list Any) (list Object))]
            admission-sources: [(Function (list Any Any) (list Any))]
            incremental-reuse-program: [Object]
            evaluate-incremental-reuse: [(Function (list Any) (list Object))]
            ai-governance-program: [Object]
            reason-ai-governance: [(Function (list Any) (list Object))]
            reuse-sources: [Any]
            reuse-plan: [(Function (list Object) (list Object))]
            project-sysml-json: [(Function (list Any) (list Object))]
            compile-sysml-subject: [(Function (list Object) (list Object))]
            compile-sysml-subjects: [(Function (list Object) (list Any))]
            inputs: [Any]
            flow: [Any]
            admit: [Any]
            unwrap-adapter-result: [(Function (list Any) (list Object))]
            receipt-tree->evidence: [(Function (list Any) (list Any))]
            dag-receipt: [(Function (list Object) (list Any))]
            dag-runtime-manifest: [(Function (list Object LibraryNonemptyString) (list Any))]
            contracts: [Object])
    'identity 'verification-flow/scope))

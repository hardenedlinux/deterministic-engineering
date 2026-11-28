;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure Fun-Flow TaskFamily descriptors, registry extension, and Runnable
;;; prototypes for multi-method verification (10.154). Zero I/O.
(import
  :clan/poo/object
  (only-in :clan/poo/type validate)
  (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
           make-task-family-descriptor
           default-task-family-registry
           task-family-registry-extend)
  "types.ss")
(export
  DefaultVerificationFlowConfig
  DeQuintTaskFamily
  DeLeanPooTaskFamily
  DeSourceContractTaskFamily
  DeNativeOracleTaskFamily
  DeVerificationMethodFamilies
  DeVerificationTaskFamilyRegistry
  RunnableTarget.
  QuintRunnableTarget.
  LeanPooRunnableTarget.
  SourceContractRunnableTarget.
  NativeOracleRunnableTarget.)

(def DefaultVerificationFlowConfig
  (validate VerificationFlowConfigType
    (.o schema: "deterministic-engineering.verification-flow.v1"
        require-mr-admission?: #t
        require-countermodel-floor?: #t)))

(def (make-method-family id capability runtime-owner adapter-op allowed-claims)
  (validate VerificationMethodFamilyType
    (.o identity: id
        descriptor: (make-task-family-descriptor id capability 'adapter runtime-owner adapter-op)
        claim-kinds: allowed-claims)))

(def DeQuintTaskFamily
  (make-method-family
    'de-quint
    'quint-apalache-mbt
    'quint-modules-resolver
    'run-quint-plan
    '(bounded-interleaving fault-race guard-countermodel mbt-trace)))

(def DeLeanPooTaskFamily
  (make-method-family
    'de-lean-poo
    'lean4-lake-kernel
    'lake-lean
    'run-lean-lake-check
    '(unbounded-invariant algebraic-bound contract-refinement proof-transport)))

(def DeSourceContractTaskFamily
  (make-method-family
    'de-source-contract
    'cbmc-kani-clippy
    'native-toolchain
    'run-source-contract
    '(source-memory-ub drop-unwind-safety api-ban-lint)))

(def DeNativeOracleTaskFamily
  (make-method-family
    'de-native-oracle
    'mbt-fault-oracle
    'ops-contained-runner
    'run-contained-oracle
    '(empirical-mbt-replay os-sigkill-oracle zero-leak-assertion)))

(def DeVerificationMethodFamilies
  (.o quint: DeQuintTaskFamily
      lean-poo: DeLeanPooTaskFamily
      source-contract: DeSourceContractTaskFamily
      native-oracle: DeNativeOracleTaskFamily))

(def DeVerificationTaskFamilyRegistry
  (let* ((r1 (task-family-registry-extend default-task-family-registry (.get DeQuintTaskFamily descriptor)))
         (r2 (task-family-registry-extend r1 (.get DeLeanPooTaskFamily descriptor)))
         (r3 (task-family-registry-extend r2 (.get DeSourceContractTaskFamily descriptor))))
    (task-family-registry-extend r3 (.get DeNativeOracleTaskFamily descriptor))))

;; Pure POO prototypes for unified CLOS Runnable dispatch.
(.def RunnableTarget.
  identity: 'runnable.base
  obligation: 'unspecified
  claim-kind: 'bounded-interleaving
  inputs: '()
  produces: '()
  consumes: '()
  requires-premises: '()
  supports-premises: '())

(.def (QuintRunnableTarget. @ RunnableTarget.)
  family: DeQuintTaskFamily
  claim-kind: 'bounded-interleaving
  quint-file: ""
  quint-module: ""
  stateful-quint?: #t
  countermodels: '())

(.def (LeanPooRunnableTarget. @ RunnableTarget.)
  family: DeLeanPooTaskFamily
  claim-kind: 'unbounded-invariant
  lake-root: "packages/lean-models"
  lean-module: ""
  refines-core: ""
  require-zero-sorry?: #t)

(.def (SourceContractRunnableTarget. @ RunnableTarget.)
  family: DeSourceContractTaskFamily
  claim-kind: 'source-memory-ub
  subject-dir: ""
  tool: 'cbmc)

(.def (NativeOracleRunnableTarget. @ RunnableTarget.)
  family: DeNativeOracleTaskFamily
  claim-kind: 'os-sigkill-oracle
  crate-dir: ""
  fault-controls: '())

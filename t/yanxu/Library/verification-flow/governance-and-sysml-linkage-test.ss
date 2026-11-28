;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Loader-owned qualification tests for library/verification-flow (10.154):
;;; 1. Fun-Flow TaskFamilyRegistry + CLOS Runnable dispatch
;;; 2. Hygienic defrules authoring macros -> Fun-Flow DAG receipts & manifests
;;; 3. ASCENT MR01-MR06 positive admission & all 6 negative controls
;;; 4. Live OpenSysML (sysml -validate -strict & -convert api-json) -> ASCENT linkage
(import :std/test
        (only-in "../../../support/repo-paths.ss" resolve-repo-root)
        (only-in :tao3k/yuanxu/testing yuanxu-test-case)
        :std/encoding/json
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :clan/poo/type validate)
        (only-in :clan/poo/mop/clos/objects clos-failure?)
        (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
                 Fun PairValue
                 task-family-for-kind-in
                 flow-dag-receipt-kind
                 +flow-dag-runtime-manifest-schema+)
        :deterministic-engineering/library/verification-flow/types
        :deterministic-engineering/library/verification-flow/objects
        :deterministic-engineering/library/verification-flow/func
        :deterministic-engineering/library/verification-flow/syntax
        :deterministic-engineering/library/verification-flow/rules
        :deterministic-engineering/library/verification-flow/methods)
(export verification-flow-governance-and-sysml-linkage-test)

(def repo-root
  (resolve-repo-root))

;; Author pilot ProcessTreeReclamation steps via hygienic defrules expanding to Fun-Flow.
(defde-verification-step pt-quint-step quint-process-tree DeQuintTaskFamily
  obligation: quint-bounded-safety
  claim-kind: bounded-interleaving
  operation: run-quint-plan
  payload: '((model . "engineering.concurrency.process-tree-reclamation"))
  input: VerificationInputEnvelopeType
  output: VerificationEvidenceRecordType
  produces: (itf-trace)
  consumes: ()
  requires-premises: ()
  supports-premises: ()
  stateful-quint?: #t
  countermodels: (premature-sigkill http-ack-not-quiescence single-pid-kill-no-containment
                  pgid-spawn-toctou pid-reuse-double-kill)
  admit: (make-step-admitter 'quint-bounded-safety 'de-quint 'bounded-interleaving))

(defde-verification-step pt-oracle-step rust-sigkill-oracle DeNativeOracleTaskFamily
  obligation: os-sigkill-leak-oracle
  claim-kind: os-sigkill-oracle
  operation: run-contained-oracle
  payload: '((crate . "languages-engineering/rust/lifecycle/process-tree-guard"))
  input: VerificationEvidenceRecordType
  output: VerificationEvidenceRecordType
  produces: ()
  consumes: (itf-trace)
  requires-premises: ()
  supports-premises: (SpawnPreservesContainer)
  stateful-quint?: #f
  countermodels: ()
  admit: (make-step-admitter 'os-sigkill-leak-oracle 'de-native-oracle 'os-sigkill-oracle))

(defde-verification-step pt-lean-step lean-process-tree-closure DeLeanPooTaskFamily
  obligation: lean-unbounded-closure
  claim-kind: unbounded-invariant
  operation: run-lean-lake-check
  payload: '((module . "DeterministicEngineering.Engineering.ProcessTree"))
  input: VerificationInputEnvelopeType
  output: VerificationEvidenceRecordType
  produces: ()
  consumes: ()
  requires-premises: (SpawnPreservesContainer)
  supports-premises: ()
  stateful-quint?: #f
  countermodels: ()
  admit: (make-step-admitter 'lean-unbounded-closure 'de-lean-poo 'unbounded-invariant))

(defde-verification-dag pt-quint-then-oracle pt-quint-then-oracle
  then: (pt-quint-step pt-oracle-step))

(defde-verification-dag pt-full-dag process-tree-verification-dag
  fanout: (pt-quint-then-oracle pt-lean-step)
  converge-output: VerificationEvidenceRecordType
  (lambda (pair-out) (car pair-out)))

(defde-verification-subject pt-subject engineering.lifecycle.process-tree-reclamation
  factors: (owns-subprocess-tree)
  obligations: '((quint-bounded-safety bounded-interleaving)
                 (lean-unbounded-closure unbounded-invariant)
                 (os-sigkill-leak-oracle os-sigkill-oracle))
  os-containment: '((linux cgroup-v2-kill) (darwin pgid-and-pipe-eof))
  steps: (list pt-quint-step pt-oracle-step pt-lean-step)
  dag-edges: '((quint-process-tree rust-sigkill-oracle))
  correspondence-bridges: '()
  dag-flow: pt-full-dag)

(def (replace-source sources key new-rows)
  (alist-replace sources key new-rows))

(def verification-flow-governance-and-sysml-linkage-test
  (test-suite "verification-flow Fun-Flow Runnable, ASCENT MR01-MR06, and live SysML v2 linkage"
    (yuanxu-test-case "Fun-Flow TaskFamilyRegistry registers all 4 orthogonal families and CLOS rejects alien targets"
      (for-each
        (lambda (fname)
          (def desc (task-family-for-kind-in DeVerificationTaskFamilyRegistry fname))
          (check-equal? (.@ desc name) fname))
        '(de-quint de-lean-poo de-source-contract de-native-oracle))
      (def alien (.o identity: 'alien))
      (check-exception (runnable-inputs alien 'default) clos-failure?)
      (check-exception (runnable-flow alien 'default 'policy) clos-failure?)
      (def lean-target
        (.o (:: @ LeanPooRunnableTarget.)
            identity: 'lean-containment
            obligation: 'lean-unbounded-closure
            lean-module: "DeterministicEngineering.Engineering.ProcessTree"
            refines-core: "DeterministicEngineering.Core.Containment"))
      (def flow (runnable-flow lean-target 'lean.kernel-and-reuse 'default))
      (check (object? flow) => #t)
      (def ev (runnable-admit lean-target
                (.o step: 'lean-containment exit-code: 0 artifacts: '() summary: "lake build ok")))
      (check-equal? (.get ev outcome) 'pass)
      (check-equal? (.get ev method) 'de-lean-poo))

    (yuanxu-test-case "defrules-authored ProcessTreeReclamation passes MR01-MR06 and emits Fun-Flow DAG receipt & manifest"
      (def res (reason-multi-method-governance (subject->governance-sources pt-subject)))
      (check-equal? ((.ref res 'rows-of) 'mr_finding) '())
      (check-equal? ((.ref res 'rows-of) 'mr03_open_premise) '())
      (check-equal? ((.ref res 'rows-of) 'runnable_admitted)
                    '(("engineering.lifecycle.process-tree-reclamation")))
      (def receipt (subject->dag-receipt pt-subject))
      (check-equal? (cdr (assoc 'kind receipt)) flow-dag-receipt-kind)
      (def manifest (subject->dag-runtime-manifest pt-subject "req-pt-001"))
      (check-equal? (cdr (assoc 'schema manifest)) +flow-dag-runtime-manifest-schema+))

    (yuanxu-test-case "ASCENT MR01-MR06 negative controls catch every forbidden routing, duplication, premise, DAG, countermodel, and leak-containment defect"
      (def base (subject->governance-sources pt-subject))
      ;; MR01: Quint claiming unbounded-invariant
      (def r-mr01
        (reason-multi-method-governance
          (replace-source base 'flow_step
            (cons '("bad-quint" "engineering.lifecycle.process-tree-reclamation"
                    "lean-unbounded-closure" "de-quint" "unbounded-invariant")
                  (cdr (assq 'flow_step base))))))
      (check (pair? ((.ref r-mr01 'rows-of) 'mr01_finding)) => #t)
      (check-equal? ((.ref r-mr01 'rows-of) 'runnable_admitted) '())

      ;; MR02: duplicate method coverage without correspondence_bridge (and cleared when bridge declared)
      (def dup-sources
        (replace-source base 'flow_step
          (cons '("dup-step" "engineering.lifecycle.process-tree-reclamation"
                  "quint-bounded-safety" "de-lean-poo" "bounded-interleaving")
                (cdr (assq 'flow_step base)))))
      (def r-mr02 (reason-multi-method-governance dup-sources))
      (check (pair? ((.ref r-mr02 'rows-of) 'mr02_finding)) => #t)
      (def r-mr02-bridged
        (reason-multi-method-governance
          (replace-source dup-sources 'correspondence_bridge
            '(("quint-bounded-safety" "de-quint" "de-lean-poo")))))
      (check-equal? ((.ref r-mr02-bridged 'rows-of) 'mr02_finding) '())

      ;; MR03: missing premise supporter exposes open_premise visibly
      (def r-mr03 (reason-multi-method-governance (replace-source base 'step_supports_premise '())))
      (check-equal? ((.ref r-mr03 'rows-of) 'mr03_open_premise)
                    '(("engineering.lifecycle.process-tree-reclamation"
                       "lean-process-tree-closure"
                       "SpawnPreservesContainer")))

      ;; MR04: missing upstream DAG edge for consumed itf-trace
      (def r-mr04 (reason-multi-method-governance (replace-source base 'flow_dag_edge '())))
      (check-equal? ((.ref r-mr04 'rows-of) 'mr04_finding)
                    '(("engineering.lifecycle.process-tree-reclamation"
                       "rust-sigkill-oracle"
                       "itf-trace")))

      ;; MR05: stateful Quint step with zero countermodels
      (def r-mr05 (reason-multi-method-governance (replace-source base 'step_countermodel '())))
      (check (pair? ((.ref r-mr05 'rows-of) 'mr05_finding)) => #t)

      ;; MR06: owns-subprocess-tree without OS containment or without SIGKILL oracle
      (def r-mr06-os (reason-multi-method-governance (replace-source base 'declared_os_containment '())))
      (check (pair? ((.ref r-mr06-os 'rows-of) 'mr06_finding)) => #t)
      (def r-mr06-oracle
        (reason-multi-method-governance
          (replace-source base 'flow_step
            (filter (lambda (row) (not (equal? (list-ref row 4) "os-sigkill-oracle")))
                    (cdr (assq 'flow_step base))))))
      (check (pair? ((.ref r-mr06-oracle 'rows-of) 'mr06_finding)) => #t)

      ;; MR07: self-justification & 2-hop mutual premise cycle both caught and refused!
      (def r-mr07-self
        (reason-multi-method-governance
          (replace-source base 'step_supports_premise
            (cons '("lean-process-tree-closure" "SpawnPreservesContainer")
                  (cdr (assq 'step_supports_premise base))))))
      (check (pair? ((.ref r-mr07-self 'rows-of) 'mr07_finding)) => #t)
      (check-equal? ((.ref r-mr07-self 'rows-of) 'runnable_admitted) '())
      (def r-mr07-mutual
        (reason-multi-method-governance
          (replace-source
            (replace-source base 'step_requires_premise
              (cons '("rust-sigkill-oracle" "LeanClosurePremise")
                    (cdr (assq 'step_requires_premise base))))
            'step_supports_premise
            (cons '("lean-process-tree-closure" "LeanClosurePremise")
                  (cdr (assq 'step_supports_premise base))))))
      (check (pair? ((.ref r-mr07-mutual 'rows-of) 'mr07_finding)) => #t)
      (check-equal? ((.ref r-mr07-mutual 'rows-of) 'runnable_admitted) '())

      ;; MR08: 2-hop cycle in flow_dag_edge caught and refused!
      (def r-mr08
        (reason-multi-method-governance
          (replace-source base 'flow_dag_edge
            '(("quint-process-tree" "rust-sigkill-oracle")
              ("rust-sigkill-oracle" "quint-process-tree")))))
      (check (pair? ((.ref r-mr08 'rows-of) 'mr08_finding)) => #t)
      (check-equal? ((.ref r-mr08 'rows-of) 'runnable_admitted) '())

      ;; Gate refuses manifest emission when subject violates MR04 (drop dag-edges)
      (def bad-subject (.cc pt-subject 'dag-edges '()))
      (check-exception (subject->dag-runtime-manifest bad-subject "req-bad") error?))

    (yuanxu-test-case "live OpenSysML strict validation and api-json drive ASCENT MR01-MR06 directly with zero Scheme duplication"
      (def sysml-path
        (path-expand "docs/10-19-design/10-architecture/10.154-multi-method-funflow-runnable-and-leanpoo-architecture.sysml"
                     repo-root))
      (def strict-out (run-process (list "sysml" "-validate" "-strict" sysml-path)))
      (check (and (string-contains strict-out "no errors") #t) => #t)
      (def json-text (run-process (list "sysml" "-convert" "api-json" sysml-path)))
      (def parsed (call-with-input-string json-text (cut read-json <> object-as-hash: #t)))
      (def projected (sysml-api-json->governance-facts parsed))
      ;; Verify package families extracted straight from SysML v2 (no project-organization/objects.ss duplication).
      (def pkgs (.get projected packages))
      (check (and (assoc "leanModels" pkgs) #t) => #t)
      (check-equal? (cadr (assoc "leanModels" pkgs)) "lean-model-content")
      (check (and (assoc "quintModels" pkgs) #t) => #t)
      (check-equal? (cadr (assoc "quintModels" pkgs)) "quint-model-content")
      ;; Verify workflow DAG edges, requirements, and verifications extracted from SysML v2.
      (check (= (length (.get projected workflow-edges)) 8) => #t)
      (check (>= (length (.get projected requirements)) 17) => #t)
      (check (= (length (.get projected verifications)) 6) => #t)
      ;; Run ASCENT MR01-MR06 directly on SysML v2 projected facts (admits all declared subjects!).
      (def gov-res (reason-multi-method-governance (.get projected governance-sources)))
      (check-equal? ((.ref gov-res 'rows-of) 'mr_finding) '())
      (check-equal? ((.ref gov-res 'rows-of) 'mr03_open_premise) '())
      (def admitted-subjs ((.ref gov-res 'rows-of) 'runnable_admitted))
      (check (and (member '("engineering.lifecycle.process-tree-reclamation") admitted-subjs) #t) => #t)
      (check (and (member '("engineering.concurrency.backpressure-memory") admitted-subjs) #t) => #t)
      (check (and (member '("engineering.concurrency.lease-fencing-token") admitted-subjs) #t) => #t)
      (check (and (member '("engineering.defense.c-boundary-conservation") admitted-subjs) #t) => #t)
      (check (and (member '("engineering.governance.meta-governance-soundness") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.runtime-env-activation-and-context-confinement") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.graph-witness-and-harness-confinement") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.agent-ifc-capability") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.agent-tool-circuit-breaker") admitted-subjs) #t) => #t)
      (check (and (member '("threat.zero-trust.shared-context-governance") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.gitops-subprocess-confinement-and-arg-injection") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.control-plane-auth-and-governance-confinement") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.hook-policy-and-protocol-contract-confinement") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.plugin-grant-rollback-and-lease-confinement") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.governance-policy-and-latch-antirollback") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.subprocess-env-scrub-and-auth-timing") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.storage-boundary-integrity-and-sync-confinement") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.single-owner-graph-governance-confinement") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.telemetry-watchdog-and-deck-vm-confinement") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.process-signal-ledger-and-fanout-confinement") admitted-subjs) #t) => #t)
      (check (and (member '("threat.execution.wasm-sandbox-confinement") admitted-subjs) #t) => #t)
      (check-equal? (length (.get projected subject-specs)) 24))))

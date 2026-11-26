;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; M5 End-to-End Multi-Method Fun-Flow Ops Runner & ASCENT ER01-ER04 Gate Test.
;;; Verifies:
;;; 1. Pure ASCENT ER01-ER04 negative controls (missing evidence, failed step,
;;;    unverified premise, unauthorized method/claim-kind).
;;; 2. Live closed-loop execution on ProcessTreeReclamation:
;;;    OpenSysML strict+api-json -> ASCENT MR01-MR06 -> Fun-Flow DAG Manifest
;;;    -> Real 4-engine Fun-Flow Runner (Quint/Apalache/MBT + Lean 4/LeanPoo
;;;       + Rust Clippy + Rust OS SIGKILL Oracle) -> Fun-Flow Replay Validation
;;;    -> ASCENT ER01-ER04 Unified Admission.
(import :std/test
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :clan/poo/type validate)
        (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
                 replay-report-valid?
                 replay-report-reasons
                 +flow-dag-runtime-manifest-schema+)
        :deterministic-engineering/library/verification-flow/types
        :deterministic-engineering/library/verification-flow/rules
        :deterministic-engineering/library/verification-flow/methods
        "../../../support/verification-flow-runner.ss")
(export verification-flow-end-to-end-ops-runner-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def (mk-ev st obl meth ck out det)
  (validate VerificationEvidenceRecordType
    (.o step: st obligation: obl method: meth claim-kind: ck outcome: out detail: det)))

(def verification-flow-end-to-end-ops-runner-test
  (test-suite "M5 Fun-Flow real 4-engine Ops Runner and ASCENT ER01-ER04 admission"
    (test-case "ASCENT ER01-ER04 negative controls reject missing evidence, failed step, unverified premise, and method mismatch"
      (def subject (make-process-tree-verification-subject))
      (def gov (subject->governance-sources subject))
      (def all-pass
        (list
          (mk-ev 'quintTarget 'quint-bounded-safety 'de-quint 'bounded-interleaving 'pass "quint ok")
          (mk-ev 'leanPooTarget 'lean-unbounded-closure 'de-lean-poo 'unbounded-invariant 'pass "lean ok")
          (mk-ev 'sourceContractTarget 'source-api-ban-lint 'de-source-contract 'api-ban-lint 'pass "clippy ok")
          (mk-ev 'rustOracleTarget 'os-sigkill-leak-oracle 'de-native-oracle 'os-sigkill-oracle 'pass "oracle ok")))

      ;; Positive control: all 4 passing records admit the subject with zero ER findings.
      (def r-ok (reason-verification-evidence-admission (governance+evidence->admission-sources gov all-pass)))
      (check-equal? ((.ref r-ok 'rows-of) 'er_finding) '())
      (check-equal? ((.ref r-ok 'rows-of) 'premise_verified) '(("SpawnPreservesContainer")))
      (check-equal? ((.ref r-ok 'rows-of) 'verification_admitted)
                    '(("engineering.lifecycle.process-tree-reclamation")))

      ;; ER01: omit Lean evidence -> missing obligation evidence refuses admission.
      (def no-lean (filter (lambda (ev) (not (eq? (.get ev step) 'leanPooTarget))) all-pass))
      (def r-er01 (reason-verification-evidence-admission (governance+evidence->admission-sources gov no-lean)))
      (check (pair? ((.ref r-er01 'rows-of) 'er01_missing_evidence)) => #t)
      (check-equal? ((.ref r-er01 'rows-of) 'verification_admitted) '())

      ;; ER02 + ER03: Rust OS SIGKILL Oracle fails -> fails both ER02 AND ER03 (SpawnPreservesContainer unverified).
      (def failed-oracle
        (map (lambda (ev)
               (if (eq? (.get ev step) 'rustOracleTarget)
                 (mk-ev 'rustOracleTarget 'os-sigkill-leak-oracle 'de-native-oracle 'os-sigkill-oracle 'fail "orphan leaked")
                 ev))
             all-pass))
      (def r-er023 (reason-verification-evidence-admission (governance+evidence->admission-sources gov failed-oracle)))
      (check (pair? ((.ref r-er023 'rows-of) 'er02_failed_step)) => #t)
      (check-equal? ((.ref r-er023 'rows-of) 'er03_unverified_premise)
                    '(("engineering.lifecycle.process-tree-reclamation"
                       "leanPooTarget"
                       "SpawnPreservesContainer")))
      (check-equal? ((.ref r-er023 'rows-of) 'verification_admitted) '())

      ;; ER04: forged evidence where Quint claims unbounded-invariant -> rejected by ER04.
      (def bad-method
        (cons (mk-ev 'quintTarget 'lean-unbounded-closure 'de-quint 'unbounded-invariant 'pass "forged")
              all-pass))
      (def r-er04 (reason-verification-evidence-admission (governance+evidence->admission-sources gov bad-method)))
      (check (pair? ((.ref r-er04 'rows-of) 'er04_method_mismatch)) => #t)
      (check-equal? ((.ref r-er04 'rows-of) 'verification_admitted) '()))

    (test-case "live 4-engine Fun-Flow Ops Runner executes Quint, LeanPoo, Clippy, and Rust SIGKILL Oracle and passes ASCENT ER01-ER04"
      (def outcome (run-multi-method-verification-pipeline repo-root request-id: "req-pt-m5-test"))
      (check-equal? (cdr (assoc 'schema (.get outcome dag-manifest)))
                    +flow-dag-runtime-manifest-schema+)
      ;; Upstream Fun-Flow replay report must confirm zero topology/frontier drift.
      (check-equal? (replay-report-valid? (.get outcome replay-report)) #t)
      (check-equal? (replay-report-reasons (.get outcome replay-report)) '())
      ;; All 4 orthogonal verification engines must emit passing evidence records.
      (def evs (.get outcome evidence-records))
      (check-equal? (length evs) 4)
      (for-each (lambda (ev) (check-equal? (.get ev outcome) 'pass)) evs)
      ;; Live SysML v2 + Fun-Flow receipts joined in ASCENT ER01-ER04 admit the subject!
      (def er-res (.get outcome er-result))
      (check-equal? ((.ref er-res 'rows-of) 'er_finding) '())
      (check-equal? (length ((.ref er-res 'rows-of) 'obligation_passed)) 4)
      (check-equal? ((.ref er-res 'rows-of) 'premise_verified) '(("SpawnPreservesContainer")))
      (check-equal? ((.ref er-res 'rows-of) 'verification_admitted)
                    '(("engineering.lifecycle.process-tree-reclamation"))))))

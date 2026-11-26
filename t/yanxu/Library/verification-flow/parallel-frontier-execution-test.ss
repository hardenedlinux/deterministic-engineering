;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Parallel Conflict-Free Fun-Flow Frontier Execution Tests (10.154).
;;; Verifies:
;;; 1. Pure `partition-parallel-frontier-waves` computes maximal conflict-free waves
;;;    respecting both explicit `dag-edges` (e.g., `quintTarget -> rustOracleTarget`)
;;;    and implicit Cargo exclusivity (`sourceContractTarget -> rustOracleTarget`).
;;; 2. Live multi-core concurrent execution (`parallel?: #t`) executes independent
;;;    engines (`cbCbmcTarget || cbLeanPooTarget` and `lfQuintTarget || lfLeanPooTarget`)
;;;    simultaneously in Wave 1 while preserving 100% deterministic Fun-Flow Replay
;;;    (`replayValid = #t`) and ASCENT ER01-ER04 admission!
(import :std/test
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
                 replay-report-valid?)
        :deterministic-engineering/library/verification-flow/func
        :deterministic-engineering/library/verification-flow/rules
        :deterministic-engineering/library/verification-flow/sysml-compiler
        "../../../support/verification-flow-runner.ss")
(export verification-flow-parallel-frontier-execution-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def (set-eq? xs ys)
  (and (= (length xs) (length ys))
       (andmap (cut member <> ys) xs)
       (andmap (cut member <> xs) ys)))

(def verification-flow-parallel-frontier-execution-test
  (test-suite "Conflict-free parallel Fun-Flow frontier execution"
    (test-case "pure partition-parallel-frontier-waves maximizes concurrency while honoring DAG edges and Cargo exclusivity"
      (def pt (make-process-tree-verification-subject))
      (def pt-waves (partition-parallel-frontier-waves (.get pt steps) (.get pt dag-edges)))
      (check-equal? (length pt-waves) 2)
      ;; Wave 1 runs Quint, LeanPoo, and Clippy simultaneously; Wave 2 runs Rust OS Oracle strictly after!
      (check (set-eq? (car pt-waves) '("quintTarget" "leanPooTarget" "sourceContractTarget")) => #t)
      (check-equal? (cadr pt-waves) '("rustOracleTarget"))

      ;; Selective pending subset (Rust-only edit): Clippy strictly precedes Rust Oracle (no Cargo lock race).
      (def rust-waves
        (partition-parallel-frontier-waves
          (.get pt steps) (.get pt dag-edges) '("sourceContractTarget" "rustOracleTarget")))
      (check-equal? rust-waves '(("sourceContractTarget") ("rustOracleTarget")))

      ;; 2-engine subject (lease-fencing-token): single 2-way parallel wave!
      (def lf (make-lease-fencing-verification-subject))
      (def lf-waves (partition-parallel-frontier-waves (.get lf steps) (.get lf dag-edges)))
      (check-equal? (length lf-waves) 1)
      (check (set-eq? (car lf-waves) '("lfQuintTarget" "lfLeanPooTarget")) => #t))

    (test-case "live parallel Fun-Flow run executes CBMC || LeanPoo simultaneously with valid Fun-Flow replay and ER01-ER04 admission"
      (def outcome
        (run-multi-method-verification-pipeline repo-root
          subject-key: 'c-boundary-conservation
          parallel?: #t
          request-id: "req-par-cb-001"))
      (def metrics (.get outcome execution-metrics))
      (check-equal? (.get metrics parallel?) #t)
      (check-equal? (.get metrics wave-count) 1)
      (check (set-eq? (car (.get metrics waves)) '("cbCbmcTarget" "cbLeanPooTarget")) => #t)
      (check (>= (.get metrics sum-step-ms) (.get metrics wall-ms)) => #t)
      (check-equal? (replay-report-valid? (.get outcome replay-report)) #t)
      (def er (.get outcome er-result))
      (check-equal? ((.ref er 'rows-of) 'er_finding) '())
      (check-equal? ((.ref er 'rows-of) 'premise_verified) '(("NoCSourceOverflowOrPointerUB")))
      (check-equal? ((.ref er 'rows-of) 'verification_admitted)
                    '(("engineering.defense.c-boundary-conservation"))))

    (test-case "SysML correspondenceBridges projection clears MR02 duplicate-method refusal when explicitly bridged"
      ;; Construct minimal synthetic SysML api-json elements with two methods covering the same
      ;; (obligation, claim-kind) without vs with `correspondenceBridges = "shared-obl:de-quint:de-lean-poo"`.
      (def (make-synthetic-sysml with-bridge?)
        (def subj-id "p-subj")
        (def q-id "p-q")
        (def l-id "p-l")
        (def (mk-attr aid own name val)
          (list (hash ("@id" aid) ("@type" "AttributeUsage") ("owner" (hash ("@id" own))) ("declaredName" name))
                (hash ("@id" (string-append aid "-lit")) ("@type" "LiteralString") ("owner" (hash ("@id" aid))) ("value" val))))
        (apply append
          (list
            (list (hash ("@id" subj-id) ("@type" "PartUsage") ("declaredName" "bridgedSubject"))
                  (hash ("@id" q-id) ("@type" "PartUsage") ("owner" (hash ("@id" subj-id))) ("declaredName" "qStep"))
                  (hash ("@id" l-id) ("@type" "PartUsage") ("owner" (hash ("@id" subj-id))) ("declaredName" "lStep")))
            (mk-attr "a1" subj-id "subjectKey" "bridged-subject")
            (mk-attr "a2" subj-id "identity" "engineering.test.bridged")
            (mk-attr "a3" subj-id "factors" "bridged-demo")
            (if with-bridge?
              (mk-attr "a4" subj-id "correspondenceBridges" "quint-bounded-safety:de-quint:de-lean-poo")
              '())
            (mk-attr "a5" q-id "modelId" "engineering.test.bridged")
            (mk-attr "a6" q-id "countermodels" "cm-1")
            (mk-attr "a7" l-id "module" "DeterministicEngineering.Engineering.LeaseFencing"))))
      ;; Verify bridge attribute projects cleanly into governance-sources & compiled VerificationSubjectType.
      (def proj-no-br (sysml-api-json->governance-facts (make-synthetic-sysml #f)))
      (def proj-with-br (sysml-api-json->governance-facts (make-synthetic-sysml #t)))
      (check-equal? (alist-ref (.get proj-no-br governance-sources) 'correspondence_bridge '()) '())
      (check-equal? (alist-ref (.get proj-with-br governance-sources) 'correspondence_bridge '())
                    '(("quint-bounded-safety" "de-quint" "de-lean-poo")))
      (def compiled-br (compile-sysml-subject-by-key proj-with-br 'bridged-subject))
      (check-equal? (.get (.get compiled-br subject) correspondence-bridges)
                    '((quint-bounded-safety de-quint de-lean-poo)))
      ;; Inject duplicate claim-kind row and confirm MR02 rejects without bridge and admits with bridge!
      (def dup-step '("lStep-dup" "engineering.test.bridged" "quint-bounded-safety" "de-lean-poo" "bounded-interleaving"))
      (def src-no-br
        (alist-replace (.get proj-no-br governance-sources) 'flow_step
          (cons dup-step (alist-ref (.get proj-no-br governance-sources) 'flow_step '()))))
      (def src-with-br
        (alist-replace (.get proj-with-br governance-sources) 'flow_step
          (cons dup-step (alist-ref (.get proj-with-br governance-sources) 'flow_step '()))))
      (check (pair? ((.ref (reason-multi-method-governance src-no-br) 'rows-of) 'mr02_finding)) => #t)
      (check-equal? ((.ref (reason-multi-method-governance src-with-br) 'rows-of) 'mr02_finding) '()))))

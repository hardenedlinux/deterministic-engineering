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
                    '(("engineering.defense.c-boundary-conservation"))))))

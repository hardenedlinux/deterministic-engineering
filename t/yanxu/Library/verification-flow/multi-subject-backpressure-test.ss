;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Horizontal Reuse Verification: Second Engineering Subject (`backpressure-memory`).
;;; Proves that the EXACT SAME SysML v2 single source of truth, Fun-Flow Runnable
;;; control plane, LeanPoo package, ASCENT MR01-MR06/ER01-ER04/IR01-IR04 rules, and
;;; SHA-256 content-addressed cache scale horizontally to a second subject with
;;; zero framework duplication.
(import :std/test
        (only-in "../../../support/repo-paths.ss" resolve-repo-root)
        (only-in :tao3k/yuanxu/testing yuanxu-test-case)
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
                 replay-report-valid?
                 replay-report-reasons
                 +flow-dag-runtime-manifest-schema+)
        "../../../support/verification-flow-runner.ss")
(export verification-flow-multi-subject-backpressure-test)

(def repo-root
  (resolve-repo-root))

(def verification-flow-multi-subject-backpressure-test
  (test-suite "Horizontal multi-subject reuse on backpressure-memory (Quint + LeanPoo Core.Budget + Clippy + Tokio/Rayon Oracle)"
    (yuanxu-test-case "live 4-engine Fun-Flow run on backpressure-memory passes MR01-MR06 (both subjects), Replay, ER01-ER04, and cold->warm SHA-256 cache reuse"
      (def tmp-parent (path-expand ".data/test-runs" repo-root))
      (create-directory* tmp-parent)
      (def cache-dir (path-expand "m5-backpressure-cache-test" tmp-parent))
      (run-process (list "rm" "-rf" cache-dir))
      (create-directory* cache-dir)

      ;; Phase 1 — Cold run: executes all 4 real engines on backpressure-memory:
      ;;   bpQuintTarget (BackpressureOwners.qnt verify + 4 countermodels + 100% MBT + 10 ITF traces)
      ;;   bpLeanPooTarget (Core.Budget + Engineering.Backpressure 8 theorems, 0 sorryAx)
      ;;   bpSourceContractTarget (Rust Clippy --offline -D warnings)
      ;;   bpRustOracleTarget (Tokio+Rayon M01-M06 live=0, available=1 -> PayloadDropPrecedesPermitRelease)
      (let ((r1 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'backpressure-memory
                  cache-dir: cache-dir
                  request-id: "req-bp-1-cold")))
        ;; Single SysML v2 file simultaneously admits ALL engineering subjects!
        (def mr-admitted ((.ref (.get r1 mr-result) 'rows-of) 'runnable_admitted))
        (check (and (member '("engineering.lifecycle.process-tree-reclamation") mr-admitted) #t) => #t)
        (check (and (member '("engineering.concurrency.backpressure-memory") mr-admitted) #t) => #t)
        (check (and (member '("engineering.concurrency.lease-fencing-token") mr-admitted) #t) => #t)

        (check-equal? (cdr (assoc 'schema (.get r1 dag-manifest)))
                      +flow-dag-runtime-manifest-schema+)
        (check-equal? (replay-report-valid? (.get r1 replay-report)) #t)
        (check-equal? (replay-report-reasons (.get r1 replay-report)) '())
        (check-equal? (length (.get r1 evidence-records)) 4)
        (for-each (lambda (ev) (check-equal? (.get ev outcome) 'pass)) (.get r1 evidence-records))

        (def er1 (.get r1 er-result))
        (check-equal? ((.ref er1 'rows-of) 'er_finding) '())
        (check-equal? (length ((.ref er1 'rows-of) 'obligation_passed)) 4)
        (check-equal? ((.ref er1 'rows-of) 'premise_verified) '(("PayloadDropPrecedesPermitRelease")))
        (check-equal? ((.ref er1 'rows-of) 'verification_admitted)
                      '(("engineering.concurrency.backpressure-memory")))
        (check-equal? (length (.get (.get r1 cache-summary) executed)) 4)
        (check-equal? (.get (.get r1 cache-summary) reused) '()))
      (##gc)

      ;; Phase 2 — Warm run: 0 engines spawned, 4/4 reused from SHA-256 cache!
      (let ((r2 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'backpressure-memory
                  cache-dir: cache-dir
                  request-id: "req-bp-2-warm")))
        (check-equal? (replay-report-valid? (.get r2 replay-report)) #t)
        (check-equal? ((.ref (.get r2 er-result) 'rows-of) 'er_finding) '())
        (check-equal? ((.ref (.get r2 er-result) 'rows-of) 'verification_admitted)
                      '(("engineering.concurrency.backpressure-memory")))
        (check-equal? (.get (.get r2 cache-summary) executed) '())
        (check-equal? (length (.get (.get r2 cache-summary) reused)) 4)))))

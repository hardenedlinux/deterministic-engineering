;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Content-Addressed Incremental Cache Reuse & Selective Invalidation Tests (IR01-IR04).
;;; Verifies:
;;; 1. Pure ASCENT IR01-IR04 rules across all 6 invalidation/reuse scenarios
;;;    (cold, warm, Rust-only edit, Quint-only edit with transitive DAG IR03,
;;;     M3-mutable-root policy IR04, and tampered/failed/incomplete cache).
;;; 2. Live 4-phase Fun-Flow run with real SHA-256 cache store:
;;;    Cold (4 executed, 0 reused) -> Warm (0 executed, 4 reused)
;;;    -> Rust-only drift (2 executed: Clippy + SIGKILL Oracle; 2 reused: Quint + LeanPoo)
;;;    -> require-fresh-m3 policy (1 executed: SIGKILL Oracle only; 3 reused: M1 proofs).
(import :std/test
        :std/encoding/json
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
                 replay-report-valid?)
        :deterministic-engineering/library/verification-flow/rules
        "../../../support/verification-flow-runner.ss")
(export verification-flow-incremental-cache-reuse-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def (set-eq? xs ys)
  (and (= (length xs) (length ys))
       (andmap (cut member <> ys) xs)
       (andmap (cut member <> xs) ys)))

(def (tamper-cache-input-digest! cache-file step-names target-rel new-digest)
  (def doc (call-with-input-file cache-file (cut read-json <> object-as-hash: #t)))
  (def entries (hash-get doc "entries"))
  (for-each
    (lambda (st)
      (let* ((rec (hash-get entries st))
             (digs (and (hash-table? rec) (hash-get rec "inputDigests"))))
        (when (and (hash-table? digs) (hash-key? digs target-rel))
          (hash-put! digs target-rel new-digest))))
    step-names)
  (call-with-output-file cache-file
    (lambda (port)
      (write-json port doc)
      (newline port))))

(def verification-flow-incremental-cache-reuse-test
  (test-suite "ASCENT IR01-IR04 incremental cache reuse and live selective invalidation"
    (test-case "pure ASCENT IR01-IR04 accurately partitions pending vs reusable frontier across cold, warm, Rust-edit, Quint-edit (transitive IR03), M3-policy (IR04), and tamper"
      (def gov (subject->governance-sources (make-process-tree-verification-subject)))
      (def base-inputs
        '(("quintTarget" "ProcessTreeReclamation.qnt" "sha-q1")
          ("leanPooTarget" "ProcessTree.lean" "sha-l1")
          ("sourceContractTarget" "src/lib.rs" "sha-r1")
          ("rustOracleTarget" "src/lib.rs" "sha-r1")
          ("rustOracleTarget" "tests/sigkill_leak_oracle.rs" "sha-t1")))
      (def all-cached
        '(("quintTarget" "quint-bounded-safety" "de-quint" "bounded-interleaving" "pass" "ok")
          ("leanPooTarget" "lean-unbounded-closure" "de-lean-poo" "unbounded-invariant" "pass" "ok")
          ("sourceContractTarget" "source-api-ban-lint" "de-source-contract" "api-ban-lint" "pass" "ok")
          ("rustOracleTarget" "os-sigkill-leak-oracle" "de-native-oracle" "os-sigkill-oracle" "pass" "ok")))

      ;; 1. Cold cache: all 4 pending, 0 reusable (IR01).
      (def p-cold
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources gov default-process-tree-step-mutability '() base-inputs '() '()))))
      (check (set-eq? (.get p-cold pending) '("quintTarget" "leanPooTarget" "sourceContractTarget" "rustOracleTarget")) => #t)
      (check-equal? (.get p-cold reusable) '())

      ;; 2. Warm exact match: 0 pending, all 4 reusable.
      (def p-warm
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources gov default-process-tree-step-mutability '() base-inputs all-cached base-inputs))))
      (check-equal? (.get p-warm pending) '())
      (check (set-eq? (.get p-warm reusable) '("quintTarget" "leanPooTarget" "sourceContractTarget" "rustOracleTarget")) => #t)

      ;; 3. Rust src/lib.rs edit ONLY: Clippy + Oracle pending (IR02), Quint + LeanPoo reusable!
      (def rust-edited-inputs
        '(("quintTarget" "ProcessTreeReclamation.qnt" "sha-q1")
          ("leanPooTarget" "ProcessTree.lean" "sha-l1")
          ("sourceContractTarget" "src/lib.rs" "sha-r2-edited")
          ("rustOracleTarget" "src/lib.rs" "sha-r2-edited")
          ("rustOracleTarget" "tests/sigkill_leak_oracle.rs" "sha-t1")))
      (def p-rust
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources gov default-process-tree-step-mutability '() rust-edited-inputs all-cached base-inputs))))
      (check (set-eq? (.get p-rust pending) '("sourceContractTarget" "rustOracleTarget")) => #t)
      (check (set-eq? (.get p-rust reusable) '("quintTarget" "leanPooTarget")) => #t)

      ;; 4. Quint model edit ONLY: quintTarget pending (IR02) AND rustOracleTarget transitively pending (IR03 via itf-trace DAG edge)!
      ;;    leanPooTarget and sourceContractTarget stay reusable!
      (def quint-edited-inputs
        '(("quintTarget" "ProcessTreeReclamation.qnt" "sha-q2-edited")
          ("leanPooTarget" "ProcessTree.lean" "sha-l1")
          ("sourceContractTarget" "src/lib.rs" "sha-r1")
          ("rustOracleTarget" "src/lib.rs" "sha-r1")
          ("rustOracleTarget" "tests/sigkill_leak_oracle.rs" "sha-t1")))
      (def p-quint
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources gov default-process-tree-step-mutability '() quint-edited-inputs all-cached base-inputs))))
      (check (set-eq? (.get p-quint pending) '("quintTarget" "rustOracleTarget")) => #t)
      (check (set-eq? (.get p-quint reusable) '("leanPooTarget" "sourceContractTarget")) => #t)
      (check (and (member '("rustOracleTarget" "IR03-upstream-dag-invalidated") (.get p-quint invalidations)) #t) => #t)

      ;; 5. IR04: require-fresh-m3 policy refreshes ONLY M3-mutable-root (rustOracleTarget), reusing all 3 M1 proofs!
      (def p-m3
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources gov default-process-tree-step-mutability '("require-fresh-m3") base-inputs all-cached base-inputs))))
      (check-equal? (.get p-m3 pending) '("rustOracleTarget"))
      (check (set-eq? (.get p-m3 reusable) '("quintTarget" "leanPooTarget" "sourceContractTarget")) => #t)
      (check (and (member '("rustOracleTarget" "IR04-m3-mutable-root-refresh") (.get p-m3 invalidations)) #t) => #t)

      ;; 6. Tampered cache controls: failed witness (IR01), missing input key (IR02), extra stale key (IR02) all force re-run!
      (def failed-lean-cache
        (map (lambda (r) (if (equal? (car r) "leanPooTarget")
                           '("leanPooTarget" "lean-unbounded-closure" "de-lean-poo" "unbounded-invariant" "fail" "sorry")
                           r))
             all-cached))
      (def p-fail
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources gov default-process-tree-step-mutability '() base-inputs failed-lean-cache base-inputs))))
      (check-equal? (.get p-fail pending) '("leanPooTarget"))

      (def missing-key-cache (filter (lambda (r) (not (equal? (cadr r) "tests/sigkill_leak_oracle.rs"))) base-inputs))
      (def p-missing
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources gov default-process-tree-step-mutability '() base-inputs all-cached missing-key-cache))))
      (check-equal? (.get p-missing pending) '("rustOracleTarget"))

      (def extra-key-cache (cons '("leanPooTarget" "ExtraGhostFile.lean" "sha-ghost") base-inputs))
      (def p-extra
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources gov default-process-tree-step-mutability '() base-inputs all-cached extra-key-cache))))
      (check-equal? (.get p-extra pending) '("leanPooTarget")))

    (test-case "live 4-phase Fun-Flow run proves cold (4/0), warm (0/4 cache hits), selective Rust invalidation (2/2), and fresh-M3 policy (1/3) with full replay & ER01-ER04 admission"
      (def tmp-parent (path-expand ".data/test-runs" repo-root))
      (create-directory* tmp-parent)
      (def cache-dir (path-expand "m5-incremental-cache-test" tmp-parent))
      (run-process (list "rm" "-rf" cache-dir))
      (create-directory* cache-dir)
      (def cache-file (path-expand "verification-cache.v1.json" cache-dir))

      ;; Phase 1 — Cold run: executes all 4 real engines, persists SHA-256 cache.
      (let ((r1 (run-multi-method-verification-pipeline repo-root cache-dir: cache-dir request-id: "req-inc-1-cold")))
        (check-equal? (replay-report-valid? (.get r1 replay-report)) #t)
        (check-equal? ((.ref (.get r1 er-result) 'rows-of) 'er_finding) '())
        (check-equal? (length (.get (.get r1 cache-summary) executed)) 4)
        (check-equal? (.get (.get r1 cache-summary) reused) '())
        (check-equal? (file-exists? cache-file) #t))
      (##gc)

      ;; Phase 2 — Warm identical run: 0 engines spawned, 4/4 reused from SHA-256 cache!
      (let ((r2 (run-multi-method-verification-pipeline repo-root cache-dir: cache-dir request-id: "req-inc-2-warm")))
        (check-equal? (replay-report-valid? (.get r2 replay-report)) #t)
        (check-equal? ((.ref (.get r2 er-result) 'rows-of) 'er_finding) '())
        (check-equal? ((.ref (.get r2 er-result) 'rows-of) 'verification_admitted)
                      '(("engineering.lifecycle.process-tree-reclamation")))
        (check-equal? (.get (.get r2 cache-summary) executed) '())
        (check-equal? (length (.get (.get r2 cache-summary) reused)) 4))
      (##gc)

      ;; Phase 3 — Selective Rust-only invalidation: drift ONLY src/lib.rs digest in cache ->
      ;;           re-executes ONLY sourceContractTarget (Clippy) + rustOracleTarget (OS SIGKILL Oracle),
      ;;           while 100% reusing quintTarget (Apalache/MBT) + leanPooTarget (Lake/LeanPoo)!
      (tamper-cache-input-digest! cache-file
        '("sourceContractTarget" "rustOracleTarget")
        "languages-engineering/rust/lifecycle/process-tree-guard/src/lib.rs"
        "0000000000000000000000000000000000000000000000000000000000000000")
      (let ((r3 (run-multi-method-verification-pipeline repo-root cache-dir: cache-dir request-id: "req-inc-3-rust-only")))
        (check-equal? (replay-report-valid? (.get r3 replay-report)) #t)
        (check-equal? ((.ref (.get r3 er-result) 'rows-of) 'er_finding) '())
        (check-equal? ((.ref (.get r3 er-result) 'rows-of) 'premise_verified) '(("SpawnPreservesContainer")))
        (check (set-eq? (.get (.get r3 cache-summary) executed) '("sourceContractTarget" "rustOracleTarget")) => #t)
        (check (set-eq? (.get (.get r3 cache-summary) reused) '("quintTarget" "leanPooTarget")) => #t))
      (##gc)

      ;; Phase 4 — IR04 fresh-M3 policy: re-runs ONLY M3-mutable-root (rustOracleTarget),
      ;;           reusing all 3 M1-immutable-proof receipts (Quint + LeanPoo + Clippy)!
      (let ((r4 (run-multi-method-verification-pipeline repo-root
                  cache-dir: cache-dir
                  policy-flags: '("require-fresh-m3")
                  request-id: "req-inc-4-fresh-m3")))
        (check-equal? (replay-report-valid? (.get r4 replay-report)) #t)
        (check-equal? ((.ref (.get r4 er-result) 'rows-of) 'er_finding) '())
        (check-equal? (.get (.get r4 cache-summary) executed) '("rustOracleTarget"))
        (check (set-eq? (.get (.get r4 cache-summary) reused) '("quintTarget" "leanPooTarget" "sourceContractTarget")) => #t)))))

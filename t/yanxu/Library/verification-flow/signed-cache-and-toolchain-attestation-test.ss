;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Toolchain Fingerprint (IR05) & Ed25519 Signed Verifiable Proof Cache / Report Attestation (IR06).
;;; Verifies:
;;; 1. Pure ASCENT IR05 (toolchain/OS drift) & IR06 (cryptographic attestation) rules,
;;;    including transitive IR03 propagation when an upstream Quint step drifts or fails attestation.
;;; 2. Live OpenSSL Ed25519 signing & offline verification of both `verification-cache.v2`
;;;    and `report.json` across 4 real Fun-Flow phases on `lease-fencing-token`:
;;;    Cold (2 executed, signed) -> Warm (0 executed, 2 verified hits)
;;;    -> Tampered cache detail attack (IR06 rejects ONLY tampered lfLeanPooTarget, reuses lfQuintTarget)
;;;    -> Toolchain upgrade drift attack (IR05 rejects ONLY drifted lfLeanPooTarget, reuses lfQuintTarget)
;;;    + Offline report tamper detection (`verify-verification-report-attestation` returns #f on 1-byte edit).
(import :std/test
        :std/encoding/json
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
                 replay-report-valid?)
        :deterministic-engineering/library/verification-flow/rules
        "../../../support/verification-flow-runner.ss")
(export verification-flow-signed-cache-and-toolchain-attestation-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def (set-eq? xs ys)
  (and (= (length xs) (length ys))
       (andmap (cut member <> ys) xs)
       (andmap (cut member <> xs) ys)))

(def (patch-cache-entry-field! cache-file step-name field new-val)
  (def doc (call-with-input-file cache-file (cut read-json <> object-as-hash: #t)))
  (def entries (hash-get doc "entries"))
  (def rec (hash-get entries step-name))
  (hash-put! rec field new-val)
  (call-with-output-file cache-file
    (lambda (port)
      (write-json port doc)
      (newline port))))

(def verification-flow-signed-cache-and-toolchain-attestation-test
  (test-suite "Toolchain fingerprint (IR05) and Ed25519 signed verifiable cache & report attestation (IR06)"
    (test-case "pure ASCENT IR05 + IR06 catch toolchain drift, unsigned/tampered witnesses, and propagate transitively via IR03"
      (def gov (subject->governance-sources (make-process-tree-verification-subject)))
      (def base-inputs
        '(("quintTarget" "ProcessTreeReclamation.qnt" "sha-q1")
          ("leanPooTarget" "ProcessTree.lean" "sha-l1")
          ("sourceContractTarget" "src/lib.rs" "sha-r1")
          ("rustOracleTarget" "src/lib.rs" "sha-r1")))
      (def all-cached
        '(("quintTarget" "quint-bounded-safety" "de-quint" "bounded-interleaving" "pass" "ok")
          ("leanPooTarget" "lean-unbounded-closure" "de-lean-poo" "unbounded-invariant" "pass" "ok")
          ("sourceContractTarget" "source-api-ban-lint" "de-source-contract" "api-ban-lint" "pass" "ok")
          ("rustOracleTarget" "os-sigkill-leak-oracle" "de-native-oracle" "os-sigkill-oracle" "pass" "ok")))
      (def base-tc
        '(("quintTarget" "quint=0.33.0|os=Darwin/arm64")
          ("leanPooTarget" "lean=4.34.0|os=Darwin/arm64")
          ("sourceContractTarget" "rustc=1.95.0|os=Darwin/arm64")
          ("rustOracleTarget" "rustc=1.95.0|os=Darwin/arm64")))
      (def all-attested
        '("quintTarget" "leanPooTarget" "sourceContractTarget" "rustOracleTarget"))

      ;; 1. Warm signed + matching toolchains: 0 pending, 4 reusable.
      (def p-ok
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources
              gov default-process-tree-step-mutability '("require-signed-cache")
              base-inputs all-cached base-inputs base-tc base-tc all-attested))))
      (check-equal? (.get p-ok pending) '())
      (check (set-eq? (.get p-ok reusable) all-attested) => #t)

      ;; 2. IR05: Lean compiler upgrade invalidates ONLY leanPooTarget; other 3 stay reusable!
      (def lean-upgraded-tc
        '(("quintTarget" "quint=0.33.0|os=Darwin/arm64")
          ("leanPooTarget" "lean=4.35.0|os=Darwin/arm64")
          ("sourceContractTarget" "rustc=1.95.0|os=Darwin/arm64")
          ("rustOracleTarget" "rustc=1.95.0|os=Darwin/arm64")))
      (def p-lean-drift
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources
              gov default-process-tree-step-mutability '("require-signed-cache")
              base-inputs all-cached base-inputs lean-upgraded-tc base-tc all-attested))))
      (check-equal? (.get p-lean-drift pending) '("leanPooTarget"))
      (check (and (member '("leanPooTarget" "IR05-toolchain-drift") (.get p-lean-drift invalidations)) #t) => #t)
      (check (set-eq? (.get p-lean-drift reusable) '("quintTarget" "sourceContractTarget" "rustOracleTarget")) => #t)

      ;; 3. IR05 + IR03: Quint version upgrade invalidates quintTarget AND transitively rustOracleTarget!
      (def quint-upgraded-tc
        '(("quintTarget" "quint=0.34.0|os=Darwin/arm64")
          ("leanPooTarget" "lean=4.34.0|os=Darwin/arm64")
          ("sourceContractTarget" "rustc=1.95.0|os=Darwin/arm64")
          ("rustOracleTarget" "rustc=1.95.0|os=Darwin/arm64")))
      (def p-quint-drift
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources
              gov default-process-tree-step-mutability '("require-signed-cache")
              base-inputs all-cached base-inputs quint-upgraded-tc base-tc all-attested))))
      (check (set-eq? (.get p-quint-drift pending) '("quintTarget" "rustOracleTarget")) => #t)
      (check (and (member '("quintTarget" "IR05-toolchain-drift") (.get p-quint-drift invalidations)) #t) => #t)
      (check (and (member '("rustOracleTarget" "IR03-upstream-dag-invalidated") (.get p-quint-drift invalidations)) #t) => #t)
      (check (set-eq? (.get p-quint-drift reusable) '("leanPooTarget" "sourceContractTarget")) => #t)

      ;; 4. IR06: Forged/unattested quintTarget invalidates quintTarget AND transitively rustOracleTarget!
      (def p-forged
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources
              gov default-process-tree-step-mutability '("require-signed-cache")
              base-inputs all-cached base-inputs base-tc base-tc
              '("leanPooTarget" "sourceContractTarget" "rustOracleTarget")))))
      (check (set-eq? (.get p-forged pending) '("quintTarget" "rustOracleTarget")) => #t)
      (check (and (member '("quintTarget" "IR06-attestation-invalid") (.get p-forged invalidations)) #t) => #t)
      (check (and (member '("rustOracleTarget" "IR03-upstream-dag-invalidated") (.get p-forged invalidations)) #t) => #t)

      ;; 5. IR07: Under `strict-premise-recheck`, Rust src/lib.rs edit invalidates rustOracleTarget (IR02)
      ;;          AND cascades via SpawnPreservesContainer premise edge to invalidate leanPooTarget (IR07),
      ;;          while still reusing quintTarget!
      (def rust-edited-inputs
        '(("quintTarget" "ProcessTreeReclamation.qnt" "sha-q1")
          ("leanPooTarget" "ProcessTree.lean" "sha-l1")
          ("sourceContractTarget" "src/lib.rs" "sha-r2-edited")
          ("rustOracleTarget" "src/lib.rs" "sha-r2-edited")))
      (def p-ir07-rust
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources
              gov default-process-tree-step-mutability '("require-signed-cache" "strict-premise-recheck")
              rust-edited-inputs all-cached base-inputs base-tc base-tc all-attested))))
      (check (set-eq? (.get p-ir07-rust pending) '("sourceContractTarget" "rustOracleTarget" "leanPooTarget")) => #t)
      (check-equal? (.get p-ir07-rust reusable) '("quintTarget"))
      (check (and (member '("leanPooTarget" "IR07-premise-supporter-invalidated")
                          (.get p-ir07-rust invalidations)) #t) => #t)

      ;; 6. IR07 2-hop cross-graph cascade: Quint edit -> quintTarget (IR02) -> rustOracleTarget (IR03) -> leanPooTarget (IR07),
      ;;    while sourceContractTarget stays reusable!
      (def quint-edited-inputs
        '(("quintTarget" "ProcessTreeReclamation.qnt" "sha-q2-edited")
          ("leanPooTarget" "ProcessTree.lean" "sha-l1")
          ("sourceContractTarget" "src/lib.rs" "sha-r1")
          ("rustOracleTarget" "src/lib.rs" "sha-r1")))
      (def p-ir07-cascade
        (reuse-result->plan
          (reason-incremental-reuse
            (build-incremental-reuse-sources
              gov default-process-tree-step-mutability '("require-signed-cache" "strict-premise-recheck")
              quint-edited-inputs all-cached base-inputs base-tc base-tc all-attested))))
      (check (set-eq? (.get p-ir07-cascade pending) '("quintTarget" "rustOracleTarget" "leanPooTarget")) => #t)
      (check-equal? (.get p-ir07-cascade reusable) '("sourceContractTarget"))
      (check (and (member '("rustOracleTarget" "IR03-upstream-dag-invalidated")
                          (.get p-ir07-cascade invalidations)) #t) => #t)
      (check (and (member '("leanPooTarget" "IR07-premise-supporter-invalidated")
                          (.get p-ir07-cascade invalidations)) #t) => #t))

    (test-case "live Ed25519 signed cache & report reject forged detail (IR06), toolchain drift (IR05), and tampered report.json"
      (def tmp-parent (path-expand ".data/test-runs" repo-root))
      (create-directory* tmp-parent)
      (def cache-dir (path-expand "m5-signed-cache-test" tmp-parent))
      (def out-dir (path-expand "m5-signed-report-test" tmp-parent))
      (run-process (list "rm" "-rf" cache-dir out-dir))
      (create-directory* cache-dir)
      (def cache-file (path-expand "verification-cache.v1.json" cache-dir))

      ;; Phase 1 — Cold run with Ed25519 cache + signed report.json.
      (let ((r1 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'lease-fencing-token
                  output-dir: out-dir
                  cache-dir: cache-dir
                  request-id: "req-att-1-cold")))
        (def rpath (.get r1 report-path))
        (check-equal? (replay-report-valid? (.get r1 replay-report)) #t)
        (check-equal? ((.ref (.get r1 er-result) 'rows-of) 'er_finding) '())
        (check-equal? (length (.get (.get r1 cache-summary) executed)) 2)
        (check-equal? (.get (.get r1 cache-summary) reused) '())
        ;; Genuine report.json verifies cryptographically with Ed25519!
        (check-equal? (verify-verification-report-attestation rpath) #t)
        ;; Tampering 1 field in a copy of report.json causes offline Ed25519 verification to FAIL!
        (let* ((tampered-path (path-expand "tampered-report.json" out-dir))
               (doc (call-with-input-file rpath (cut read-json <> object-as-hash: #t))))
          (hash-put! doc "requestId" "req-att-1-forged")
          (call-with-output-file tampered-path
            (lambda (port) (write-json port doc) (newline port)))
          (check-equal? (verify-verification-report-attestation tampered-path) #f)))
      (##gc)

      ;; Phase 2 — Warm run: 0 engines spawned, 2/2 Ed25519-verified cache hits!
      (let ((r2 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'lease-fencing-token
                  cache-dir: cache-dir
                  request-id: "req-att-2-warm")))
        (check-equal? (replay-report-valid? (.get r2 replay-report)) #t)
        (check-equal? ((.ref (.get r2 er-result) 'rows-of) 'er_finding) '())
        (check-equal? (.get (.get r2 cache-summary) executed) '())
        (check-equal? (length (.get (.get r2 cache-summary) reused)) 2)
        (check-equal? (length (.get (.get r2 cache-summary) attested-hits)) 2))
      (##gc)

      ;; Phase 3 — Tamper attack on cached `detail` WITHOUT changing `inputDigests` or `toolchainFingerprint`!
      ;;           Ed25519 verification fails -> IR06-attestation-invalid re-executes ONLY lfLeanPooTarget!
      (patch-cache-entry-field! cache-file "lfLeanPooTarget" "detail" "FORGED-WITHOUT-RUNNING-LAKE")
      (let ((r3 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'lease-fencing-token
                  cache-dir: cache-dir
                  request-id: "req-att-3-tamper")))
        (check-equal? (replay-report-valid? (.get r3 replay-report)) #t)
        (check-equal? ((.ref (.get r3 er-result) 'rows-of) 'er_finding) '())
        (check-equal? (.get (.get r3 cache-summary) executed) '("lfLeanPooTarget"))
        (check-equal? (.get (.get r3 cache-summary) reused) '("lfQuintTarget"))
        (check (and (member '("lfLeanPooTarget" "IR06-attestation-invalid")
                            (.get (.get r3 cache-summary) invalidations)) #t) => #t))
      (##gc)

      ;; Phase 4 — Simulated Lean toolchain upgrade (`IR05-toolchain-drift`):
      ;;           Re-executes ONLY lfLeanPooTarget while reusing lfQuintTarget!
      (patch-cache-entry-field! cache-file "lfLeanPooTarget" "toolchainFingerprint" "lean=4.99.0-upgraded|os=Darwin/arm64")
      (let ((r4 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'lease-fencing-token
                  cache-dir: cache-dir
                  request-id: "req-att-4-toolchain-drift")))
        (check-equal? (replay-report-valid? (.get r4 replay-report)) #t)
        (check-equal? ((.ref (.get r4 er-result) 'rows-of) 'er_finding) '())
        (check-equal? (.get (.get r4 cache-summary) executed) '("lfLeanPooTarget"))
        (check-equal? (.get (.get r4 cache-summary) reused) '("lfQuintTarget"))
        (check (and (member '("lfLeanPooTarget" "IR05-toolchain-drift")
                            (.get (.get r4 cache-summary) invalidations)) #t) => #t)))

    (test-case "live run-impacted-multi-method-fleet runs ONLY affected c-boundary-conservation for C file change and skips unrelated subjects"
      (def tmp-parent (path-expand ".data/test-runs" repo-root))
      (create-directory* tmp-parent)
      (def imp-out (path-expand "m5-impact-run-out" tmp-parent))
      (def imp-cache (path-expand "m5-impact-run-cache" tmp-parent))
      (run-process (list "rm" "-rf" imp-out imp-cache))
      (create-directory* imp-cache)
      ;; Zero-impact file (e.g. README) runs 0 subjects in <0.2s!
      (let ((empty-res (run-impacted-multi-method-fleet repo-root '("README.md") cache-dir: imp-cache)))
        (check-equal? (.get empty-res affected-keys) '())
        (check-equal? (.get empty-res all-admitted?) #t)
        (check-equal? (.get empty-res total-executed) 0))
      ;; Editing deterministic_boundary.c runs ONLY c-boundary-conservation (skipping all other 4 subjects)!
      (let ((res (run-impacted-multi-method-fleet repo-root
                   '("languages-engineering/c/defense/silent-fallback-contrast/deterministic_boundary.c")
                   output-dir: imp-out
                   cache-dir: imp-cache)))
        (check-equal? (.get res affected-keys) '(c-boundary-conservation))
        (check-equal? (.get res all-admitted?) #t)
        (check-equal? (.get res total-executed) 2)
        (def pub-key (path-expand "attestation-ed25519.pub.pem" imp-cache))
        (def rep-path (cdr (assq 'c-boundary-conservation (.get res reports))))
        (check-equal? (verify-report-with-pinned-key rep-path pub-key) #t)))))

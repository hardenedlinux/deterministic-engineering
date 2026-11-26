;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Multi-Key Ed25519 Trust Store, Zero-Downtime Key Rotation, & Compromise Revocation Tests.
;;; Verifies:
;;; 1. Pure `trust-store-key-admitted?` admits active & rotated unrevoked keys and
;;;    unconditionally rejects untrusted and revoked keys.
;;; 2. Live 4-phase OpenSSL 3.6.1 Ed25519 lifecycle on `c-boundary-conservation`:
;;;    - Phase 1 (Cold under K1): executes 2/2 (CBMC || LeanPoo), signs cache & report-k1.
;;;    - Phase 2 (Zero-downtime rotation K1 -> K2): TrustStore {K1, K2} achieves 0 executed /
;;;      2 reused (zero cache busting!), and report-k1 still verifies under {K1, K2}.
;;;    - Phase 3 (Emergency compromise revocation of K1): TrustStore {K1, K2} \ {K1} immediately
;;;      rejects report-k1 (`#f`), triggers `IR06-attestation-invalid` on both K1-signed cache
;;;      entries, re-executes 2/2, and re-signs cache & report-k2 with K2!
;;;    - Phase 4 (Post-revocation Warm under K2): 0 executed / 2 reused, report-k2 verifies `#t`!
(import :std/test
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
                 replay-report-valid?)
        :deterministic-engineering/library/verification-flow/func
        "../../../support/verification-flow-runner.ss")
(export verification-flow-key-rotation-and-revocation-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def verification-flow-key-rotation-and-revocation-test
  (test-suite "Multi-key Ed25519 trust store, zero-downtime key rotation, and compromise revocation"
    (test-case "live 4-phase K1 -> rotate K2 -> revoke K1 -> warm K2 enforces zero-downtime rotation and instant compromise invalidation"
      (def tmp-parent (path-expand ".data/test-runs" repo-root))
      (create-directory* tmp-parent)
      (def work-root (path-expand "m5-key-rotation-test" tmp-parent))
      (run-process (list "rm" "-rf" work-root))
      (def k1-dir (path-expand "key-v1" work-root))
      (def k2-dir (path-expand "key-v2" work-root))
      (def k-rogue-dir (path-expand "key-rogue" work-root))
      (def cache-dir (path-expand "shared-cache" work-root))
      (def out-k1 (path-expand "report-k1" work-root))
      (def out-k2 (path-expand "report-k2" work-root))
      (create-directory* cache-dir)

      (def kp1 (ensure-cache-signing-keypair! k1-dir))
      (def kp2 (ensure-cache-signing-keypair! k2-dir))
      (def kp-rogue (ensure-cache-signing-keypair! k-rogue-dir))
      (def kid1 (.get kp1 key-id))
      (def kid2 (.get kp2 key-id))
      (def kid-rogue (.get kp-rogue key-id))
      (check (not (equal? kid1 kid2)) => #t)

      (def ts-k1 (make-ed25519-trust-store (list (.get kp1 public-key))))
      (def ts-rotated (make-ed25519-trust-store (list (.get kp1 public-key) (.get kp2 public-key))))
      (def ts-k1-revoked
        (make-ed25519-trust-store (list (.get kp1 public-key) (.get kp2 public-key))
                                  (list kid1)))

      ;; Pure trust-store admission checks.
      (check-equal? (trust-store-key-admitted? ts-k1 kid1) (.get kp1 public-key))
      (check-equal? (trust-store-key-admitted? ts-k1 kid-rogue) #f)
      (check-equal? (trust-store-key-admitted? ts-rotated kid1) (.get kp1 public-key))
      (check-equal? (trust-store-key-admitted? ts-rotated kid2) (.get kp2 public-key))
      (check-equal? (trust-store-key-admitted? ts-k1-revoked kid1) #f)
      (check-equal? (trust-store-key-admitted? ts-k1-revoked kid2) (.get kp2 public-key))

      ;; Phase 1 — Cold run signed by K1.
      (def rep-k1-path #f)
      (let ((r1 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'c-boundary-conservation
                  output-dir: out-k1
                  cache-dir: cache-dir
                  signing-keypair: kp1
                  trust-store: ts-k1
                  request-id: "req-rot-1-k1")))
        (set! rep-k1-path (.get r1 report-path))
        (check-equal? (replay-report-valid? (.get r1 replay-report)) #t)
        (check-equal? (length (.get (.get r1 cache-summary) executed)) 2)
        (check-equal? (.get (.get r1 cache-summary) reused) '())
        (check-equal? (verify-report-with-trust-store rep-k1-path ts-k1) #t))
      (##gc)

      ;; Phase 2 — Zero-downtime rotation K1 -> K2 (TrustStore {K1, K2}):
      ;;           0 engines re-executed (2/2 reused!), and report-k1 still verifies!
      (let ((r2 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'c-boundary-conservation
                  cache-dir: cache-dir
                  signing-keypair: kp2
                  trust-store: ts-rotated
                  request-id: "req-rot-2-zero-downtime")))
        (check-equal? (replay-report-valid? (.get r2 replay-report)) #t)
        (check-equal? (.get (.get r2 cache-summary) executed) '())
        (check-equal? (length (.get (.get r2 cache-summary) reused)) 2)
        (check-equal? (verify-report-with-trust-store rep-k1-path ts-rotated) #t))
      (##gc)

      ;; Phase 3 — Emergency compromise revocation of K1 (TrustStore {K1, K2} \ {K1}):
      ;;           report-k1 is IMMEDIATELY rejected, and BOTH K1-signed cache entries fail
      ;;           IR06-attestation-invalid, forcing fresh re-execution and re-signing under K2!
      (check-equal? (verify-report-with-trust-store rep-k1-path ts-k1-revoked) #f)
      (def rep-k2-path #f)
      (let ((r3 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'c-boundary-conservation
                  output-dir: out-k2
                  cache-dir: cache-dir
                  signing-keypair: kp2
                  trust-store: ts-k1-revoked
                  request-id: "req-rot-3-revoked-k1")))
        (set! rep-k2-path (.get r3 report-path))
        (check-equal? (replay-report-valid? (.get r3 replay-report)) #t)
        (check-equal? (length (.get (.get r3 cache-summary) executed)) 2)
        (check-equal? (.get (.get r3 cache-summary) reused) '())
        (check (and (member '("cbCbmcTarget" "IR06-attestation-invalid")
                            (.get (.get r3 cache-summary) invalidations)) #t) => #t)
        (check (and (member '("cbLeanPooTarget" "IR06-attestation-invalid")
                            (.get (.get r3 cache-summary) invalidations)) #t) => #t)
        (check-equal? (verify-report-with-trust-store rep-k2-path ts-k1-revoked) #t))
      (##gc)

      ;; Phase 4 — Post-revocation Warm run under K2: 0 executed / 2 reused!
      (let ((r4 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'c-boundary-conservation
                  cache-dir: cache-dir
                  signing-keypair: kp2
                  trust-store: ts-k1-revoked
                  request-id: "req-rot-4-warm-k2")))
        (check-equal? (replay-report-valid? (.get r4 replay-report)) #t)
        (check-equal? (.get (.get r4 cache-summary) executed) '())
        (check-equal? (length (.get (.get r4 cache-summary) reused)) 2)))))

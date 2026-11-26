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
        :std/encoding/json
        :std/misc/ports
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
                 replay-report-valid?)
        :deterministic-engineering/library/verification-flow/func
        "../../../support/verification-flow-runner.ss"
        (only-in "../../../support/offline-attestation-verifier.ss"
                 load-trust-store-json-lite
                 verify-fleet-offline))
(export verification-flow-key-rotation-and-revocation-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def (run-offline-verifier mode target-path store-path)
  (let* ((cmd (string-append
                "cd \"" repo-root "\" && "
                "gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q "
                "t/support/offline-attestation-verifier.ss " mode " "
                "\"" target-path "\" \"" store-path "\""))
         (proc (open-process
                 (list path: "/bin/bash"
                       arguments: (list "-euo" "pipefail" "-c" cmd)
                       stdin-redirection: #f
                       stdout-redirection: #t
                       stderr-redirection: #t)))
         (out (read-all-as-string proc))
         (status (process-status proc)))
    (close-port proc)
    (values status out)))

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
        (check-equal? (length (.get (.get r4 cache-summary) reused)) 2)))

    (test-case "2-level Merkle Fleet rotation K1 -> K2 and mixed-key sub-report revocation cascade via offline-attestation-verifier.ss"
      (def tmp-parent (path-expand ".data/test-runs" repo-root))
      (create-directory* tmp-parent)
      (def work-root (path-expand "m5-fleet-rotation-test" tmp-parent))
      (run-process (list "rm" "-rf" work-root))
      (def cache-dir (path-expand "fleet-cache" work-root))
      (def fleet-k1-dir (path-expand "fleet-k1" work-root))
      (def fleet-k2-warm-dir (path-expand "fleet-k2-warm" work-root))
      (def fleet-k2-postrev-dir (path-expand "fleet-k2-postrev" work-root))
      (def mixed-dir (path-expand "fleet-mixed-k1-child" work-root))
      (create-directory* cache-dir)

      (def kp1 (ensure-cache-signing-keypair! (path-expand "key-k1" work-root)))
      (def kp2 (ensure-cache-signing-keypair! (path-expand "key-k2" work-root)))
      (def kid1 (.get kp1 key-id))
      (def ts-rot (make-ed25519-trust-store (list (.get kp1 public-key) (.get kp2 public-key))))
      (def ts-rev (make-ed25519-trust-store (list (.get kp1 public-key) (.get kp2 public-key))
                                            (list kid1)))
      (def ts-rot-json (path-expand "ts-rotated.json" work-root))
      (def ts-rev-json (path-expand "ts-k1-revoked.json" work-root))
      (write-ed25519-trust-store-json ts-rot ts-rot-json)
      (write-ed25519-trust-store-json ts-rev ts-rev-json)
      (def cache-file (path-expand "verification-cache.v1.json" cache-dir))
      (def subset '(c-boundary-conservation meta-governance-soundness))

      ;; 1. Cold 2-subject Fleet under K1 (3 engines: CBMC + LeanPoo + MetaGov LeanPoo).
      (def f1 (run-multi-method-fleet repo-root fleet-k1-dir
                cache-dir: cache-dir
                signing-keypair: kp1
                trust-store: ts-rot
                subject-keys: subset
                fleet-id: "fleet-rot-k1"))
      (check-equal? (.get f1 all-admitted?) #t)
      (check-equal? (.get f1 total-executed) 3)
      (check-equal? (.get f1 total-reused) 0)

      ;; 2. Zero-downtime rotated Fleet under K2 with TrustStore {K1, K2}:
      ;;    0 executed / 3 reused; Fleet root & new child reports signed by K2 while cache stays K1!
      (def f2 (run-multi-method-fleet repo-root fleet-k2-warm-dir
                cache-dir: cache-dir
                signing-keypair: kp2
                trust-store: ts-rot
                subject-keys: subset
                fleet-id: "fleet-rot-k2-warm"))
      (check-equal? (.get f2 all-admitted?) #t)
      (check-equal? (.get f2 total-executed) 0)
      (check-equal? (.get f2 total-reused) 3)
      ;; Both Fleet-K2 and K1-signed cache verify offline under {K1, K2}!
      (let-values (((st out) (run-offline-verifier "--verify-fleet" (.get f2 fleet-report-path) ts-rot-json)))
        (check-equal? st 0)
        (check (and (string-contains out "MULTI-METHOD-VERIFY-FLEET-OK") #t) => #t))
      (let-values (((st out) (run-offline-verifier "--verify-cache" cache-file ts-rot-json)))
        (check-equal? st 0)
        (check (and (string-contains out "MULTI-METHOD-VERIFY-CACHE-OK") #t) => #t)
        (check (and (string-contains out "entries=3") #t) => #t))

      ;; 3. Mixed-Key Sub-Report Revocation Cascade:
      ;;    Build a genuine Mixed-Key Fleet where child 1 (`c-boundary-conservation`) is signed
      ;;    by K1, child 2 (`meta-governance-soundness`) is signed by K2, and the Fleet Merkle
      ;;    root itself is signed by unrevoked K2.
      ;;    - Under {K1, K2}: offline verifier ADMITS the mixed-key Fleet!
      ;;    - Under {K1, K2} \ {K1}: revoking K1 IMMEDIATELY REJECTS the entire Fleet at the
      ;;      child-report layer even though the top-level Fleet signature is valid K2!
      (run-process (list "cp" "-R" fleet-k2-warm-dir mixed-dir))
      (run-process (list "cp"
                         (path-expand "c-boundary-conservation/report.json" fleet-k1-dir)
                         (path-expand "c-boundary-conservation/report.json" mixed-dir)))
      (let* ((mixed-fleet-path (path-expand "fleet-report.json" mixed-dir))
             (k1-child-doc (call-with-input-file
                             (path-expand "c-boundary-conservation/report.json" mixed-dir)
                             (cut read-json <> object-as-hash: #t)))
             (k1-child-sha (hash-get (hash-get k1-child-doc "attestation") "payloadSha256"))
             (fdoc (call-with-input-file mixed-fleet-path (cut read-json <> object-as-hash: #t)))
             (subs (hash-get fdoc "subjects")))
        (for-each
          (lambda (s)
            (when (equal? (hash-get s "subjectKey") "c-boundary-conservation")
              (hash-put! s "reportPayloadSha256" k1-child-sha)))
          subs)
        (let* ((entries
                (map (lambda (s)
                       (list (hash-get s "subjectKey")
                             (hash-get s "subjectId")
                             (hash-get s "reportPayloadSha256")
                             (eq? (hash-get s "replayValid") #t)
                             (eq? (hash-get s "admitted") #t)))
                     subs))
               (canonical
                (canonical-fleet-signing-payload
                  (hash-get fdoc "fleetId")
                  (hash-get fdoc "sysmlSha256")
                  entries))
               (att (hash-get fdoc "attestation")))
          (hash-put! att "payloadSha256" (sha256-of-string canonical))
          (hash-put! att "signature" (ed25519-sign-string (.get kp2 private-key) canonical))
          (call-with-output-file mixed-fleet-path
            (lambda (port) (write-json port fdoc) (newline port))))
        (check-equal? (verify-fleet-offline mixed-fleet-path (load-trust-store-json-lite ts-rot-json)) #t)
        (check-equal? (verify-fleet-offline mixed-fleet-path (load-trust-store-json-lite ts-rev-json)) #f)
        (let-values (((st _out) (run-offline-verifier "--verify-fleet" mixed-fleet-path ts-rev-json)))
          (check (not (= st 0)) => #t)))

      ;; 4. Post-revocation Fleet under K2 with K1 revoked:
      ;;    K1-signed cache fails `--verify-cache` under ts-rev; Fleet re-executes 3/3 & re-signs
      ;;    cache under K2 -> BOTH `--verify-fleet` and `--verify-cache` pass under ts-rev!
      (let-values (((st _out) (run-offline-verifier "--verify-cache" cache-file ts-rev-json)))
        (check (not (= st 0)) => #t))
      (def f3 (run-multi-method-fleet repo-root fleet-k2-postrev-dir
                cache-dir: cache-dir
                signing-keypair: kp2
                trust-store: ts-rev
                subject-keys: subset
                fleet-id: "fleet-rot-k2-postrev"))
      (check-equal? (.get f3 all-admitted?) #t)
      (check-equal? (.get f3 total-executed) 3)
      (check-equal? (.get f3 total-reused) 0)
      (let-values (((st out) (run-offline-verifier "--verify-fleet" (.get f3 fleet-report-path) ts-rev-json)))
        (check-equal? st 0)
        (check (and (string-contains out "MULTI-METHOD-VERIFY-FLEET-OK") #t) => #t))
      (let-values (((st out) (run-offline-verifier "--verify-cache" cache-file ts-rev-json)))
        (check-equal? st 0)
        (check (and (string-contains out "MULTI-METHOD-VERIFY-CACHE-OK") #t) => #t)
        (check (and (string-contains out "entries=3") #t) => #t)))))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Multi-Subject Fleet Verification & 2-Level Merkle Pinned-Key Attestation Test.
;;; Verifies:
;;; 1. `run-multi-method-fleet` dynamically discovers ALL 3 SysML v2 subjects
;;;    (`process-tree-reclamation`, `backpressure-memory`, `lease-fencing-token`),
;;;    runs all 10 verification engines Cold (10 executed / 0 reused) into a shared
;;;    Ed25519-signed cache, and emits a 2-level Merkle-bound signed `fleet-report.json`.
;;; 2. `verify-fleet-report-with-pinned-key` validates both Fleet and every child
;;;    `report.json` strictly against an externally pinned trusted public key.
;;; 3. Negative security controls:
;;;    - Rogue/untrusted Ed25519 public key substitution is unconditionally rejected.
;;;    - Tampering a child subject's `report.json` breaks the Fleet Merkle verification
;;;      even when `fleet-report.json` itself is untouched.
;;; 4. Warm Fleet run against the exact same signed cache achieves 0 executed / 10 reused
;;;    across all 3 subjects and passes full pinned-key Merkle verification!
(import :std/test
        :std/encoding/json
        :std/misc/ports
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        "../../../support/verification-flow-runner.ss")
(export verification-flow-multi-subject-fleet-and-pinned-attestation-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def (run-verify-fleet-cli fleet-report-path trust-store-path)
  (let* ((cmd (string-append
                "cd \"" repo-root "\" && "
                "gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q "
                "t/support/offline-attestation-verifier.ss --verify-fleet "
                "\"" fleet-report-path "\" \"" trust-store-path "\""))
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

(def verification-flow-multi-subject-fleet-and-pinned-attestation-test
  (test-suite "Multi-subject Fleet orchestration and 2-level Merkle pinned-key Ed25519 attestation"
    (test-case "live 6-subject Fleet passes Cold (15/0) -> Warm (0/15), pinned-key & offline --verify-fleet CLI, and rejects rogue-key, revocation & child-tamper attacks"
      (def tmp-parent (path-expand ".data/test-runs" repo-root))
      (create-directory* tmp-parent)
      (def cache-dir (path-expand "m5-fleet-cache-test" tmp-parent))
      (def cold-dir (path-expand "m5-fleet-cold-out" tmp-parent))
      (def warm-dir (path-expand "m5-fleet-warm-out" tmp-parent))
      (def rogue-key-dir (path-expand "m5-fleet-rogue-key" tmp-parent))
      (def tamper-copy-dir (path-expand "m5-fleet-tamper-copy" tmp-parent))
      (run-process (list "rm" "-rf" cache-dir cold-dir warm-dir rogue-key-dir tamper-copy-dir))
      (create-directory* cache-dir)

      ;; Phase 0 — Dry-run Change-Impact Predictor before Cold Fleet: 15 pending, 0 reusable!
      (let ((p0 (predict-fleet-reuse-plan repo-root cache-dir: cache-dir)))
        (check-equal? (length (.get p0 subjects)) 6)
        (check-equal? (.get p0 total-pending) 15)
        (check-equal? (.get p0 total-reusable) 0))

      ;; Phase 1 — Cold Fleet across all 6 SysML v2 subjects (4 + 4 + 2 + 2 + 1 + 2 = 15 engines,
      ;;           covering Quint/Apalache, LeanPoo 6/6 cores across Engineering + Threat,
      ;;           Clippy, CBMC 6.11, and Rust OS/MBT Oracles!).
      (let ((f1 (run-multi-method-fleet repo-root cold-dir cache-dir: cache-dir fleet-id: "fleet-test-cold")))
        (def frpath (.get f1 fleet-report-path))
        (def trusted-pub (.get f1 public-key-path))
        (check-equal? (length (.get f1 subject-keys)) 6)
        (check-equal? (.get f1 all-admitted?) #t)
        (check-equal? (.get f1 total-executed) 15)
        (check-equal? (.get f1 total-reused) 0)

        ;; Genuine Fleet + all 6 child reports verify cleanly against externally pinned public key
        ;; AND via standalone offline `--verify-fleet` CLI with portable JSON Trust Store!
        (check-equal? (verify-fleet-report-with-pinned-key frpath trusted-pub) #t)
        (let* ((ts-valid (make-ed25519-trust-store (list trusted-pub)))
               (ts-valid-json (path-expand "fleet-trust-valid.json" cold-dir))
               (fleet-kid (car (car (.get ts-valid trusted-keys))))
               (ts-revoked (make-ed25519-trust-store (list trusted-pub) (list fleet-kid)))
               (ts-revoked-json (path-expand "fleet-trust-revoked.json" cold-dir)))
          (write-ed25519-trust-store-json ts-valid ts-valid-json)
          (write-ed25519-trust-store-json ts-revoked ts-revoked-json)
          (let-values (((st out) (run-verify-fleet-cli frpath ts-valid-json)))
            (check-equal? st 0)
            (check (and (string-contains out "MULTI-METHOD-VERIFY-FLEET-OK") #t) => #t))
          ;; Negative Control C: Revoked Fleet key in JSON Trust Store -> CLI MUST reject!
          (let-values (((st _out) (run-verify-fleet-cli frpath ts-revoked-json)))
            (check (not (= st 0)) => #t)))

        ;; Negative Control A: Rogue/untrusted Ed25519 public key MUST be rejected!
        (let* ((rogue-kp (ensure-cache-signing-keypair! rogue-key-dir))
               (rogue-pub (.get rogue-kp public-key))
               (child-rep (path-expand "meta-governance-soundness/report.json" cold-dir)))
          (check-equal? (verify-fleet-report-with-pinned-key frpath rogue-pub) #f)
          (check-equal? (verify-report-with-pinned-key child-rep rogue-pub) #f))

        ;; Negative Control B + D: Tampering 1 field inside a child report breaks BOTH in-process
        ;; pinned-key Merkle check AND standalone offline `--verify-fleet` CLI!
        (run-process (list "cp" "-R" cold-dir tamper-copy-dir))
        (let* ((copied-fleet (path-expand "fleet-report.json" tamper-copy-dir))
               (copied-child (path-expand "meta-governance-soundness/report.json" tamper-copy-dir))
               (ts-valid-json (path-expand "fleet-trust-valid.json" cold-dir))
               (cdoc (call-with-input-file copied-child (cut read-json <> object-as-hash: #t))))
          (hash-put! cdoc "requestId" "forged-child-request")
          (call-with-output-file copied-child
            (lambda (port) (write-json port cdoc) (newline port)))
          (check-equal? (verify-fleet-report-with-pinned-key copied-fleet trusted-pub) #f)
          (let-values (((st _out) (run-verify-fleet-cli copied-fleet ts-valid-json)))
            (check (not (= st 0)) => #t))))
      (##gc)

      ;; Phase 1.5 — Dry-run Change-Impact Predictor after Cold Fleet: 0 pending, 15 reusable (<1s)!
      (let ((p1 (predict-fleet-reuse-plan repo-root cache-dir: cache-dir)))
        (check-equal? (.get p1 total-pending) 0)
        (check-equal? (.get p1 total-reusable) 15))

      ;; Phase 2 — Warm Fleet: 0 engines executed, 15/15 verified Ed25519 cache hits across all 6 subjects!
      (let ((f2 (run-multi-method-fleet repo-root warm-dir cache-dir: cache-dir fleet-id: "fleet-test-warm")))
        (check-equal? (length (.get f2 subject-keys)) 6)
        (check-equal? (.get f2 all-admitted?) #t)
        (check-equal? (.get f2 total-executed) 0)
        (check-equal? (.get f2 total-reused) 15)
        (check-equal? (verify-fleet-report-with-pinned-key
                        (.get f2 fleet-report-path)
                        (.get f2 public-key-path))
                      #t)))))

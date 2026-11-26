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
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        "../../../support/verification-flow-runner.ss")
(export verification-flow-multi-subject-fleet-and-pinned-attestation-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def verification-flow-multi-subject-fleet-and-pinned-attestation-test
  (test-suite "Multi-subject Fleet orchestration and 2-level Merkle pinned-key Ed25519 attestation"
    (test-case "live 3-subject Fleet passes Cold (10/0) -> Warm (0/10), pinned-key Merkle verification, and rejects rogue-key & child-tamper attacks"
      (def tmp-parent (path-expand ".data/test-runs" repo-root))
      (create-directory* tmp-parent)
      (def cache-dir (path-expand "m5-fleet-cache-test" tmp-parent))
      (def cold-dir (path-expand "m5-fleet-cold-out" tmp-parent))
      (def warm-dir (path-expand "m5-fleet-warm-out" tmp-parent))
      (def rogue-key-dir (path-expand "m5-fleet-rogue-key" tmp-parent))
      (def tamper-copy-dir (path-expand "m5-fleet-tamper-copy" tmp-parent))
      (run-process (list "rm" "-rf" cache-dir cold-dir warm-dir rogue-key-dir tamper-copy-dir))
      (create-directory* cache-dir)

      ;; Phase 1 — Cold Fleet across all 3 SysML v2 subjects (4 + 4 + 2 = 10 engines).
      (let ((f1 (run-multi-method-fleet repo-root cold-dir cache-dir: cache-dir fleet-id: "fleet-test-cold")))
        (def frpath (.get f1 fleet-report-path))
        (def trusted-pub (.get f1 public-key-path))
        (check-equal? (length (.get f1 subject-keys)) 3)
        (check-equal? (.get f1 all-admitted?) #t)
        (check-equal? (.get f1 total-executed) 10)
        (check-equal? (.get f1 total-reused) 0)

        ;; Genuine Fleet + all 3 child reports verify cleanly against externally pinned public key!
        (check-equal? (verify-fleet-report-with-pinned-key frpath trusted-pub) #t)

        ;; Negative Control A: Rogue/untrusted Ed25519 public key MUST be rejected!
        (let* ((rogue-kp (ensure-cache-signing-keypair! rogue-key-dir))
               (rogue-pub (.get rogue-kp public-key))
               (child-rep (path-expand "lease-fencing-token/report.json" cold-dir)))
          (check-equal? (verify-fleet-report-with-pinned-key frpath rogue-pub) #f)
          (check-equal? (verify-report-with-pinned-key child-rep rogue-pub) #f))

        ;; Negative Control B: Tampering 1 field inside a child report breaks 2-level Fleet Merkle check!
        (run-process (list "cp" "-R" cold-dir tamper-copy-dir))
        (let* ((copied-fleet (path-expand "fleet-report.json" tamper-copy-dir))
               (copied-child (path-expand "lease-fencing-token/report.json" tamper-copy-dir))
               (cdoc (call-with-input-file copied-child (cut read-json <> object-as-hash: #t))))
          (hash-put! cdoc "requestId" "forged-child-request")
          (call-with-output-file copied-child
            (lambda (port) (write-json port cdoc) (newline port)))
          (check-equal? (verify-fleet-report-with-pinned-key copied-fleet trusted-pub) #f)))
      (##gc)

      ;; Phase 2 — Warm Fleet: 0 engines executed, 10/10 verified Ed25519 cache hits across all 3 subjects!
      (let ((f2 (run-multi-method-fleet repo-root warm-dir cache-dir: cache-dir fleet-id: "fleet-test-warm")))
        (check-equal? (length (.get f2 subject-keys)) 3)
        (check-equal? (.get f2 all-admitted?) #t)
        (check-equal? (.get f2 total-executed) 0)
        (check-equal? (.get f2 total-reused) 10)
        (check-equal? (verify-fleet-report-with-pinned-key
                        (.get f2 fleet-report-path)
                        (.get f2 public-key-path))
                      #t)))))

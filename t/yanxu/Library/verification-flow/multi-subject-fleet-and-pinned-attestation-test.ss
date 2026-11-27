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
        (only-in "../../../support/repo-paths.ss" resolve-repo-root)
        (only-in :tao3k/yuanxu/testing yuanxu-test-case)
        :std/encoding/json
        :std/misc/ports
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in "../../../support/offline-attestation-verifier.ss"
                 load-trust-store-json-lite
                 verify-fleet-bundle-offline)
        "../../../support/verification-flow-runner.ss")
(export verification-flow-multi-subject-fleet-and-pinned-attestation-test)

(def repo-root
  (resolve-repo-root))

(def (run-verify-fleet-cli fleet-report-path trust-store-path)
  (let* ((cmd (string-append
                "cd \"" repo-root "\" && "
                "GERBIL_PATH=\"$PWD/.gerbil\" gxi -:max-heap=2G,debug=q "
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
    (yuanxu-test-case "live 10-subject Fleet passes Cold (23/0) -> Warm (0/23), 2-file release bundle & in-toto statement, and rejects rogue-key, revocation & child-tamper attacks"
      (def tmp-parent (path-expand ".data/test-runs" repo-root))
      (create-directory* tmp-parent)
      (def cache-dir (path-expand "m5-fleet-cache-test" tmp-parent))
      (def cold-dir (path-expand "m5-fleet-cold-out" tmp-parent))
      (def warm-dir (path-expand "m5-fleet-warm-out" tmp-parent))
      (def rogue-key-dir (path-expand "m5-fleet-rogue-key" tmp-parent))
      (def tamper-copy-dir (path-expand "m5-fleet-tamper-copy" tmp-parent))
      (run-process (list "rm" "-rf" cache-dir cold-dir warm-dir rogue-key-dir tamper-copy-dir))
      (create-directory* cache-dir)

      ;; Phase 0 — Dry-run Change-Impact Predictor before Cold Fleet: 23 pending, 0 reusable!
      (let ((p0 (predict-fleet-reuse-plan repo-root cache-dir: cache-dir)))
        (check-equal? (length (.get p0 subjects)) 10)
        (check-equal? (.get p0 total-pending) 23)
        (check-equal? (.get p0 total-reusable) 0))

      ;; Phase 1 — Cold Fleet across all 10 SysML v2 subjects (4 + 4 + 2 + 2 + 1 + 2 + 2 + 2 + 2 + 2 = 23 engines,
      ;;           covering Quint/Apalache, LeanPoo across 5 Engineering + 5 AI-Security Threat subjects,
      ;;           Clippy, CBMC 6.11, and Rust OS/MBT Oracles!).
      (let ((f1 (run-multi-method-fleet repo-root cold-dir cache-dir: cache-dir fleet-id: "fleet-test-cold")))
        (def frpath (.get f1 fleet-report-path))
        (def trusted-pub (.get f1 public-key-path))
        (check-equal? (length (.get f1 subject-keys)) 10)
        (check-equal? (.get f1 all-admitted?) #t)
        (check-equal? (.get f1 total-executed) 23)
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

      ;; Phase 1.5 — Dry-run Change-Impact Predictor after Cold Fleet: 0 pending, 23 reusable (<1s)!
      (let ((p1 (predict-fleet-reuse-plan repo-root cache-dir: cache-dir)))
        (check-equal? (.get p1 total-pending) 0)
        (check-equal? (.get p1 total-reusable) 23))

      ;; Phase 2 — Warm Fleet with `emit-bundles?: #t`: 0 engines executed, 23/23 verified Ed25519 cache hits
      ;; across all 10 subjects + live 2-file air-gapped release bundle & in-toto v1 statement cross-audit!
      (let ((f2 (run-multi-method-fleet repo-root warm-dir cache-dir: cache-dir
                  fleet-id: "fleet-test-warm" emit-bundles?: #t)))
        (def fb-path (.get f2 fleet-bundle-path))
        (def tb-path (.get f2 trust-bundle-path))
        (def sysml-sha (.get f2 sysml-sha256))
        (def stmt-path (path-expand "verification-summary.intoto.json" warm-dir))
        (check-equal? (length (.get f2 subject-keys)) 10)
        (check-equal? (.get f2 all-admitted?) #t)
        (check-equal? (.get f2 total-executed) 0)
        (check-equal? (.get f2 total-reused) 23)
        (check-equal? (verify-fleet-report-with-pinned-key
                        (.get f2 fleet-report-path)
                        (.get f2 public-key-path))
                      #t)
        (check-equal? (file-exists? fb-path) #t)
        (check-equal? (file-exists? tb-path) #t)
        ;; Independent Gerbil 2-file air-gapped audit with spec pinning + 10-subject coverage:
        (let ((tp (load-trust-store-json-lite tb-path)))
          (check-equal?
            (verify-fleet-bundle-offline fb-path tp
              expected-sysml-sha256: sysml-sha
              expected-subject-count: 10
              required-subjects: '("meta-governance-soundness"
                                   "graph-witness-and-harness-confinement"
                                   "runtime-env-activation-and-context-confinement"
                                   "sandbox-symlink-archive-confinement"
                                   "stepup-attestation-and-host-effect-confinement"))
            #t))
        ;; Independent zero-dependency Bun/TS (<100ms) audit + in-toto v1 statement export:
        (let* ((cmd (string-append
                      "cd \"" repo-root "\" && bun t/harness/offline-attestation-verifier.ts "
                      "--json --verify-fleet-bundle "
                      "--expected-sysml-sha256 \"" sysml-sha "\" "
                      "--expected-subject-count 10 "
                      "--require-subject meta-governance-soundness "
                      "--require-subject graph-witness-and-harness-confinement "
                      "--require-subject runtime-env-activation-and-context-confinement "
                      "--require-subject sandbox-symlink-archive-confinement "
                      "--require-subject stepup-attestation-and-host-effect-confinement "
                      "--emit-statement \"" stmt-path "\" "
                      "\"" fb-path "\" \"" tb-path "\""))
               (proc (open-process
                       (list path: "/bin/bash"
                             arguments: (list "-euo" "pipefail" "-c" cmd)
                             stdin-redirection: #f
                             stdout-redirection: #t
                             stderr-redirection: #t)))
               (out (read-all-as-string proc))
               (st (process-status proc)))
          (close-port proc)
          (check-equal? st 0)
          (check (and (string-contains out "\"ok\":true") #t) => #t)
          (check (and (string-contains out "\"subjectCount\":10") #t) => #t)
          (let ((sdoc (call-with-input-file stmt-path (cut read-json <> object-as-hash: #t))))
            (check-equal? (hash-get sdoc "_type") "https://in-toto.io/Statement/v1")
            (check-equal? (hash-get (hash-get sdoc "predicate") "subjectCount") 10)))))))

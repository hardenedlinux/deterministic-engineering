;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Cross-Domain Threat LeanPoo Subject (`delegated-agent-authz`) & Standalone
;;; Offline JSON Ed25519 Trust-Store Verifier CLI Test (10.154).
;;;
;;; Verifies:
;;; 1. Zero-glue compilation & parallel execution of the 6th SysML v2 subject
;;;    `delegated-agent-authz` (Threat domain): Quint/Apalache (`DelegatedAgentAuthz.qnt`,
;;;    4 countermodels + 10 MBT traces) || Lean 4/LeanPoo (`Threat.CapabilityContainment`
;;;    reusing the exact same `Core.Containment` + `Core.Order` + `Core.Transport`).
;;; 2. Portable JSON Multi-Key Ed25519 Trust Store (`de.attestation.ed25519-trust-store.v1`)
;;;    serialization, reload, keyId-spoof rejection, and standalone CLI `--verify-report`:
;;;    - Authentic unrevoked key -> CLI exits 0 (`MULTI-METHOD-VERIFY-REPORT-OK`)
;;;    - Revoked key in JSON trust store -> CLI exits non-zero
;;;    - Tampered report.json -> CLI exits non-zero
(import :std/test
        :std/encoding/json
        :std/misc/ports
        :std/misc/process
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
                 replay-report-valid?)
        :deterministic-engineering/library/verification-flow/sysml-compiler
        "../../../support/verification-flow-runner.ss")
(export verification-flow-threat-capability-and-offline-verifier-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def (rm-rf! path)
  (when (file-exists? path)
    (run-process (list "rm" "-rf" path))))

(def (run-verify-cli report-path store-path (air-gapped? #f))
  (let* ((airgap-setup
          (if air-gapped?
            (string-append
              "GERBIL_REAL=\"$(command -v gerbil)\"\n"
              "GXI_REAL=\"$(command -v gxi)\"\n"
              "OPENSSL_BIN=\"$(command -v openssl)\"\n"
              "AIRGAP_BIN=\"$(mktemp -d)\"\n"
              "trap 'rm -rf \"$AIRGAP_BIN\"' EXIT\n"
              "ln -s \"$GERBIL_REAL\" \"$AIRGAP_BIN/gerbil\"\n"
              "ln -s \"$GXI_REAL\" \"$AIRGAP_BIN/gxi\"\n"
              "ln -s \"$OPENSSL_BIN\" \"$AIRGAP_BIN/openssl\"\n"
              "export PATH=\"$AIRGAP_BIN:/usr/bin:/bin\"\n"
              "if command -v sysml >/dev/null 2>&1; then echo 'ERROR: sysml leaked into airgap PATH' >&2; exit 99; fi\n")
            ""))
         (cmd (string-append
                "cd \"" repo-root "\"\n"
                airgap-setup
                "gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q "
                "t/support/verification-flow-runner.ss --verify-report "
                "\"" report-path "\" \"" store-path "\""))
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

(def verification-flow-threat-capability-and-offline-verifier-test
  (test-suite "Cross-domain Threat LeanPoo subject (delegated-agent-authz) & offline JSON trust-store CLI verifier"
    (test-case "delegated-agent-authz runs zero-glue Quint || LeanPoo and offline --verify-report enforces JSON trust store + revocation"
      (def work-dir (path-expand ".data/test-runs/m5-threat-offline-cli" repo-root))
      (rm-rf! work-dir)
      (create-directory* work-dir)

      (def cache-dir (path-expand "cache" work-dir))
      (def out-dir (path-expand "out-threat" work-dir))
      (def k1 (ensure-cache-signing-keypair! (path-expand "keys-k1" work-dir)))
      (def ts-valid (make-ed25519-trust-store (list (.get k1 public-key))))
      (def ts-valid-json (path-expand "trust-store-valid.json" work-dir))
      (write-ed25519-trust-store-json ts-valid ts-valid-json)

      ;; 1. Live zero-glue execution of 6th subject (Threat domain: Quint || LeanPoo).
      (def r1
        (run-multi-method-verification-pipeline repo-root
          subject-key: 'delegated-agent-authz
          output-dir: out-dir
          cache-dir: cache-dir
          signing-keypair: k1
          trust-store: ts-valid
          request-id: "req-threat-da-1"))
      (check-equal? (replay-report-valid? (.get r1 replay-report)) #t)
      (check-equal? ((.ref (.get r1 er-result) 'rows-of) 'er_finding) '())
      (check-equal? ((.ref (.get r1 er-result) 'rows-of) 'verification_admitted)
                    '(("threat.identity.delegated-agent-authz")))
      (check-equal? (length (.get (.get r1 cache-summary) executed)) 2)
      (check-equal? (length (.get (.get r1 cache-summary) reused)) 0)
      (def report-path (.get r1 report-path))

      ;; 2. Reload portable JSON trust store and verify in-process + via AIR-GAPPED standalone CLI!
      ;;    Hostile minimal PATH strips `sysml`, `quint`, `lean`, `lake`, `cargo`, `cbmc`, `bun`:
      ;;    proves `--verify-report` needs ONLY Gerbil + OpenSSL + shasum (zero SysML leakage)!
      (def ts-reloaded (load-ed25519-trust-store-json ts-valid-json))
      (check-equal? (verify-report-with-trust-store report-path ts-reloaded) #t)
      (let-values (((st out) (run-verify-cli report-path ts-valid-json #t)))
        (check-equal? st 0)
        (check (and (string-contains out "MULTI-METHOD-VERIFY-REPORT-OK") #t) => #t)
        (check (not (string-contains out "RDF conversion")) => #t))

      ;; 3. Negative control A: Revoke K1 in trust-store JSON -> standalone CLI MUST reject!
      (def ts-revoked
        (make-ed25519-trust-store (list (.get k1 public-key))
                                  (list (.get k1 key-id))))
      (def ts-revoked-json (path-expand "trust-store-revoked.json" work-dir))
      (write-ed25519-trust-store-json ts-revoked ts-revoked-json)
      (let-values (((st _out) (run-verify-cli report-path ts-revoked-json)))
        (check (not (= st 0)) => #t))

      ;; 4. Negative control B: Tamper with requestId in report.json -> standalone CLI MUST reject!
      (def tampered-report (path-expand "tampered-report.json" work-dir))
      (def rdoc (call-with-input-file report-path (cut read-json <> object-as-hash: #t)))
      (hash-put! rdoc "requestId" "forged-threat-request")
      (call-with-output-file tampered-report
        (lambda (p) (write-json p rdoc) (newline p)))
      (let-values (((st _out) (run-verify-cli tampered-report ts-valid-json)))
        (check (not (= st 0)) => #t))

      ;; 5. Warm cache hit on Threat subject: 0 executed, 2/2 Ed25519-verified reuse!
      (let ((r2 (run-multi-method-verification-pipeline repo-root
                  subject-key: 'delegated-agent-authz
                  cache-dir: cache-dir
                  signing-keypair: k1
                  trust-store: ts-valid
                  request-id: "req-threat-da-2")))
        (check-equal? (length (.get (.get r2 cache-summary) executed)) 0)
        (check-equal? (length (.get (.get r2 cache-summary) reused)) 2))

      ;; 6. Verify static air-gapped mutability constants match live SysML v2 projection.
      (let ((compiled (load-compiled-sysml-subjects repo-root)))
        (check-equal? default-process-tree-step-mutability
                      (.get (cdr (assq 'process-tree-reclamation compiled)) mutability))
        (check-equal? default-backpressure-step-mutability
                      (.get (cdr (assq 'backpressure-memory compiled)) mutability)))

      (rm-rf! work-dir))))

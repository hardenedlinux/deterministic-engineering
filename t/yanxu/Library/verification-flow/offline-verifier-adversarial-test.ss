;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Adversarial Cryptographic & Boundary Security Qualification Suite for
;;; `library/verification-flow/attestation.ss` and `t/support/offline-attestation-verifier.ss`.
;;;
;;; Zero Fun-Flow, zero ASCENT, zero SysML, zero formal-engine spawns (<5s runtime).
;;; Exercises 14 concrete adversarial attack surfaces:
;;;  1. Length-prefix injection / delimiter confusion immunity
;;;  2. Order-independent canonical determinism & timestamp binding
;;;  3. Trust-store JSON keyId spoofing rejection (`kid1` bound to `k2.pub.pem`)
;;;  4. Invalid schema & missing PEM file rejection + relative path resolution
;;;  5. Malformed Base64 signature crash resistance
;;;  6. Algorithm downgrade rejection (`none`, `HS256`)
;;;  7. Semantic admission bypass rejection (valid signature on `replayValid=#f` / `erFindings != ()` / empty `admitted`)
;;;  8. Revoked key rejection on valid report
;;;  9. Empty proof cache rejection (`entries: {}`)
;;; 10. Single-entry `issuedAtEpoch` rollback/tampering rejection in `--verify-cache`
;;; 11. Unsigned witness injection alongside valid signed entries
;;; 12. Empty `subjects: []` Fleet rejection
;;; 13. Validly re-signed child report with mismatched 2-level Merkle digest rejection
;;; 14. Missing child report path rejection
(import :std/test
        :std/crypto/digest
        :std/encoding/base64
        :std/encoding/hex
        :std/encoding/json
        :std/misc/ports
        :std/misc/process
        (only-in :std/source this-source-file)
        :deterministic-engineering/library/verification-flow/attestation
        "../../../support/offline-attestation-verifier.ss")
(export verification-flow-offline-verifier-adversarial-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def (sha256-str-local s) (hex-encode (sha256 (string->utf8 s))))
(def (sha256-file-local p) (hex-encode (sha256 (call-with-input-file p read-all-as-u8vector))))

(def (gen-ed25519-pair dir name)
  (create-directory* dir)
  (def priv (path-expand (string-append name ".pem") dir))
  (def pub (path-expand (string-append name ".pub.pem") dir))
  (run-process (list "openssl" "genpkey" "-algorithm" "ED25519" "-out" priv))
  (run-process (list "chmod" "600" priv))
  (run-process (list "openssl" "pkey" "-in" priv "-pubout" "-out" pub))
  (list (substring (sha256-file-local pub) 0 16) priv pub))

(def (sign-ed25519-local priv-pem payload-str tmp-dir tag)
  (def msg-path (path-expand (string-append tag ".msg") tmp-dir))
  (def sig-path (path-expand (string-append tag ".sig") tmp-dir))
  (call-with-output-file msg-path
    (lambda (port)
      (let ((v (string->utf8 payload-str)))
        (write-subu8vector v 0 (u8vector-length v) port))))
  (run-process (list "openssl" "pkeyutl" "-sign" "-rawin"
                     "-inkey" priv-pem "-in" msg-path "-out" sig-path))
  (base64-encode (call-with-input-file sig-path read-all-as-u8vector)))

(def (write-json-file path obj)
  (create-directory* (path-directory path))
  (call-with-output-file path (lambda (p) (write-json p obj) (newline p)))
  path)

(def (build-signed-report path key-triple tmp-dir tag
       replay-valid?: (replay-valid? #t)
       mr-findings: (mr-findings '())
       mr-open: (mr-open '())
       er-findings: (er-findings '())
       admitted: (admitted '(("subject.demo")))
       algorithm: (algorithm "Ed25519")
       override-sig: (override-sig #f)
       request-id: (request-id "req-adv-1"))
  (def kid (car key-triple))
  (def priv (cadr key-triple))
  (def pub (caddr key-triple))
  (def ev-rows '(("stepA" "oblA" "de-lean-poo" "unbounded-invariant" "pass" "ok")))
  (def tc-pairs '(("stepA" . "lean=4.34")))
  (def admitted-flat (map (lambda (r) (if (pair? r) (car r) r)) admitted))
  (def canonical
    (canonical-report-signing-payload
      "subject.demo" request-id "ok" replay-valid? admitted-flat ev-rows tc-pairs))
  (def sha (sha256-str-local canonical))
  (def sig (or override-sig (sign-ed25519-local priv canonical tmp-dir tag)))
  (def tc-ht (make-hash-table))
  (hash-put! tc-ht "stepA" "lean=4.34")
  (write-json-file path
    (hash ("schema" "deterministic-engineering.multi-method-report.v2")
          ("subject" "subject.demo")
          ("requestId" request-id)
          ("replayStatus" "ok")
          ("replayValid" replay-valid?)
          ("mrFindings" mr-findings)
          ("mrOpenPremises" mr-open)
          ("erFindings" er-findings)
          ("verificationAdmitted" admitted)
          ("toolchainFingerprints" tc-ht)
          ("evidence"
           (list (hash ("step" "stepA") ("obligation" "oblA")
                       ("method" "de-lean-poo") ("claimKind" "unbounded-invariant")
                       ("outcome" "pass") ("detail" "ok"))))
          ("attestation"
           (hash ("algorithm" algorithm)
                 ("keyId" kid)
                 ("publicKeyPath" pub)
                 ("payloadSha256" sha)
                 ("signature" sig)))))
  sha)

(def (throws? thunk)
  (with-catch (lambda (_) #t) (lambda () (thunk) #f)))

(def verification-flow-offline-verifier-adversarial-test
  (test-suite "Adversarial cryptographic & boundary security controls for attestation.ss and offline-attestation-verifier.ss"
    (test-case "canonical length-prefixed framing defeats delimiter injection, preserves order independence, and binds issuedAt"
      ;; Delimiter injection: embedding `\ninputCount=1:...\n` inside detail MUST NOT collide!
      (def p-injected
        (canonical-witness-signing-payload
          "s1" "o1" "de-lean-poo" "unbounded-invariant" "pass"
          "ok\ninputCount=1:1\nin:a=1:x" "tc1" '() "1700000000"))
      (def p-legit
        (canonical-witness-signing-payload
          "s1" "o1" "de-lean-poo" "unbounded-invariant" "pass"
          "ok" "tc1" '(("a" . "x")) "1700000000"))
      (check (not (equal? p-injected p-legit)) => #t)

      ;; Order independence across input-pairs and subject-entries.
      (def p-ord1
        (canonical-witness-signing-payload
          "s1" "o1" "de-quint" "fault-race" "pass" "ok" "tc1"
          '(("b.qnt" . "222") ("a.qnt" . "111")) "1700000000"))
      (def p-ord2
        (canonical-witness-signing-payload
          "s1" "o1" "de-quint" "fault-race" "pass" "ok" "tc1"
          '(("a.qnt" . "111") ("b.qnt" . "222")) "1700000000"))
      (check-equal? p-ord1 p-ord2)

      ;; Timestamp binding: altering issuedAt by 1 second MUST change payload.
      (def p-ts2
        (canonical-witness-signing-payload
          "s1" "o1" "de-quint" "fault-race" "pass" "ok" "tc1"
          '(("a.qnt" . "111") ("b.qnt" . "222")) "1700000001"))
      (check (not (equal? p-ord1 p-ts2)) => #t))

    (test-case "trust-store anti-spoofing, semantic admission bypass, cache poisoning, and 2-level Merkle forgery are all rejected"
      (def work (path-expand ".data/test-runs/m5-offline-adversarial" repo-root))
      (when (file-exists? work) (run-process (list "rm" "-rf" work)))
      (create-directory* work)
      (def keys-dir (path-expand "keys" work))
      (def k1 (gen-ed25519-pair keys-dir "k1"))
      (def k2 (gen-ed25519-pair keys-dir "k2"))
      (def kid1 (car k1))
      (def kid2 (car k2))

      ;; Relative public-key path resolution succeeds cleanly.
      (def ts-rel-path (path-expand "trust-relative.json" work))
      (def tk-rel (make-hash-table))
      (hash-put! tk-rel kid1 "keys/k1.pub.pem")
      (hash-put! tk-rel kid2 "keys/k2.pub.pem")
      (write-json-file ts-rel-path
        (hash ("schema" "de.attestation.ed25519-trust-store.v1")
              ("trustedKeys" tk-rel)
              ("revokedKeyIds" '())))
      (def tp-valid (load-trust-store-json-lite ts-rel-path))
      (check-equal? (length (car tp-valid)) 2)

      ;; Attack 1: keyId spoofing (bind k2.pub.pem under kid1) -> MUST throw!
      (def ts-spoof (path-expand "trust-spoof.json" work))
      (def tk-spoof (make-hash-table))
      (hash-put! tk-spoof kid1 "keys/k2.pub.pem")
      (write-json-file ts-spoof
        (hash ("schema" "de.attestation.ed25519-trust-store.v1")
              ("trustedKeys" tk-spoof)
              ("revokedKeyIds" '())))
      (check-equal? (throws? (lambda () (load-trust-store-json-lite ts-spoof))) #t)

      ;; Attack 2 & 3: wrong schema and missing PEM path -> MUST throw!
      (def ts-bad-schema (path-expand "trust-bad-schema.json" work))
      (write-json-file ts-bad-schema
        (hash ("schema" "de.attestation.v0") ("trustedKeys" tk-rel) ("revokedKeyIds" '())))
      (check-equal? (throws? (lambda () (load-trust-store-json-lite ts-bad-schema))) #t)
      (def ts-missing-pem (path-expand "trust-missing.json" work))
      (def tk-miss (make-hash-table))
      (hash-put! tk-miss kid1 "keys/does-not-exist.pub.pem")
      (write-json-file ts-missing-pem
        (hash ("schema" "de.attestation.ed25519-trust-store.v1")
              ("trustedKeys" tk-miss)
              ("revokedKeyIds" '())))
      (check-equal? (throws? (lambda () (load-trust-store-json-lite ts-missing-pem))) #t)

      ;; Positive report control.
      (def rep-ok (path-expand "rep-ok.json" work))
      (def rep-ok-sha (build-signed-report rep-ok k1 work "rep-ok"))
      (check-equal? (verify-report-offline rep-ok tp-valid) #t)

      ;; Attack 5: Malformed Base64 signature -> returns #f cleanly without crashing.
      (def rep-bad-b64 (path-expand "rep-bad-b64.json" work))
      (build-signed-report rep-bad-b64 k1 work "rep-b64" override-sig: "!!!not-valid-base64!!!")
      (check-equal? (verify-report-offline rep-bad-b64 tp-valid) #f)

      ;; Attack 6: Algorithm downgrade ("none") -> returns #f.
      (def rep-downgrade (path-expand "rep-downgrade.json" work))
      (build-signed-report rep-downgrade k1 work "rep-alg" algorithm: "none")
      (check-equal? (verify-report-offline rep-downgrade tp-valid) #f)

      ;; Attack 7: Semantic admission bypass (valid K1 signature on un-admitted reports!).
      (def rep-no-replay (path-expand "rep-no-replay.json" work))
      (build-signed-report rep-no-replay k1 work "rep-nr" replay-valid?: #f)
      (check-equal? (verify-report-offline rep-no-replay tp-valid) #f)

      (def rep-er-fail (path-expand "rep-er-fail.json" work))
      (build-signed-report rep-er-fail k1 work "rep-er" er-findings: '(("ER02-failed-step")))
      (check-equal? (verify-report-offline rep-er-fail tp-valid) #f)

      (def rep-empty-adm (path-expand "rep-empty-adm.json" work))
      (build-signed-report rep-empty-adm k1 work "rep-ea" admitted: '())
      (check-equal? (verify-report-offline rep-empty-adm tp-valid) #f)

      ;; Attack 8: Revoking kid1 immediately rejects valid rep-ok.
      (def tp-rev-k1 (cons (car tp-valid) (list kid1)))
      (check-equal? (verify-report-offline rep-ok tp-rev-k1) #f)

      ;; Attack 9, 10, 11: Cache verification controls (empty, valid, timestamp tamper, unsigned injection).
      (def cache-empty (path-expand "cache-empty.json" work))
      (write-json-file cache-empty
        (hash ("schema" "deterministic-engineering.verification-cache.v2")
              ("entries" (make-hash-table))))
      (check-equal? (verify-cache-offline cache-empty tp-valid) #f)

      (def (mk-signed-cache-entry step-s key-t issued-ep)
        (def digs (make-hash-table))
        (hash-put! digs "a.lean" "deadbeef")
        (def canon (canonical-witness-signing-payload
                     step-s "obl" "de-lean-poo" "unbounded-invariant" "pass" "ok"
                     "lean=4.34" '(("a.lean" . "deadbeef")) (number->string issued-ep)))
        (hash ("obligation" "obl") ("method" "de-lean-poo") ("claimKind" "unbounded-invariant")
              ("outcome" "pass") ("detail" "ok") ("toolchainFingerprint" "lean=4.34")
              ("issuedAtEpoch" issued-ep) ("keyId" (car key-t)) ("inputDigests" digs)
              ("signature" (sign-ed25519-local (cadr key-t) canon work (string-append "ce-" step-s)))))

      (def entries-ok (make-hash-table))
      (hash-put! entries-ok "s1" (mk-signed-cache-entry "s1" k1 1700000100))
      (hash-put! entries-ok "s2" (mk-signed-cache-entry "s2" k2 1700000200))
      (def cache-ok (path-expand "cache-ok.json" work))
      (write-json-file cache-ok
        (hash ("schema" "deterministic-engineering.verification-cache.v2") ("entries" entries-ok)))
      (check-equal? (verify-cache-offline cache-ok tp-valid) 2)
      ;; Revoking k1 invalidates mixed-key cache immediately!
      (check-equal? (verify-cache-offline cache-ok tp-rev-k1) #f)

      ;; Attack 10: Tampering issuedAtEpoch by +1 on s1 invalidates cache!
      (def s1-tampered (mk-signed-cache-entry "s1" k1 1700000100))
      (hash-put! s1-tampered "issuedAtEpoch" 1700000101)
      (def entries-ts-bad (make-hash-table))
      (hash-put! entries-ts-bad "s1" s1-tampered)
      (hash-put! entries-ts-bad "s2" (mk-signed-cache-entry "s2" k2 1700000200))
      (def cache-ts-bad (path-expand "cache-ts-bad.json" work))
      (write-json-file cache-ts-bad
        (hash ("schema" "deterministic-engineering.verification-cache.v2") ("entries" entries-ts-bad)))
      (check-equal? (verify-cache-offline cache-ts-bad tp-valid) #f)

      ;; Attack 11: Unsigned witness injected alongside valid signed entries -> rejected!
      (def entries-unsigned (make-hash-table))
      (hash-put! entries-unsigned "s1" (mk-signed-cache-entry "s1" k1 1700000100))
      (hash-put! entries-unsigned "s-rogue" (hash ("outcome" "pass")))
      (def cache-unsigned (path-expand "cache-unsigned.json" work))
      (write-json-file cache-unsigned
        (hash ("schema" "deterministic-engineering.verification-cache.v2") ("entries" entries-unsigned)))
      (check-equal? (verify-cache-offline cache-unsigned tp-valid) #f)

      ;; Attack 12, 13, 14: 2-level Merkle Fleet controls.
      (def (write-signed-fleet fpath sub-list key-t tag)
        (def canon-entries
          (map (lambda (s)
                 (list (hash-get s "subjectKey") (hash-get s "subjectId")
                       (hash-get s "reportPayloadSha256")
                       (eq? (hash-get s "replayValid") #t)
                       (eq? (hash-get s "admitted") #t)))
               sub-list))
        (def canon (canonical-fleet-signing-payload "fleet-adv" "sysml-sha" canon-entries))
        (write-json-file fpath
          (hash ("schema" "deterministic-engineering.multi-method-fleet-report.v1")
                ("fleetId" "fleet-adv")
                ("sysmlSha256" "sysml-sha")
                ("allAdmitted" #t)
                ("subjects" sub-list)
                ("attestation"
                 (hash ("algorithm" "Ed25519")
                       ("keyId" (car key-t))
                       ("payloadSha256" (sha256-str-local canon))
                       ("signature" (sign-ed25519-local (cadr key-t) canon work tag)))))))

      ;; Attack 12: Empty subjects list with valid K2 signature -> MUST be rejected!
      (def fleet-empty (path-expand "fleet-empty.json" work))
      (write-signed-fleet fleet-empty '() k2 "fl-empty")
      (check-equal? (verify-fleet-offline fleet-empty tp-valid) #f)

      ;; Attack 13: Attacker replaces child report with a DIFFERENT report validly re-signed by K2
      ;;            (same trusted key, valid signature, valid admission, WRONG Merkle digest!) -> MUST be rejected!
      (def rep-forged-valid-sig (path-expand "rep-forged-k2.json" work))
      (build-signed-report rep-forged-valid-sig k2 work "rep-forged" request-id: "req-attacker-re-signed")
      (def fleet-merkle-mismatch (path-expand "fleet-mismatch.json" work))
      (write-signed-fleet fleet-merkle-mismatch
        (list (hash ("subjectKey" "demo") ("subjectId" "subject.demo")
                    ("reportRelativePath" "rep-forged-k2.json")
                    ("reportPayloadSha256" rep-ok-sha)
                    ("replayValid" #t) ("admitted" #t)))
        k2 "fl-mismatch")
      (check-equal? (verify-fleet-offline fleet-merkle-mismatch tp-valid) #f)

      ;; Attack 14: Missing child report path -> MUST be rejected!
      (def fleet-missing-child (path-expand "fleet-missing.json" work))
      (write-signed-fleet fleet-missing-child
        (list (hash ("subjectKey" "demo") ("subjectId" "subject.demo")
                    ("reportRelativePath" "nonexistent/report.json")
                    ("reportPayloadSha256" rep-ok-sha)
                    ("replayValid" #t) ("admitted" #t)))
        k2 "fl-missing")
      (check-equal? (verify-fleet-offline fleet-missing-child tp-valid) #f)

      ;; Attack 15: Parent-directory traversal (`../rep-ok.json`) pointing to a REAL valid K1-signed
      ;;            report OUTSIDE the Fleet directory with matching Merkle digest -> MUST be rejected!
      (def subfleet-dir (path-expand "subfleet" work))
      (create-directory* subfleet-dir)
      (def fleet-traversal (path-expand "fleet-report.json" subfleet-dir))
      (write-signed-fleet fleet-traversal
        (list (hash ("subjectKey" "demo") ("subjectId" "subject.demo")
                    ("reportRelativePath" "../rep-ok.json")
                    ("reportPayloadSha256" rep-ok-sha)
                    ("replayValid" #t) ("admitted" #t)))
        k2 "fl-traversal")
      (check-equal? (verify-fleet-offline fleet-traversal tp-valid) #f)

      ;; Attack 16: Absolute path override (`/…/rep-ok.json`) pointing to a REAL valid K1-signed
      ;;            report with matching Merkle digest -> MUST be rejected!
      (def fleet-abs (path-expand "fleet-abs.json" subfleet-dir))
      (write-signed-fleet fleet-abs
        (list (hash ("subjectKey" "demo") ("subjectId" "subject.demo")
                    ("reportRelativePath" rep-ok)
                    ("reportPayloadSha256" rep-ok-sha)
                    ("replayValid" #t) ("admitted" #t)))
        k2 "fl-abs")
      (check-equal? (verify-fleet-offline fleet-abs tp-valid) #f)

      ;; Attack 17: Pure `safe-relative-child-path?` matrix.
      (check-equal? (safe-relative-child-path? "demo/report.json") #t)
      (check-equal? (safe-relative-child-path? "report.json") #t)
      (check-equal? (safe-relative-child-path? "") #f)
      (check-equal? (safe-relative-child-path? "/etc/passwd") #f)
      (check-equal? (safe-relative-child-path? "../rep-ok.json") #f)
      (check-equal? (safe-relative-child-path? "sub/../../rep-ok.json") #f)
      (check-equal? (safe-relative-child-path? "sub//report.json") #f)
      (check-equal? (safe-relative-child-path? "./report.json") #f)
      (check-equal? (safe-relative-child-path? "sub\\report.json") #f)

      ;; Attack 18A: File symlink escape (`evil-link.json -> ../rep-ok.json`) inside subfleet/ -> MUST be rejected!
      (def evil-file-link (path-expand "evil-link.json" subfleet-dir))
      (create-symbolic-link rep-ok evil-file-link)
      (def fleet-sym-file (path-expand "fleet-sym-file.json" subfleet-dir))
      (write-signed-fleet fleet-sym-file
        (list (hash ("subjectKey" "demo") ("subjectId" "subject.demo")
                    ("reportRelativePath" "evil-link.json")
                    ("reportPayloadSha256" rep-ok-sha)
                    ("replayValid" #t) ("admitted" #t)))
        k2 "fl-sym-file")
      (check-equal? (verify-fleet-offline fleet-sym-file tp-valid) #f)

      ;; Attack 18B: Directory symlink escape (`linked-dir -> ..`, path `linked-dir/rep-ok.json`) -> MUST be rejected!
      (def evil-dir-link (path-expand "linked-dir" subfleet-dir))
      (create-symbolic-link work evil-dir-link)
      (def fleet-sym-dir (path-expand "fleet-sym-dir.json" subfleet-dir))
      (write-signed-fleet fleet-sym-dir
        (list (hash ("subjectKey" "demo") ("subjectId" "subject.demo")
                    ("reportRelativePath" "linked-dir/rep-ok.json")
                    ("reportPayloadSha256" rep-ok-sha)
                    ("replayValid" #t) ("admitted" #t)))
        k2 "fl-sym-dir")
      (check-equal? (verify-fleet-offline fleet-sym-dir tp-valid) #f)

      ;; Machine-readable `--json` CLI mode: positive (exit 0, ok=#t) & negative (exit != 0, ok=#f)!
      (def (run-json-cli mode target store)
        (let* ((cmd (string-append
                      "cd \"" repo-root "\" && "
                      "gerbil -:max-heap=2G,debug=q env gxi -:max-heap=2G,debug=q "
                      "t/support/offline-attestation-verifier.ss --json " mode " "
                      "\"" target "\" \"" store "\""))
               (proc (open-process
                       (list path: "/bin/bash"
                             arguments: (list "-euo" "pipefail" "-c" cmd)
                             stdin-redirection: #f
                             stdout-redirection: #t
                             stderr-redirection: #t)))
               (out (read-all-as-string proc))
               (st (process-status proc)))
          (close-port proc)
          (values st out)))
      (let-values (((st out) (run-json-cli "--verify-report" rep-ok ts-rel-path)))
        (check-equal? st 0)
        (let* ((json-line (car (filter (lambda (ln) (and (> (string-length ln) 0)
                                                         (char=? (string-ref ln 0) #\{)))
                                       (string-split out #\newline))))
               (doc (call-with-input-string json-line (cut read-json <> object-as-hash: #t))))
          (check-equal? (hash-get doc "schema") "de.attestation.offline-verify-result.v1")
          (check-equal? (hash-get doc "ok") #t)
          (check-equal? (hash-get doc "mode") "verify-report")))
      (let-values (((st out) (run-json-cli "--verify-report" rep-bad-b64 ts-rel-path)))
        (check (not (= st 0)) => #t)
        (let* ((json-line (car (filter (lambda (ln) (and (> (string-length ln) 0)
                                                         (char=? (string-ref ln 0) #\{)))
                                       (string-split out #\newline))))
               (doc (call-with-input-string json-line (cut read-json <> object-as-hash: #t))))
          (check-equal? (hash-get doc "ok") #f)
          (check (string? (hash-get doc "reason")) => #t)))

      (run-process (list "rm" "-rf" work)))))

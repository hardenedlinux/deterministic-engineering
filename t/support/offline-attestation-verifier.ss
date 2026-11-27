;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Ultra-Lightweight Standalone Air-Gapped Offline Attestation Verifier (10.154).
;;;
;;; Zero Fun-Flow, zero ASCENT, zero POO, zero OpenSysML, zero formal-engine imports!
;;; Requires ONLY Gerbil (`gxi`), OpenSSL (`openssl pkeyutl`), and the compiled
;;; zero-dependency canonical module `library/verification-flow/attestation`.
;;;
;;; CLI:
;;;   gxi t/support/offline-attestation-verifier.ss [--json] --verify-report <report.json> <trust-store.json>
;;;   gxi t/support/offline-attestation-verifier.ss [--json] --verify-fleet  <fleet-report.json> <trust-store.json>
;;;   gxi t/support/offline-attestation-verifier.ss [--json] --verify-cache  <verification-cache.v1.json> <trust-store.json>
;;;   gxi t/support/offline-attestation-verifier.ss [--json] --verify-trust-store <trust-store.json>
;;;   gxi t/support/offline-attestation-verifier.ss [--json] --export-trust-bundle <out.json> [--revoke <keyId>]... <pub1.pem> [<pub2.pem> ...]
;;;   gxi t/support/offline-attestation-verifier.ss [--json] --pack-fleet-bundle <fleet-report.json> <out-bundle.json>
;;;   gxi t/support/offline-attestation-verifier.ss [--json] --verify-fleet-bundle <fleet-bundle.json> <trust-store.json>
(import
  :std/crypto/digest
  :std/encoding/base64
  :std/encoding/hex
  :std/encoding/json
  :std/misc/ports
  :deterministic-engineering/library/verification-flow/attestation)
(export
  load-trust-store-json-lite
  load-audit-policy-json
  merge-audit-policy-strict
  export-trust-bundle-offline
  pack-fleet-bundle-offline
  resolve-contained-child-report-path
  verify-report-doc-offline
  verify-report-offline
  verify-fleet-offline
  inspect-fleet-bundle-verified
  build-intoto-verification-statement
  emit-intoto-verification-statement!
  inspect-dsse-statement-verified
  verify-dsse-statement-offline
  cosign-dsse-statement-offline
  verify-fleet-bundle-offline
  verify-cache-offline
  main)

(def (sha256-file path)
  (hex-encode (sha256 (call-with-input-file path read-all-as-u8vector))))

(def (sha256-str text)
  (hex-encode (sha256 (string->utf8 text))))

(def *tmp-seq* 0)
(def (next-tmp-prefix)
  (set! *tmp-seq* (+ *tmp-seq* 1))
  (string-append "/tmp/de-offline-verify-"
                 (number->string (##os-getpid)) "-"
                 (number->string *tmp-seq*)))

(def (write-bytes-file path vec)
  (call-with-output-file path
    (lambda (port)
      (write-subu8vector vec 0 (u8vector-length vec) port))))

(def (safe-rm! path)
  (when (file-exists? path)
    (with-catch (lambda (_) (void)) (lambda () (delete-file path)))))

(def (hash->string-alist ht)
  (def acc '())
  (when (hash-table? ht)
    (hash-for-each (lambda (k v) (set! acc (cons (cons k v) acc))) ht))
  acc)

;; Native POSIX lstat() segment-by-segment containment check:
;; Rejects lexical traversal (`safe-relative-child-path?`) AND any symbolic link
;; along intermediate directories OR the leaf report file itself!
(def (resolve-contained-child-report-path fleet-dir rel)
  (and (safe-relative-child-path? rel)
       (let loop ((segs (string-split rel #\/)) (acc fleet-dir))
         (if (null? segs)
           #f
           (let* ((seg (car segs))
                  (rest (cdr segs))
                  (cur (path-expand seg acc))
                  (ftype (with-catch (lambda (_) #f)
                           (lambda () (file-info-type (file-info cur #f))))))
             (if (null? rest)
               (and (eq? ftype 'regular) cur)
               (and (eq? ftype 'directory) (loop rest cur))))))))

(def (inline-pem-string? val)
  (and (string? val)
       (>= (string-length val) 26)
       (equal? (substring val 0 26) "-----BEGIN PUBLIC KEY-----")))

(def (ed25519-sign-raw priv-pem-path payload-str)
  (let* ((prefix (next-tmp-prefix))
         (msg-path (string-append prefix ".msg"))
         (sig-path (string-append prefix ".sig")))
    (try
      (write-bytes-file msg-path (string->utf8 payload-str))
      (let* ((proc (open-process
                     (list path: "openssl"
                           arguments: (list "pkeyutl" "-sign" "-rawin"
                                            "-inkey" priv-pem-path
                                            "-in" msg-path
                                            "-out" sig-path)
                           stdin-redirection: #f
                           stdout-redirection: #t
                           stderr-redirection: #t)))
             (_out (read-all-as-string proc))
             (status (process-status proc)))
        (close-port proc)
        (unless (= status 0)
          (error "Ed25519 signing failed" priv-pem-path))
        (base64-encode (call-with-input-file sig-path read-all-as-u8vector)))
      (finally
        (safe-rm! msg-path)
        (safe-rm! sig-path)))))

(def (ed25519-verify-raw pub-pem payload-str sig-b64)
  (def is-inline? (inline-pem-string? pub-pem))
  (if (and (string? pub-pem)
           (or is-inline? (file-exists? pub-pem))
           (string? sig-b64) (> (string-length sig-b64) 0))
    (let ((sig-bytes (with-catch (lambda (_) #f) (lambda () (base64-decode sig-b64)))))
      (if (u8vector? sig-bytes)
        (let* ((prefix (next-tmp-prefix))
               (msg-path (string-append prefix ".msg"))
               (sig-path (string-append prefix ".sig"))
               (tmp-pub-path (and is-inline? (string-append prefix ".pub.pem")))
               (inkey-path (or tmp-pub-path pub-pem)))
          (try
            (write-bytes-file msg-path (string->utf8 payload-str))
            (write-bytes-file sig-path sig-bytes)
            (when tmp-pub-path
              (write-bytes-file tmp-pub-path (string->utf8 pub-pem)))
            (let* ((proc (open-process
                           (list path: "openssl"
                                 arguments: (list "pkeyutl" "-verify" "-rawin" "-pubin"
                                                  "-inkey" inkey-path
                                                  "-sigfile" sig-path
                                                  "-in" msg-path)
                                 stdin-redirection: #f
                                 stdout-redirection: #t
                                 stderr-redirection: #t)))
                   (_out (read-all-as-string proc))
                   (status (process-status proc)))
              (close-port proc)
              (= status 0))
            (finally
              (safe-rm! msg-path)
              (safe-rm! sig-path)
              (when tmp-pub-path (safe-rm! tmp-pub-path)))))
        #f))
    #f))

(def (resolve-trusted-pem-path base-dir raw-path)
  (unless (and (string? raw-path) (> (string-length raw-path) 0))
    (error "Invalid trusted public key path" raw-path))
  (if (char=? (string-ref raw-path 0) #\/)
    (let ((ftype (with-catch (lambda (_) #f)
                   (lambda () (file-info-type (file-info raw-path #f))))))
      (unless (eq? ftype 'regular)
        (error "Trusted public key must be an existing regular non-symlink file" raw-path))
      raw-path)
    (let ((contained (resolve-contained-child-report-path base-dir raw-path)))
      (unless contained
        (error "Relative trusted public key path rejected (missing, traversal, or symlink)"
               raw-path base-dir))
      contained)))

(def (trust-pair-trusted tp) (car tp))
(def (trust-pair-revoked tp)
  (if (and (pair? (cdr tp)) (pair? (cddr tp)) (hash-table? (caddr tp)))
    (cadr tp)
    (cdr tp)))
(def (trust-pair-key-roles tp)
  (if (and (pair? (cdr tp)) (pair? (cddr tp)) (hash-table? (caddr tp)))
    (caddr tp)
    (make-hash-table)))

;; Returns `(list trusted-keys-alist revoked-key-ids-list key-roles-hash)` after validating schema,
;; non-symlink regular PEM files, keyId SHA-256 anti-spoofing, and optional `keyRoles` bindings.
(def (load-trust-store-json-lite store-path)
  (unless (and (string? store-path) (file-exists? store-path))
    (error "Ed25519 trust store file not found" store-path))
  (def base-dir (path-directory store-path))
  (def doc (call-with-input-file store-path (cut read-json <> object-as-hash: #t)))
  (unless (and (hash-table? doc)
               (equal? (hash-get doc "schema") "de.attestation.ed25519-trust-store.v1"))
    (error "Invalid Ed25519 trust store schema" store-path))
  (def keys-ht (hash-get doc "trustedKeys"))
  (unless (hash-table? keys-ht)
    (error "Ed25519 trust store missing trustedKeys map" store-path))
  (def trusted '())
  (hash-for-each
    (lambda (declared-kid raw-val)
      (unless (and (string? declared-kid) (string? raw-val))
        (error "Invalid trustedKeys entry" declared-kid raw-val))
      (if (inline-pem-string? raw-val)
        (let ((actual-kid (substring (sha256-str raw-val) 0 16)))
          (unless (equal? actual-kid declared-kid)
            (error "Inline trusted public keyId mismatch (possible spoofing)"
                   declared-kid actual-kid))
          (set! trusted (cons (cons declared-kid raw-val) trusted)))
        (let* ((resolved (resolve-trusted-pem-path base-dir raw-val))
               (actual-kid (substring (sha256-file resolved) 0 16)))
          (unless (equal? actual-kid declared-kid)
            (error "Trusted public keyId mismatch (possible spoofing)"
                   declared-kid actual-kid resolved))
          (set! trusted (cons (cons declared-kid resolved) trusted)))))
    keys-ht)
  (def revoked (filter string? (or (hash-get doc "revokedKeyIds") '())))
  (def roles-ht (make-hash-table))
  (let ((raw-roles (hash-get doc "keyRoles")))
    (when raw-roles
      (unless (hash-table? raw-roles)
        (error "Ed25519 trust store keyRoles must be a JSON object" store-path))
      (hash-for-each
        (lambda (kid rlist)
          (unless (and (string? kid) (hash-key? keys-ht kid))
            (error "keyRoles references unknown keyId not in trustedKeys" kid))
          (unless (list? rlist)
            (error "keyRoles value must be a list of non-empty role strings" kid))
          (let ((clean '()))
            (for-each
              (lambda (r)
                (unless (and (string? r) (> (string-length r) 0))
                  (error "Invalid empty or non-string role in keyRoles" kid r))
                (unless (member r clean) (set! clean (cons r clean))))
              rlist)
            (hash-put! roles-ht kid (sort-by clean string<?))))
        raw-roles)))
  (list (reverse trusted) revoked roles-ht))

(def *audit-policy-schema* "de.attestation.policy.v1")
(def *audit-policy-allowed-keys*
  '("schema" "expectedSysmlSha256" "expectedSubjectCount"
    "requiredSubjects" "minSignatures" "requiredSigners" "requiredRoles"))

(def (validate-policy-string-list field-name raw)
  (unless (list? raw)
    (error (string-append "Policy field " field-name " must be a list of non-empty strings") raw))
  (let ((acc '()))
    (for-each
      (lambda (x)
        (unless (and (string? x) (> (string-length x) 0))
          (error (string-append "Invalid empty/non-string entry in policy " field-name) x))
        (unless (member x acc) (set! acc (cons x acc))))
      raw)
    (sort-by acc string<?)))

;; Strict loader for declarative `de.attestation.policy.v1` manifests:
;; Enforces POSIX lstat non-symlink regular file, exact schema, strict allowlisted keys
;; (rejecting typos that would silently disable controls), and valid field types.
(def (load-audit-policy-json policy-path)
  (unless (and (string? policy-path) (> (string-length policy-path) 0))
    (error "Invalid audit policy path" policy-path))
  (let ((ftype (with-catch (lambda (_) #f)
                 (lambda () (file-info-type (file-info policy-path #f))))))
    (unless (eq? ftype 'regular)
      (error "Audit policy must be an existing regular non-symlink file" policy-path)))
  (def doc (call-with-input-file policy-path (cut read-json <> object-as-hash: #t)))
  (unless (and (hash-table? doc)
               (equal? (hash-get doc "schema") *audit-policy-schema*))
    (error "Invalid audit policy schema (expected de.attestation.policy.v1)" policy-path))
  (hash-for-each
    (lambda (k _v)
      (unless (member k *audit-policy-allowed-keys*)
        (error "Unknown key in audit policy manifest (fail-closed typo guard)" k policy-path)))
    doc)
  (def exp-sysml (hash-get doc "expectedSysmlSha256"))
  (when exp-sysml
    (unless (and (string? exp-sysml) (> (string-length exp-sysml) 0))
      (error "Policy expectedSysmlSha256 must be a non-empty string" exp-sysml)))
  (def exp-cnt (hash-get doc "expectedSubjectCount"))
  (when exp-cnt
    (unless (and (exact-integer? exp-cnt) (>= exp-cnt 1))
      (error "Policy expectedSubjectCount must be a positive integer" exp-cnt)))
  (def min-sigs (hash-get doc "minSignatures"))
  (when min-sigs
    (unless (and (exact-integer? min-sigs) (>= min-sigs 1))
      (error "Policy minSignatures must be a positive integer" min-sigs)))
  (def req-subs (if (hash-key? doc "requiredSubjects")
                  (validate-policy-string-list "requiredSubjects" (hash-get doc "requiredSubjects"))
                  '()))
  (def req-signers (if (hash-key? doc "requiredSigners")
                     (validate-policy-string-list "requiredSigners" (hash-get doc "requiredSigners"))
                     '()))
  (def req-roles (if (hash-key? doc "requiredRoles")
                   (validate-policy-string-list "requiredRoles" (hash-get doc "requiredRoles"))
                   '()))
  (hash ("expectedSysmlSha256" exp-sysml)
        ("expectedSubjectCount" exp-cnt)
        ("requiredSubjects" req-subs)
        ("minSignatures" min-sigs)
        ("requiredSigners" req-signers)
        ("requiredRoles" req-roles)))

(def (union-sorted-strings a b)
  (let ((acc '()))
    (for-each (lambda (x) (unless (member x acc) (set! acc (cons x acc)))) a)
    (for-each (lambda (x) (unless (member x acc) (set! acc (cons x acc)))) b)
    (sort-by acc string<?)))

;; Monotonic policy tightening merge: CLI flags can ONLY tighten (never weaken) a loaded policy!
(def (merge-audit-policy-strict policy-ht cli-sysml cli-cnt cli-subs cli-min-sigs cli-signers cli-roles)
  (if (not policy-ht)
    (values cli-sysml cli-cnt cli-subs (or cli-min-sigs 1) cli-signers cli-roles)
    (let* ((p-sysml (hash-get policy-ht "expectedSysmlSha256"))
           (p-cnt (hash-get policy-ht "expectedSubjectCount"))
           (p-min (hash-get policy-ht "minSignatures"))
           (eff-sysml
             (cond
              ((and p-sysml cli-sysml (not (equal? p-sysml cli-sysml)))
               (error "CLI --expected-sysml-sha256 conflicts with policy expectedSysmlSha256"
                      cli-sysml p-sysml))
              (else (or cli-sysml p-sysml))))
           (eff-cnt
             (cond
              ((and p-cnt cli-cnt (not (= p-cnt cli-cnt)))
               (error "CLI --expected-subject-count conflicts with policy expectedSubjectCount"
                      cli-cnt p-cnt))
              (else (or cli-cnt p-cnt))))
           (eff-min
             (cond
              ((and p-min cli-min-sigs (< cli-min-sigs p-min))
               (error "Refusing to weaken policy minSignatures via CLI --min-signatures"
                      cli-min-sigs p-min))
              ((and p-min cli-min-sigs) (max p-min cli-min-sigs))
              (else (or cli-min-sigs p-min 1)))))
      (values eff-sysml
              eff-cnt
              (union-sorted-strings (or (hash-get policy-ht "requiredSubjects") '()) cli-subs)
              eff-min
              (union-sorted-strings (or (hash-get policy-ht "requiredSigners") '()) cli-signers)
              (union-sorted-strings (or (hash-get policy-ht "requiredRoles") '()) cli-roles)))))

(def (verify-report-doc-offline doc trust-pair)
  (and (hash-table? doc)
       (let* ((trusted (trust-pair-trusted trust-pair))
              (revoked (trust-pair-revoked trust-pair))
              (att (hash-get doc "attestation"))
              (kid (and (hash-table? att) (hash-get att "keyId")))
              (pub (trust-store-alist-key-admitted? trusted revoked kid)))
         (and pub
              (equal? (hash-get att "algorithm") "Ed25519")
              (eq? (hash-get doc "replayValid") #t)
              (equal? (hash-get doc "mrFindings") '())
              (equal? (hash-get doc "mrOpenPremises") '())
              (equal? (hash-get doc "erFindings") '())
              (pair? (hash-get doc "verificationAdmitted"))
              (let* ((sig (hash-get att "signature"))
                     (expected-sha (hash-get att "payloadSha256"))
                     (admitted-flat
                       (map (lambda (r) (if (pair? r) (car r) r))
                            (or (hash-get doc "verificationAdmitted") '())))
                     (ev-rows
                       (map (lambda (e)
                              (list (or (hash-get e "step") "")
                                    (or (hash-get e "obligation") "")
                                    (or (hash-get e "method") "")
                                    (or (hash-get e "claimKind") "")
                                    (or (hash-get e "outcome") "")
                                    (or (hash-get e "detail") "")))
                            (or (hash-get doc "evidence") '())))
                     (tc-pairs (hash->string-alist (hash-get doc "toolchainFingerprints")))
                     (canonical
                       (canonical-report-signing-payload
                         (or (hash-get doc "subject") "")
                         (or (hash-get doc "requestId") "")
                         (or (hash-get doc "replayStatus") "")
                         #t
                         admitted-flat
                         ev-rows
                         tc-pairs)))
                (and (equal? (sha256-str canonical) expected-sha)
                     (ed25519-verify-raw pub canonical sig)))))))

(def (verify-report-offline report-path trust-pair)
  (and (file-exists? report-path)
       (verify-report-doc-offline
         (call-with-input-file report-path (cut read-json <> object-as-hash: #t))
         trust-pair)))

(def (fleet-subject-coverage-ok? subjects expected-subject-count required-subjects)
  (let loop ((xs subjects) (seen '()))
    (if (null? xs)
      (and (or (not expected-subject-count)
               (and (exact-integer? expected-subject-count)
                    (>= expected-subject-count 1)
                    (= (length seen) expected-subject-count)))
           (andmap (lambda (req) (and (member req seen) #t)) required-subjects))
      (let* ((s (car xs))
             (skey (and (hash-table? s) (hash-get s "subjectKey"))))
        (and (string? skey)
             (> (string-length skey) 0)
             (not (member skey seen))
             (loop (cdr xs) (cons skey seen)))))))

(def (verify-fleet-offline
       fleet-report-path
       trust-pair
       expected-sysml-sha256: (expected-sysml-sha256 #f)
       expected-subject-count: (expected-subject-count #f)
       required-subjects: (required-subjects '()))
  (and (file-exists? fleet-report-path)
       (let* ((trusted (trust-pair-trusted trust-pair))
              (revoked (trust-pair-revoked trust-pair))
              (doc (call-with-input-file fleet-report-path (cut read-json <> object-as-hash: #t)))
              (att (and (hash-table? doc) (hash-get doc "attestation")))
              (subjects (and (hash-table? doc) (hash-get doc "subjects")))
              (kid (and (hash-table? att) (hash-get att "keyId")))
              (fleet-pub (trust-store-alist-key-admitted? trusted revoked kid)))
         (and fleet-pub
              (or (not expected-sysml-sha256)
                  (equal? (hash-get doc "sysmlSha256") expected-sysml-sha256))
              (list? subjects)
              (pair? subjects)
              (fleet-subject-coverage-ok? subjects expected-subject-count required-subjects)
              (equal? (hash-get att "algorithm") "Ed25519")
              (let* ((expected-sha (hash-get att "payloadSha256"))
                     (sig (hash-get att "signature"))
                     (fleet-dir (path-directory fleet-report-path))
                     (entries
                       (map (lambda (s)
                              (list (or (hash-get s "subjectKey") "")
                                    (or (hash-get s "subjectId") "")
                                    (or (hash-get s "reportPayloadSha256") "")
                                    (eq? (hash-get s "replayValid") #t)
                                    (eq? (hash-get s "admitted") #t)))
                            subjects))
                     (canonical
                       (canonical-fleet-signing-payload
                         (or (hash-get doc "fleetId") "")
                         (or (hash-get doc "sysmlSha256") "")
                         entries)))
                (and (equal? (sha256-str canonical) expected-sha)
                     (ed25519-verify-raw fleet-pub canonical sig)
                     (andmap
                       (lambda (s)
                         (let* ((rel (hash-get s "reportRelativePath"))
                                (child-path (resolve-contained-child-report-path fleet-dir rel))
                                (expected-child-sha (hash-get s "reportPayloadSha256")))
                           (and child-path
                                (verify-report-offline child-path trust-pair)
                                (let* ((cdoc (call-with-input-file child-path
                                               (cut read-json <> object-as-hash: #t)))
                                       (catt (and (hash-table? cdoc) (hash-get cdoc "attestation"))))
                                  (and (hash-table? catt)
                                       (equal? (hash-get catt "payloadSha256") expected-child-sha))))))
                       subjects)))))))

;; Verifies EVERY witness entry in a signed `verification-cache.v1.json` against the Trust Store.
;; Optional anti-replay freshness window (`max-age-seconds`, `now-epoch`, `max-future-skew-seconds`):
;; when `max-age-seconds` is set, rejects expired witnesses AND future-dated clock forgeries.
;; Returns verified entry count (exact integer) on full pass, or `#f` if any entry is invalid/revoked/stale.
(def (verify-cache-offline
       cache-path
       trust-pair
       max-age-seconds: (max-age-seconds #f)
       now-epoch: (now-epoch #f)
       max-future-skew-seconds: (max-future-skew-seconds 60))
  (def effective-now
    (or now-epoch (inexact->exact (floor (time->seconds (current-time))))))
  (and (file-exists? cache-path)
       (let* ((trusted (trust-pair-trusted trust-pair))
              (revoked (trust-pair-revoked trust-pair))
              (doc (call-with-input-file cache-path (cut read-json <> object-as-hash: #t)))
              (entries (and (hash-table? doc) (hash-get doc "entries"))))
         (and (hash-table? entries)
              (let ((all-ok? #t)
                    (count 0))
                (hash-for-each
                  (lambda (step-str rec)
                    (set! count (+ count 1))
                    (unless (and (hash-table? rec)
                                 (let* ((obl (or (hash-get rec "obligation") ""))
                                        (meth (or (hash-get rec "method") ""))
                                        (ck (or (hash-get rec "claimKind") ""))
                                        (out (or (hash-get rec "outcome") ""))
                                        (det (or (hash-get rec "detail") ""))
                                        (tc (hash-get rec "toolchainFingerprint"))
                                        (issued (hash-get rec "issuedAtEpoch"))
                                        (kid (hash-get rec "keyId"))
                                        (sig (hash-get rec "signature"))
                                        (dig-pairs (hash->string-alist (hash-get rec "inputDigests")))
                                        (pub (trust-store-alist-key-admitted? trusted revoked kid)))
                                   (and pub
                                        (string? tc)
                                        (string? sig)
                                        (witness-epoch-fresh?
                                          issued effective-now max-age-seconds max-future-skew-seconds)
                                        (ed25519-verify-raw
                                          pub
                                          (canonical-witness-signing-payload
                                            step-str obl meth ck out det tc dig-pairs
                                            (if (exact-integer? issued) (number->string issued) ""))
                                          sig))))
                      (set! all-ok? #f)))
                  entries)
                (and all-ok? (> count 0) count))))))

(def (emit-json-result! ok? mode target-path store-path detail-or-reason (extra-pairs '()))
  (def doc
    (hash ("schema" "de.attestation.offline-verify-result.v1")
          ("ok" (and ok? #t))
          ("mode" mode)
          ("target" target-path)
          ("trustStore" store-path)))
  (hash-put! doc (if ok? "detail" "reason") detail-or-reason)
  (for-each (lambda (p) (hash-put! doc (car p) (cdr p))) extra-pairs)
  (write-json (current-output-port) doc)
  (newline))

;; Air-gapped single-file Inline-PEM Trust Bundle exporter.
;; Enforces:
;;   1. Every input key file is an existing POSIX lstat regular non-symlink file.
;;   2. Every input file begins with `"-----BEGIN PUBLIC KEY-----"` (rejects private keys!).
;;   3. Exact content-derived `keyId = sha256(pem)[:16]` binding.
;;   4. At least one active (unrevoked) key remains (rejects zero-active lockout bundles).
;; Returns `(cons active-key-ids-sorted revoked-key-ids-sorted)`.
(def (export-trust-bundle-offline out-path pub-paths (revoked-key-ids '()) (role-bindings '()))
  (unless (and (string? out-path) (> (string-length out-path) 0))
    (error "Invalid output trust bundle path" out-path))
  (unless (pair? pub-paths)
    (error "At least one public key PEM path is required to export a trust bundle"))
  (def cwd (current-directory))
  (def keys-ht (make-hash-table))
  (def all-kids '())
  (for-each
    (lambda (raw-path)
      (let* ((resolved (resolve-trusted-pem-path cwd raw-path))
             (pem-str (call-with-input-file resolved read-all-as-string)))
        (unless (inline-pem-string? pem-str)
          (error "Refusing to bundle non-public-key PEM (private keys and malformed PEMs are rejected)"
                 raw-path))
        (let ((kid (substring (sha256-str pem-str) 0 16)))
          (hash-put! keys-ht kid pem-str)
          (unless (member kid all-kids)
            (set! all-kids (cons kid all-kids))))))
    pub-paths)
  (def revoked-clean
    (let ((acc '()))
      (for-each
        (lambda (r)
          (unless (and (string? r) (> (string-length r) 0))
            (error "Invalid --revoke keyId" r))
          (unless (member r acc) (set! acc (cons r acc))))
        revoked-key-ids)
      (sort-by acc string<?)))
  (def active
    (sort-by (filter (lambda (kid) (not (member kid revoked-clean))) all-kids) string<?))
  (unless (pair? active)
    (error "Refusing to export trust bundle with zero active unrevoked keys"
           revoked-clean))
  (def roles-ht (make-hash-table))
  (for-each
    (lambda (rb)
      (let ((kid (car rb))
            (role (cdr rb)))
        (unless (and (string? kid) (hash-key? keys-ht kid))
          (error "Refusing to assign role to unknown keyId not in exported bundle" kid role))
        (unless (and (string? role) (> (string-length role) 0))
          (error "Invalid empty role name" kid role))
        (let ((prev (or (hash-get roles-ht kid) '())))
          (unless (member role prev)
            (hash-put! roles-ht kid (sort-by (cons role prev) string<?))))))
    role-bindings)
  (def parent-dir (path-directory out-path))
  (when (and (> (string-length parent-dir) 0) (not (file-exists? parent-dir)))
    (create-directory* parent-dir))
  (def doc
    (hash ("schema" "de.attestation.ed25519-trust-store.v1")
          ("trustedKeys" keys-ht)
          ("revokedKeyIds" revoked-clean)))
  (when (> (hash-length roles-ht) 0)
    (hash-put! doc "keyRoles" roles-ht))
  (call-with-output-file out-path
    (lambda (port)
      (write-json port doc)
      (newline port)))
  (cons active revoked-clean))

;; Packs a 2-level Merkle Fleet report + ALL contained child reports into a single
;; self-contained `de.attestation.fleet-evidence-bundle.v1` JSON archive.
(def (pack-fleet-bundle-offline fleet-report-path out-path)
  (unless (and (string? fleet-report-path) (file-exists? fleet-report-path))
    (error "Fleet report file not found" fleet-report-path))
  (unless (and (string? out-path) (> (string-length out-path) 0))
    (error "Invalid output fleet bundle path" out-path))
  (def fleet-doc (call-with-input-file fleet-report-path (cut read-json <> object-as-hash: #t)))
  (def subjects (and (hash-table? fleet-doc) (hash-get fleet-doc "subjects")))
  (unless (and (list? subjects) (pair? subjects))
    (error "Invalid or empty fleet report subjects" fleet-report-path))
  (def fleet-dir (path-directory fleet-report-path))
  (def child-reports (make-hash-table))
  (for-each
    (lambda (s)
      (unless (hash-table? s)
        (error "Malformed subject entry in fleet report"))
      (let* ((rel (hash-get s "reportRelativePath"))
             (child-path (resolve-contained-child-report-path fleet-dir rel)))
        (unless (and child-path (string? rel))
          (error "Refusing to pack uncontained/symlink/missing child report" rel))
        (when (hash-key? child-reports rel)
          (error "Duplicate child reportRelativePath in fleet report" rel))
        (let* ((cdoc (call-with-input-file child-path (cut read-json <> object-as-hash: #t)))
               (catt (and (hash-table? cdoc) (hash-get cdoc "attestation"))))
          (unless (and (hash-table? catt)
                       (equal? (hash-get catt "payloadSha256")
                               (hash-get s "reportPayloadSha256")))
            (error "Child report Merkle payloadSha256 mismatch while packing" rel))
          (hash-put! child-reports rel cdoc))))
    subjects)
  (def parent-dir (path-directory out-path))
  (when (and (> (string-length parent-dir) 0) (not (file-exists? parent-dir)))
    (create-directory* parent-dir))
  (def bundle
    (hash ("schema" "de.attestation.fleet-evidence-bundle.v1")
          ("fleetReport" fleet-doc)
          ("childReports" child-reports)))
  (call-with-output-file out-path
    (lambda (port)
      (write-json port bundle)
      (newline port)))
  (length subjects))

;; Pure zero-disk-traversal verifier returning a cryptographically authenticated audit summary
;; hash-table on full pass, or `#f` on any failure (never leaks unverified metadata).
(def (inspect-fleet-bundle-verified
       bundle-path
       trust-pair
       expected-sysml-sha256: (expected-sysml-sha256 #f)
       expected-subject-count: (expected-subject-count #f)
       required-subjects: (required-subjects '()))
  (and (file-exists? bundle-path)
       (let* ((trusted (trust-pair-trusted trust-pair))
              (revoked (trust-pair-revoked trust-pair))
              (bundle (call-with-input-file bundle-path (cut read-json <> object-as-hash: #t)))
              (fleet-doc (and (hash-table? bundle)
                              (equal? (hash-get bundle "schema")
                                      "de.attestation.fleet-evidence-bundle.v1")
                              (hash-get bundle "fleetReport")))
              (child-reports (and (hash-table? bundle) (hash-get bundle "childReports")))
              (att (and (hash-table? fleet-doc) (hash-get fleet-doc "attestation")))
              (subjects (and (hash-table? fleet-doc) (hash-get fleet-doc "subjects")))
              (kid (and (hash-table? att) (hash-get att "keyId")))
              (fleet-pub (trust-store-alist-key-admitted? trusted revoked kid)))
         (and fleet-pub
              (string? kid)
              (or (not expected-sysml-sha256)
                  (equal? (hash-get fleet-doc "sysmlSha256") expected-sysml-sha256))
              (hash-table? child-reports)
              (list? subjects)
              (pair? subjects)
              (fleet-subject-coverage-ok? subjects expected-subject-count required-subjects)
              (= (hash-length child-reports) (length subjects))
              (equal? (hash-get att "algorithm") "Ed25519")
              (let* ((expected-sha (hash-get att "payloadSha256"))
                     (sig (hash-get att "signature"))
                     (fleet-id (or (hash-get fleet-doc "fleetId") ""))
                     (sysml-sha (or (hash-get fleet-doc "sysmlSha256") ""))
                     (entries
                       (map (lambda (s)
                              (list (or (hash-get s "subjectKey") "")
                                    (or (hash-get s "subjectId") "")
                                    (or (hash-get s "reportPayloadSha256") "")
                                    (eq? (hash-get s "replayValid") #t)
                                    (eq? (hash-get s "admitted") #t)))
                            subjects))
                     (canonical
                       (canonical-fleet-signing-payload fleet-id sysml-sha entries))
                     (seen-rels '())
                     (summaries '()))
                (and (equal? (sha256-str canonical) expected-sha)
                     (ed25519-verify-raw fleet-pub canonical sig)
                     (andmap
                       (lambda (s)
                         (let* ((rel (and (hash-table? s) (hash-get s "reportRelativePath")))
                                (expected-child-sha (and (hash-table? s) (hash-get s "reportPayloadSha256")))
                                (cdoc (and (safe-relative-child-path? rel)
                                           (not (member rel seen-rels))
                                           (hash-key? child-reports rel)
                                           (hash-get child-reports rel))))
                           (when (and cdoc (string? rel))
                             (set! seen-rels (cons rel seen-rels)))
                           (and (hash-table? cdoc)
                                (verify-report-doc-offline cdoc trust-pair)
                                (let* ((catt (hash-get cdoc "attestation"))
                                       (ckid (and (hash-table? catt) (hash-get catt "keyId")))
                                       (cev (or (hash-get cdoc "evidence") '())))
                                  (and (hash-table? catt)
                                       (string? ckid)
                                       (equal? (hash-get catt "payloadSha256") expected-child-sha)
                                       (begin
                                         (set! summaries
                                           (cons (hash ("subjectKey" (or (hash-get s "subjectKey") ""))
                                                       ("subjectId" (or (hash-get s "subjectId") ""))
                                                       ("keyId" ckid)
                                                       ("evidenceCount" (if (list? cev) (length cev) 0)))
                                                 summaries))
                                         #t))))))
                       subjects)
                     (= (length seen-rels) (hash-length child-reports))
                     (let ((sorted-subs
                            (sort-by summaries
                                     (lambda (a b)
                                       (string<? (hash-get a "subjectKey")
                                                 (hash-get b "subjectKey"))))))
                       (hash ("fleetId" fleet-id)
                             ("sysmlSha256" sysml-sha)
                             ("fleetPayloadSha256" expected-sha)
                             ("rootKeyId" kid)
                             ("subjectCount" (length sorted-subs))
                             ("verifiedSubjects" sorted-subs)))))))))

(def (build-intoto-verification-statement summary)
  (def fleet-id (hash-get summary "fleetId"))
  (def sysml-sha (hash-get summary "sysmlSha256"))
  (def fleet-sha (hash-get summary "fleetPayloadSha256"))
  (hash ("_type" "https://in-toto.io/Statement/v1")
        ("subject"
         (list (hash ("name" "sysml:10.154-multi-method-funflow-runnable-architecture")
                     ("digest" (hash ("sha256" sysml-sha))))
               (hash ("name" (string-append "fleet:" fleet-id))
                     ("digest" (hash ("sha256" fleet-sha))))))
        ("predicateType"
         "https://deterministic-engineering.hardenedlinux.org/attestation/fleet-verification-summary/v1")
        ("predicate"
         (hash ("verifier" "de.offline-attestation-verifier.v1")
               ("fleetId" fleet-id)
               ("sysmlSha256" sysml-sha)
               ("fleetPayloadSha256" fleet-sha)
               ("rootKeyId" (hash-get summary "rootKeyId"))
               ("subjectCount" (hash-get summary "subjectCount"))
               ("verifiedSubjects" (hash-get summary "verifiedSubjects"))))))

;; Fail-closed safe writer for `--emit-statement <out.json>`:
;; Rejects symlink targets and symlinked parent directories (preserving macOS `/tmp` & `/var`).
(def (assert-safe-statement-output-path! out-path)
  (unless (and (string? out-path) (> (string-length out-path) 0))
    (error "Invalid --emit-statement output path" out-path))
  (let ((leaf-type (with-catch (lambda (_) #f)
                     (lambda () (file-info-type (file-info out-path #f))))))
    (when (and leaf-type (not (eq? leaf-type 'regular)))
      (error "Refusing to write in-toto statement to symlink or non-regular path" out-path)))
  (let* ((raw-parent (path-directory out-path))
         (parent (if (and (> (string-length raw-parent) 1)
                          (char=? (string-ref raw-parent (- (string-length raw-parent) 1)) #\/))
                   (substring raw-parent 0 (- (string-length raw-parent) 1))
                   raw-parent)))
    (when (and (> (string-length parent) 0)
               (not (member parent '("/" "/tmp" "/var"))))
      (let ((ptype (with-catch (lambda (_) #f)
                     (lambda () (file-info-type (file-info parent #f))))))
        (when (and ptype (not (eq? ptype 'directory)))
          (error "Refusing to write in-toto statement inside symlinked or non-directory parent"
                 parent))))))

(def (emit-intoto-verification-statement! out-path summary)
  (unless (hash-table? summary)
    (error "Refusing to emit in-toto statement without verified fleet summary"))
  (assert-safe-statement-output-path! out-path)
  (def parent-dir (path-directory out-path))
  (when (and (> (string-length parent-dir) 0) (not (file-exists? parent-dir)))
    (create-directory* parent-dir))
  (def stmt (build-intoto-verification-statement summary))
  (call-with-output-file out-path
    (lambda (port)
      (write-json port stmt)
      (newline port)))
  stmt)

(def (verify-fleet-bundle-offline
       bundle-path
       trust-pair
       expected-sysml-sha256: (expected-sysml-sha256 #f)
       expected-subject-count: (expected-subject-count #f)
       required-subjects: (required-subjects '()))
  (and (inspect-fleet-bundle-verified bundle-path trust-pair
         expected-sysml-sha256: expected-sysml-sha256
         expected-subject-count: expected-subject-count
         required-subjects: required-subjects)
       #t))

(def *intoto-dsse-payload-type* "application/vnd.in-toto+json")
(def *intoto-statement-type* "https://in-toto.io/Statement/v1")
(def *intoto-predicate-type*
  "https://deterministic-engineering.hardenedlinux.org/attestation/fleet-verification-summary/v1")
(def *intoto-sysml-subject-name* "sysml:10.154-multi-method-funflow-runnable-architecture")

(def (intoto-subject-digest-matches? subjects target-name expected-sha)
  (and (list? subjects)
       (string? expected-sha)
       (> (string-length expected-sha) 0)
       (let loop ((xs subjects))
         (if (null? xs)
           #f
           (let* ((s (car xs))
                  (nm (and (hash-table? s) (hash-get s "name")))
                  (dig (and (hash-table? s) (hash-get s "digest")))
                  (sha (and (hash-table? dig) (hash-get dig "sha256"))))
             (if (and (equal? nm target-name) (equal? sha expected-sha))
               #t
               (loop (cdr xs))))))))

;; Strict offline verifier for a standard DSSE v1 signed in-toto Verification Summary Statement.
;; Enforces:
;;   1. Exact `payloadType == "application/vnd.in-toto+json"` (blocks type confusion).
;;   2. Strict Base64 decoding & valid UTF-8 JSON in-toto v1 Statement schema.
;;   3. At least one valid Ed25519 signature over DSSE v1 PAE from an admitted unrevoked key in Trust Store.
;;   4. Exact digest agreement between `subject` bindings (`sysml:...` and `fleet:...`) and `predicate`.
;;   5. Optional anti-downgrade `--expected-sysml-sha256` & subject-coverage completeness gates.
;; Returns authenticated summary hash-table on pass, or `#f` on any failure (zero leakage).
(def (collect-verified-roles verified-kids key-roles-ht)
  (def roles '())
  (when (hash-table? key-roles-ht)
    (for-each
      (lambda (kid)
        (for-each
          (lambda (r)
            (when (and (string? r) (> (string-length r) 0) (not (member r roles)))
              (set! roles (cons r roles))))
          (or (hash-get key-roles-ht kid) '())))
      verified-kids))
  (sort-by roles string<?))

(def (inspect-dsse-statement-verified
       dsse-path
       trust-pair
       expected-sysml-sha256: (expected-sysml-sha256 #f)
       expected-subject-count: (expected-subject-count #f)
       required-subjects: (required-subjects '())
       min-signatures: (min-signatures 1)
       required-signers: (required-signers '())
       required-roles: (required-roles '()))
  (and (file-exists? dsse-path)
       (exact-integer? min-signatures)
       (>= min-signatures 1)
       (let* ((trusted (trust-pair-trusted trust-pair))
              (revoked (trust-pair-revoked trust-pair))
              (key-roles (trust-pair-key-roles trust-pair))
              (env (with-catch (lambda (_) #f)
                     (lambda () (call-with-input-file dsse-path (cut read-json <> object-as-hash: #t)))))
              (ptype (and (hash-table? env) (hash-get env "payloadType")))
              (payload-b64 (and (hash-table? env) (hash-get env "payload")))
              (sigs (and (hash-table? env) (hash-get env "signatures"))))
         (and (equal? ptype *intoto-dsse-payload-type*)
              (string? payload-b64)
              (> (string-length payload-b64) 0)
              (list? sigs)
              (pair? sigs)
              (let* ((payload-bytes (with-catch (lambda (_) #f) (lambda () (base64-decode payload-b64))))
                     (payload-str (and (u8vector? payload-bytes)
                                       (with-catch (lambda (_) #f) (lambda () (utf8->string payload-bytes)))))
                     (pae (and (string? payload-str) (dsse-v1-pae ptype payload-str))))
                (and (string? pae)
                     (let ((verified-kids '()))
                       (for-each
                         (lambda (sig-entry)
                           (when (hash-table? sig-entry)
                             (let* ((kid (hash-get sig-entry "keyid"))
                                    (sig-b64 (hash-get sig-entry "sig"))
                                    (pub (trust-store-alist-key-admitted? trusted revoked kid)))
                               (when (and pub
                                          (string? kid)
                                          (string? sig-b64)
                                          (ed25519-verify-raw pub pae sig-b64)
                                          (not (member kid verified-kids)))
                                 (set! verified-kids (cons kid verified-kids))))))
                         sigs)
                       (let ((verified-roles (collect-verified-roles verified-kids key-roles)))
                         (and (>= (length verified-kids) min-signatures)
                              (andmap (lambda (req) (and (member req verified-kids) #t)) required-signers)
                              (andmap (lambda (req) (and (member req verified-roles) #t)) required-roles)
                              (let ((stmt (with-catch (lambda (_) #f)
                                            (lambda () (call-with-input-string payload-str
                                                         (cut read-json <> object-as-hash: #t))))))
                                (and (hash-table? stmt)
                                     (equal? (hash-get stmt "_type") *intoto-statement-type*)
                                     (equal? (hash-get stmt "predicateType") *intoto-predicate-type*)
                                     (let* ((subjects (hash-get stmt "subject"))
                                            (pred (hash-get stmt "predicate"))
                                            (fleet-id (and (hash-table? pred) (hash-get pred "fleetId")))
                                            (sysml-sha (and (hash-table? pred) (hash-get pred "sysmlSha256")))
                                            (fleet-sha (and (hash-table? pred) (hash-get pred "fleetPayloadSha256")))
                                            (root-kid (and (hash-table? pred) (hash-get pred "rootKeyId")))
                                            (sub-cnt (and (hash-table? pred) (hash-get pred "subjectCount")))
                                            (ver-subs (and (hash-table? pred) (hash-get pred "verifiedSubjects"))))
                                       (and (hash-table? pred)
                                            (equal? (hash-get pred "verifier") "de.offline-attestation-verifier.v1")
                                            (string? fleet-id) (> (string-length fleet-id) 0)
                                            (string? sysml-sha) (> (string-length sysml-sha) 0)
                                            (string? fleet-sha) (> (string-length fleet-sha) 0)
                                            (string? root-kid) (> (string-length root-kid) 0)
                                            (exact-integer? sub-cnt) (>= sub-cnt 1)
                                            (list? ver-subs) (= (length ver-subs) sub-cnt)
                                            (intoto-subject-digest-matches?
                                              subjects *intoto-sysml-subject-name* sysml-sha)
                                            (intoto-subject-digest-matches?
                                              subjects (string-append "fleet:" fleet-id) fleet-sha)
                                            (or (not expected-sysml-sha256)
                                                (equal? sysml-sha expected-sysml-sha256))
                                            (fleet-subject-coverage-ok?
                                              ver-subs expected-subject-count required-subjects)
                                            (hash ("fleetId" fleet-id)
                                                  ("sysmlSha256" sysml-sha)
                                                  ("fleetPayloadSha256" fleet-sha)
                                                  ("rootKeyId" root-kid)
                                                  ("verifiedKeyIds" (sort-by verified-kids string<?))
                                                  ("verifiedRoles" verified-roles)
                                                  ("subjectCount" sub-cnt)
                                                  ("verifiedSubjects" ver-subs)))))))))))))))

(def (verify-dsse-statement-offline
       dsse-path
       trust-pair
       expected-sysml-sha256: (expected-sysml-sha256 #f)
       expected-subject-count: (expected-subject-count #f)
       required-subjects: (required-subjects '())
       min-signatures: (min-signatures 1)
       required-signers: (required-signers '())
       required-roles: (required-roles '()))
  (and (inspect-dsse-statement-verified dsse-path trust-pair
         expected-sysml-sha256: expected-sysml-sha256
         expected-subject-count: expected-subject-count
         required-subjects: required-subjects
         min-signatures: min-signatures
         required-signers: required-signers
         required-roles: required-roles)
       #t))

;; Air-gapped offline DSSE v1 counter-signer (`--cosign-dsse-statement`):
;; Verifies the input DSSE envelope first, validates non-symlink keypair & active admission in
;; `trust-pair`, signs DSSE v1 PAE, self-verifies against `pub-path`, deduplicates `keyid`,
;; and writes `out-path` (refusing symlink targets).
(def (cosign-dsse-statement-offline
       in-dsse-path
       priv-path
       pub-path
       trust-pair
       out-path
       expected-sysml-sha256: (expected-sysml-sha256 #f)
       expected-subject-count: (expected-subject-count #f)
       required-subjects: (required-subjects '()))
  (def pre-summary
    (inspect-dsse-statement-verified in-dsse-path trust-pair
      expected-sysml-sha256: expected-sysml-sha256
      expected-subject-count: expected-subject-count
      required-subjects: required-subjects))
  (unless pre-summary
    (error "Refusing to cosign unverified or policy-failing DSSE envelope" in-dsse-path))
  (assert-safe-statement-output-path! out-path)
  (def cwd (current-directory))
  (def resolved-priv (resolve-trusted-pem-path cwd priv-path))
  (def resolved-pub (resolve-trusted-pem-path cwd pub-path))
  (def pub-pem (call-with-input-file resolved-pub read-all-as-string))
  (unless (inline-pem-string? pub-pem)
    (error "Cosigner public key must be a valid PUBLIC KEY PEM" pub-path))
  (def cosigner-kid (substring (sha256-str pub-pem) 0 16))
  (def admitted-pub (trust-store-alist-key-admitted? (trust-pair-trusted trust-pair) (trust-pair-revoked trust-pair) cosigner-kid))
  (unless admitted-pub
    (error "Refusing to cosign with untrusted or revoked keyId" cosigner-kid))
  (def env (call-with-input-file in-dsse-path (cut read-json <> object-as-hash: #t)))
  (def ptype (hash-get env "payloadType"))
  (def payload-b64 (hash-get env "payload"))
  (def payload-str (utf8->string (base64-decode payload-b64)))
  (def pae (dsse-v1-pae ptype payload-str))
  (def new-sig (ed25519-sign-raw resolved-priv pae))
  (unless (ed25519-verify-raw pub-pem pae new-sig)
    (error "Cosigner private/public keypair mismatch (self-verification failed)" cosigner-kid))
  (def kept-sigs
    (filter (lambda (entry)
              (and (hash-table? entry)
                   (not (equal? (hash-get entry "keyid") cosigner-kid))))
            (or (hash-get env "signatures") '())))
  (def next-sigs
    (append kept-sigs (list (hash ("keyid" cosigner-kid) ("sig" new-sig)))))
  (def next-env
    (hash ("payloadType" ptype)
          ("payload" payload-b64)
          ("signatures" next-sigs)))
  (def parent-dir (path-directory out-path))
  (when (and (> (string-length parent-dir) 0) (not (file-exists? parent-dir)))
    (create-directory* parent-dir))
  (call-with-output-file out-path
    (lambda (port)
      (write-json port next-env)
      (newline port)))
  (def post-summary
    (inspect-dsse-statement-verified out-path trust-pair
      expected-sysml-sha256: expected-sysml-sha256
      expected-subject-count: expected-subject-count
      required-subjects: required-subjects))
  (unless post-summary
    (error "Post-cosign DSSE self-verification failed" out-path))
  (hash ("cosignerKeyId" cosigner-kid)
        ("verifiedKeyIds" (hash-get post-summary "verifiedKeyIds"))
        ("signatureCount" (length next-sigs))))

(def (parse-role-binding raw)
  (let* ((len (if (string? raw) (string-length raw) 0))
         (idx (let loop ((i 0))
                (cond ((>= i len) #f)
                      ((char=? (string-ref raw i) #\=) i)
                      (else (loop (+ i 1)))))))
    (unless (and idx (> idx 0) (< (+ idx 1) len))
      (error "--role requires <keyId>=<role> format" raw))
    (cons (substring raw 0 idx) (substring raw (+ idx 1) len))))

(def (parse-export-bundle-args rest)
  (let loop ((xs rest) (revoked '()) (roles '()) (pubs '()))
    (cond
     ((null? xs) (values (reverse pubs) (reverse revoked) (reverse roles)))
     ((equal? (car xs) "--revoke")
      (unless (pair? (cdr xs))
        (error "--revoke requires a keyId argument"))
      (loop (cddr xs) (cons (cadr xs) revoked) roles pubs))
     ((equal? (car xs) "--role")
      (unless (pair? (cdr xs))
        (error "--role requires a <keyId>=<role> argument"))
      (loop (cddr xs) revoked (cons (parse-role-binding (cadr xs)) roles) pubs))
     (else
      (loop (cdr xs) revoked roles (cons (car xs) pubs))))))

(def (parse-nonneg-int-flag flag-name raw)
  (let ((n (and (string? raw) (string->number raw))))
    (unless (and (exact-integer? n) (>= n 0))
      (error (string-append flag-name " requires a non-negative integer") raw))
    n))

(def (extract-global-cli-flags args)
  (let loop ((xs args) (json? #f) (max-age #f) (now-ep #f) (max-skew 60)
             (exp-sysml #f) (exp-cnt #f) (req-subs '()) (emit-stmt #f) (min-sigs #f)
             (req-signers '()) (req-roles '()) (policy-path #f) (pos '()))
    (cond
     ((null? xs)
      (values json? max-age now-ep max-skew exp-sysml exp-cnt (reverse req-subs) emit-stmt min-sigs
              (reverse req-signers) (reverse req-roles) policy-path (reverse pos)))
     ((equal? (car xs) "--json")
      (loop (cdr xs) #t max-age now-ep max-skew exp-sysml exp-cnt req-subs emit-stmt min-sigs req-signers req-roles policy-path pos))
     ((equal? (car xs) "--max-age-seconds")
      (unless (pair? (cdr xs)) (error "--max-age-seconds requires an integer argument"))
      (loop (cddr xs) json? (parse-nonneg-int-flag "--max-age-seconds" (cadr xs)) now-ep max-skew exp-sysml exp-cnt req-subs emit-stmt min-sigs req-signers req-roles policy-path pos))
     ((equal? (car xs) "--now-epoch")
      (unless (pair? (cdr xs)) (error "--now-epoch requires an integer argument"))
      (loop (cddr xs) json? max-age (parse-nonneg-int-flag "--now-epoch" (cadr xs)) max-skew exp-sysml exp-cnt req-subs emit-stmt min-sigs req-signers req-roles policy-path pos))
     ((equal? (car xs) "--max-future-skew-seconds")
      (unless (pair? (cdr xs)) (error "--max-future-skew-seconds requires an integer argument"))
      (loop (cddr xs) json? max-age now-ep (parse-nonneg-int-flag "--max-future-skew-seconds" (cadr xs)) exp-sysml exp-cnt req-subs emit-stmt min-sigs req-signers req-roles policy-path pos))
     ((equal? (car xs) "--expected-sysml-sha256")
      (unless (and (pair? (cdr xs)) (string? (cadr xs)) (> (string-length (cadr xs)) 0))
        (error "--expected-sysml-sha256 requires a non-empty digest argument"))
      (loop (cddr xs) json? max-age now-ep max-skew (cadr xs) exp-cnt req-subs emit-stmt min-sigs req-signers req-roles policy-path pos))
     ((equal? (car xs) "--expected-subject-count")
      (unless (pair? (cdr xs)) (error "--expected-subject-count requires an integer argument"))
      (let ((n (parse-nonneg-int-flag "--expected-subject-count" (cadr xs))))
        (unless (>= n 1) (error "--expected-subject-count must be >= 1" n))
        (loop (cddr xs) json? max-age now-ep max-skew exp-sysml n req-subs emit-stmt min-sigs req-signers req-roles policy-path pos)))
     ((equal? (car xs) "--require-subject")
      (unless (and (pair? (cdr xs)) (string? (cadr xs)) (> (string-length (cadr xs)) 0))
        (error "--require-subject requires a non-empty subjectKey argument"))
      (let ((next-req (if (member (cadr xs) req-subs) req-subs (cons (cadr xs) req-subs))))
        (loop (cddr xs) json? max-age now-ep max-skew exp-sysml exp-cnt next-req emit-stmt min-sigs req-signers req-roles policy-path pos)))
     ((equal? (car xs) "--emit-statement")
      (unless (and (pair? (cdr xs)) (string? (cadr xs)) (> (string-length (cadr xs)) 0))
        (error "--emit-statement requires a non-empty output file path"))
      (loop (cddr xs) json? max-age now-ep max-skew exp-sysml exp-cnt req-subs (cadr xs) min-sigs req-signers req-roles policy-path pos))
     ((equal? (car xs) "--min-signatures")
      (unless (pair? (cdr xs)) (error "--min-signatures requires an integer argument"))
      (let ((n (parse-nonneg-int-flag "--min-signatures" (cadr xs))))
        (unless (>= n 1) (error "--min-signatures must be >= 1" n))
        (loop (cddr xs) json? max-age now-ep max-skew exp-sysml exp-cnt req-subs emit-stmt n req-signers req-roles policy-path pos)))
     ((equal? (car xs) "--require-signer")
      (unless (and (pair? (cdr xs)) (string? (cadr xs)) (> (string-length (cadr xs)) 0))
        (error "--require-signer requires a non-empty keyId argument"))
      (let ((next-signers (if (member (cadr xs) req-signers) req-signers (cons (cadr xs) req-signers))))
        (loop (cddr xs) json? max-age now-ep max-skew exp-sysml exp-cnt req-subs emit-stmt min-sigs next-signers req-roles policy-path pos)))
     ((equal? (car xs) "--require-role")
      (unless (and (pair? (cdr xs)) (string? (cadr xs)) (> (string-length (cadr xs)) 0))
        (error "--require-role requires a non-empty role name"))
      (let ((next-roles (if (member (cadr xs) req-roles) req-roles (cons (cadr xs) req-roles))))
        (loop (cddr xs) json? max-age now-ep max-skew exp-sysml exp-cnt req-subs emit-stmt min-sigs req-signers next-roles policy-path pos)))
     ((equal? (car xs) "--policy")
      (unless (and (pair? (cdr xs)) (string? (cadr xs)) (> (string-length (cadr xs)) 0))
        (error "--policy requires a non-empty policy manifest path"))
      (loop (cddr xs) json? max-age now-ep max-skew exp-sysml exp-cnt req-subs emit-stmt min-sigs req-signers req-roles (cadr xs) pos))
     (else
      (loop (cdr xs) json? max-age now-ep max-skew exp-sysml exp-cnt req-subs emit-stmt min-sigs req-signers req-roles policy-path (cons (car xs) pos))))))

(def (main . args)
  (let-values (((json-mode? max-age-sec now-ep max-skew-sec raw-expected-sysml-sha
                 raw-expected-sub-cnt raw-req-subs emit-stmt-path raw-min-sigs raw-req-signers
                 raw-req-roles policy-path clean-args)
                (extract-global-cli-flags args)))
  (def loaded-policy
    (if policy-path
      (with-catch
        (lambda (e)
          (if json-mode?
            (begin
              (emit-json-result! #f "policy-load" policy-path policy-path
                (string-append "audit policy load failed: " (error-message e)))
              (exit 1))
            (raise e)))
        (lambda () (load-audit-policy-json policy-path)))
      #f))
  (let-values (((expected-sysml-sha expected-sub-cnt req-subs min-sigs req-signers req-roles)
                (with-catch
                  (lambda (e)
                    (if json-mode?
                      (begin
                        (emit-json-result! #f "policy-merge" (or policy-path "") (or policy-path "")
                          (string-append "audit policy merge failed: " (error-message e)))
                        (exit 1))
                      (raise e)))
                  (lambda ()
                    (merge-audit-policy-strict
                      loaded-policy raw-expected-sysml-sha raw-expected-sub-cnt
                      raw-req-subs raw-min-sigs raw-req-signers raw-req-roles)))))
  (when (null? clean-args)
    (error "usage: [--json] --verify-report|--verify-fleet|--verify-fleet-bundle|--verify-cache [--max-age-seconds N] [--now-epoch T] <artifact.json> <trust-store.json> | [--json] --verify-trust-store <trust-store.json> | [--json] --export-trust-bundle <out.json> [--revoke <keyId>]... <pub1.pem>... | [--json] --pack-fleet-bundle <fleet-report.json> <out-bundle.json>"
           args))
  (def mode (car clean-args))
  (cond
   ((equal? mode "--export-trust-bundle")
    (unless (>= (length clean-args) 3)
      (error "usage: [--json] --export-trust-bundle <out.json> [--revoke <keyId>]... <pub1.pem>..." args))
    (let ((out-path (cadr clean-args)))
      (with-catch
        (lambda (e)
          (if json-mode?
            (begin
              (emit-json-result! #f "export-trust-bundle" out-path out-path
                (string-append "export-trust-bundle failed: " (error-message e)))
              (exit 1))
            (raise e)))
        (lambda ()
          (let-values (((pub-paths revoked-ids role-bindings) (parse-export-bundle-args (cddr clean-args))))
            (let* ((res (export-trust-bundle-offline out-path pub-paths revoked-ids role-bindings))
                   (active (car res))
                   (revoked (cdr res)))
              (if json-mode?
                (emit-json-result! #t "export-trust-bundle" out-path out-path
                  "exported-inline-pem-trust-bundle"
                  (list (cons "inlinePem" #t)
                        (cons "activeKeyIds" active)
                        (cons "revokedKeyIds" revoked)))
                (displayln "MULTI-METHOD-EXPORT-TRUST-BUNDLE-OK " out-path
                           " active=" (length active)
                           " revoked=" (length revoked)))))))))
   ((equal? mode "--pack-fleet-bundle")
    (unless (= (length clean-args) 3)
      (error "usage: [--json] --pack-fleet-bundle <fleet-report.json> <out-bundle.json>" args))
    (let ((fleet-path (list-ref clean-args 1))
          (out-path (list-ref clean-args 2)))
      (with-catch
        (lambda (e)
          (if json-mode?
            (begin
              (emit-json-result! #f "pack-fleet-bundle" fleet-path out-path
                (string-append "pack-fleet-bundle failed: " (error-message e)))
              (exit 1))
            (raise e)))
        (lambda ()
          (let ((n (pack-fleet-bundle-offline fleet-path out-path)))
            (if json-mode?
              (emit-json-result! #t "pack-fleet-bundle" fleet-path out-path
                "packed-fleet-evidence-bundle"
                (list (cons "subjects" n)))
              (displayln "MULTI-METHOD-PACK-FLEET-BUNDLE-OK " out-path " subjects=" n)))))))
   ((equal? mode "--cosign-dsse-statement")
    (unless (= (length clean-args) 6)
      (error "usage: [--json] --cosign-dsse-statement <in.dsse.json> <priv.pem> <pub.pem> <trust-store.json> <out.dsse.json>"
             args))
    (let ((in-dsse (list-ref clean-args 1))
          (priv-pem (list-ref clean-args 2))
          (pub-pem (list-ref clean-args 3))
          (store-path (list-ref clean-args 4))
          (out-dsse (list-ref clean-args 5)))
      (with-catch
        (lambda (e)
          (if json-mode?
            (begin
              (emit-json-result! #f "cosign-dsse-statement" in-dsse store-path
                (string-append "cosign-dsse-statement failed: " (error-message e)))
              (exit 1))
            (raise e)))
        (lambda ()
          (let* ((tp (load-trust-store-json-lite store-path))
                 (res (cosign-dsse-statement-offline in-dsse priv-pem pub-pem tp out-dsse
                        expected-sysml-sha256: expected-sysml-sha
                        expected-subject-count: expected-sub-cnt
                        required-subjects: req-subs)))
            (if json-mode?
              (emit-json-result! #t "cosign-dsse-statement" out-dsse store-path
                "cosigned-dsse-v1-intoto-statement"
                (list (cons "cosignerKeyId" (hash-get res "cosignerKeyId"))
                      (cons "verifiedKeyIds" (hash-get res "verifiedKeyIds"))
                      (cons "signatureCount" (hash-get res "signatureCount"))))
              (displayln "MULTI-METHOD-COSIGN-DSSE-STATEMENT-OK " out-dsse
                         " cosigner=" (hash-get res "cosignerKeyId")
                         " verified=" (length (hash-get res "verifiedKeyIds")))))))))
   ((equal? mode "--verify-trust-store")
    (begin
      (unless (= (length clean-args) 2)
        (error "usage: [--json] --verify-trust-store <trust-store.json>" args))
      (let* ((store-path (cadr clean-args))
             (trust-pair
               (with-catch
                 (lambda (e)
                   (if json-mode?
                     (begin
                       (emit-json-result! #f "verify-trust-store" store-path store-path
                         (string-append "trust-store load failed: " (error-message e)))
                       (exit 1))
                     (raise e)))
                 (lambda () (load-trust-store-json-lite store-path))))
             (trusted (trust-pair-trusted trust-pair))
             (revoked (sort-by (trust-pair-revoked trust-pair) string<?))
             (key-roles (trust-pair-key-roles trust-pair))
             (active (sort-by
                       (filter (lambda (kid) (not (member kid revoked)))
                               (map car trusted))
                       string<?)))
        (if (pair? active)
          (if json-mode?
            (emit-json-result! #t "verify-trust-store" store-path store-path
              "trust-store-valid-with-active-keys"
              (append
                (list (cons "activeKeyIds" active)
                      (cons "revokedKeyIds" revoked))
                (if (> (hash-length key-roles) 0)
                  (list (cons "keyRoles" key-roles))
                  '())))
            (displayln "MULTI-METHOD-VERIFY-TRUST-STORE-OK " store-path
                       " active=" (length active)
                       " revoked=" (length revoked)))
          (if json-mode?
            (begin
              (emit-json-result! #f "verify-trust-store" store-path store-path
                "trust-store has zero active unrevoked keys"
                (list (cons "activeKeyIds" '())
                      (cons "revokedKeyIds" revoked)))
              (exit 1))
            (error "trust-store has zero active unrevoked keys" store-path))))))
   (else
    (begin
      (unless (= (length clean-args) 3)
        (error "usage: [--json] --verify-report|--verify-fleet|--verify-cache <artifact.json> <trust-store.json>"
               args))
      (let* ((target-path (list-ref clean-args 1))
             (store-path (list-ref clean-args 2))
             (trust-pair
               (with-catch
                 (lambda (e)
                   (if json-mode?
                     (begin
                       (emit-json-result! #f mode target-path store-path
                         (string-append "trust-store load failed: " (error-message e)))
                       (exit 1))
                     (raise e)))
                 (lambda () (load-trust-store-json-lite store-path)))))
        (cond
         ((equal? mode "--verify-report")
          (if (verify-report-offline target-path trust-pair)
            (if json-mode?
              (emit-json-result! #t "verify-report" target-path store-path "authentic-admitted-report")
              (displayln "MULTI-METHOD-VERIFY-REPORT-OK " target-path))
            (if json-mode?
              (begin
                (emit-json-result! #f "verify-report" target-path store-path "offline report verification failed")
                (exit 1))
              (error "offline report verification failed" target-path))))
         ((equal? mode "--verify-fleet")
          (if (verify-fleet-offline target-path trust-pair
                expected-sysml-sha256: expected-sysml-sha
                expected-subject-count: expected-sub-cnt
                required-subjects: req-subs)
            (if json-mode?
              (emit-json-result! #t "verify-fleet" target-path store-path "authentic-2-level-merkle-fleet"
                (append
                  (if expected-sysml-sha (list (cons "expectedSysmlSha256" expected-sysml-sha)) '())
                  (if expected-sub-cnt (list (cons "expectedSubjectCount" expected-sub-cnt)) '())
                  (if (pair? req-subs) (list (cons "requiredSubjects" (sort-by req-subs string<?))) '())))
              (displayln "MULTI-METHOD-VERIFY-FLEET-OK " target-path))
            (if json-mode?
              (begin
                (emit-json-result! #f "verify-fleet" target-path store-path "offline fleet verification failed")
                (exit 1))
              (error "offline fleet verification failed" target-path))))
         ((equal? mode "--verify-fleet-bundle")
          (let ((summary (inspect-fleet-bundle-verified target-path trust-pair
                           expected-sysml-sha256: expected-sysml-sha
                           expected-subject-count: expected-sub-cnt
                           required-subjects: req-subs)))
            (if summary
              (let ((stmt-err #f))
                (when emit-stmt-path
                  (with-catch
                    (lambda (e) (set! stmt-err (error-message e)))
                    (lambda () (emit-intoto-verification-statement! emit-stmt-path summary))))
                (if stmt-err
                  (if json-mode?
                    (begin
                      (emit-json-result! #f "verify-fleet-bundle" target-path store-path
                        (string-append "statement export failed: " stmt-err))
                      (exit 1))
                    (error (string-append "statement export failed: " stmt-err) emit-stmt-path))
                  (if json-mode?
                    (emit-json-result! #t "verify-fleet-bundle" target-path store-path
                      "authentic-self-contained-fleet-bundle"
                      (append
                        (if expected-sysml-sha (list (cons "expectedSysmlSha256" expected-sysml-sha)) '())
                        (if expected-sub-cnt (list (cons "expectedSubjectCount" expected-sub-cnt)) '())
                        (if (pair? req-subs) (list (cons "requiredSubjects" (sort-by req-subs string<?))) '())
                        (if emit-stmt-path (list (cons "statementPath" emit-stmt-path)) '())
                        (list (cons "fleetId" (hash-get summary "fleetId"))
                              (cons "sysmlSha256" (hash-get summary "sysmlSha256"))
                              (cons "fleetPayloadSha256" (hash-get summary "fleetPayloadSha256"))
                              (cons "rootKeyId" (hash-get summary "rootKeyId"))
                              (cons "subjectCount" (hash-get summary "subjectCount"))
                              (cons "verifiedSubjects" (hash-get summary "verifiedSubjects")))))
                    (displayln "MULTI-METHOD-VERIFY-FLEET-BUNDLE-OK " target-path
                               (if emit-stmt-path (string-append " statement=" emit-stmt-path) "")))))
              (if json-mode?
                (begin
                  (emit-json-result! #f "verify-fleet-bundle" target-path store-path
                    "offline fleet bundle verification failed")
                  (exit 1))
                (error "offline fleet bundle verification failed" target-path)))))
         ((equal? mode "--verify-dsse-statement")
          (let ((summary (inspect-dsse-statement-verified target-path trust-pair
                           expected-sysml-sha256: expected-sysml-sha
                           expected-subject-count: expected-sub-cnt
                           required-subjects: req-subs
                           min-signatures: min-sigs
                           required-signers: req-signers
                           required-roles: req-roles)))
            (if summary
              (if json-mode?
                (let ((vroles (hash-get summary "verifiedRoles")))
                  (emit-json-result! #t "verify-dsse-statement" target-path store-path
                    "authentic-dsse-v1-intoto-statement"
                    (append
                      (if expected-sysml-sha (list (cons "expectedSysmlSha256" expected-sysml-sha)) '())
                      (if expected-sub-cnt (list (cons "expectedSubjectCount" expected-sub-cnt)) '())
                      (if (pair? req-subs) (list (cons "requiredSubjects" (sort-by req-subs string<?))) '())
                      (if (> min-sigs 1) (list (cons "minSignatures" min-sigs)) '())
                      (if (pair? req-signers) (list (cons "requiredSigners" (sort-by req-signers string<?))) '())
                      (if (pair? req-roles) (list (cons "requiredRoles" (sort-by req-roles string<?))) '())
                      (if policy-path (list (cons "policyPath" policy-path)) '())
                      (if (or (pair? vroles) (pair? req-roles)) (list (cons "verifiedRoles" vroles)) '())
                      (list (cons "fleetId" (hash-get summary "fleetId"))
                            (cons "sysmlSha256" (hash-get summary "sysmlSha256"))
                            (cons "fleetPayloadSha256" (hash-get summary "fleetPayloadSha256"))
                            (cons "rootKeyId" (hash-get summary "rootKeyId"))
                            (cons "verifiedKeyIds" (hash-get summary "verifiedKeyIds"))
                            (cons "subjectCount" (hash-get summary "subjectCount"))
                            (cons "verifiedSubjects" (hash-get summary "verifiedSubjects"))))))
                (displayln "MULTI-METHOD-VERIFY-DSSE-STATEMENT-OK " target-path))
              (if json-mode?
                (begin
                  (emit-json-result! #f "verify-dsse-statement" target-path store-path
                    "offline DSSE v1 in-toto statement verification failed")
                  (exit 1))
                (error "offline DSSE v1 in-toto statement verification failed" target-path)))))
         ((equal? mode "--verify-cache")
          (let* ((eff-now (or now-ep (inexact->exact (floor (time->seconds (current-time))))))
                 (n (verify-cache-offline target-path trust-pair
                      max-age-seconds: max-age-sec
                      now-epoch: eff-now
                      max-future-skew-seconds: max-skew-sec)))
            (if n
              (if json-mode?
                (emit-json-result! #t "verify-cache" target-path store-path "all-cache-witnesses-verified"
                  (if max-age-sec
                    (list (cons "entries" n)
                          (cons "maxAgeSeconds" max-age-sec)
                          (cons "nowEpoch" eff-now))
                    (list (cons "entries" n))))
                (displayln "MULTI-METHOD-VERIFY-CACHE-OK " target-path " entries=" n))
              (if json-mode?
                (begin
                  (emit-json-result! #f "verify-cache" target-path store-path "offline cache verification failed")
                  (exit 1))
                (error "offline cache verification failed" target-path)))))
         (else
          (error "usage: [--json] --verify-report|--verify-fleet|--verify-fleet-bundle|--verify-dsse-statement|--verify-cache <artifact.json> <trust-store.json>"
                 mode))))))))))

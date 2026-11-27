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
(import
  :std/crypto/digest
  :std/encoding/base64
  :std/encoding/hex
  :std/encoding/json
  :std/misc/ports
  :deterministic-engineering/library/verification-flow/attestation)
(export
  load-trust-store-json-lite
  export-trust-bundle-offline
  resolve-contained-child-report-path
  verify-report-offline
  verify-fleet-offline
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

;; Returns `(cons trusted-keys-alist revoked-key-ids-list)` after validating schema,
;; non-symlink regular PEM files, and keyId SHA-256 anti-spoofing.
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
  (cons (reverse trusted) revoked))

(def (verify-report-offline report-path trust-pair)
  (and (file-exists? report-path)
       (let* ((trusted (car trust-pair))
              (revoked (cdr trust-pair))
              (doc (call-with-input-file report-path (cut read-json <> object-as-hash: #t)))
              (att (and (hash-table? doc) (hash-get doc "attestation")))
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

(def (verify-fleet-offline fleet-report-path trust-pair)
  (and (file-exists? fleet-report-path)
       (let* ((trusted (car trust-pair))
              (revoked (cdr trust-pair))
              (doc (call-with-input-file fleet-report-path (cut read-json <> object-as-hash: #t)))
              (att (and (hash-table? doc) (hash-get doc "attestation")))
              (subjects (and (hash-table? doc) (hash-get doc "subjects")))
              (kid (and (hash-table? att) (hash-get att "keyId")))
              (fleet-pub (trust-store-alist-key-admitted? trusted revoked kid)))
         (and fleet-pub
              (list? subjects)
              (pair? subjects)
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
;; Returns verified entry count (exact integer) on full pass, or `#f` if any entry is invalid/revoked.
(def (verify-cache-offline cache-path trust-pair)
  (and (file-exists? cache-path)
       (let* ((trusted (car trust-pair))
              (revoked (cdr trust-pair))
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
(def (export-trust-bundle-offline out-path pub-paths (revoked-key-ids '()))
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
  (def parent-dir (path-directory out-path))
  (when (and (> (string-length parent-dir) 0) (not (file-exists? parent-dir)))
    (create-directory* parent-dir))
  (def doc
    (hash ("schema" "de.attestation.ed25519-trust-store.v1")
          ("trustedKeys" keys-ht)
          ("revokedKeyIds" revoked-clean)))
  (call-with-output-file out-path
    (lambda (port)
      (write-json port doc)
      (newline port)))
  (cons active revoked-clean))

(def (parse-export-bundle-args rest)
  (let loop ((xs rest) (revoked '()) (pubs '()))
    (cond
     ((null? xs) (values (reverse pubs) (reverse revoked)))
     ((equal? (car xs) "--revoke")
      (unless (pair? (cdr xs))
        (error "--revoke requires a keyId argument"))
      (loop (cddr xs) (cons (cadr xs) revoked) pubs))
     (else
      (loop (cdr xs) revoked (cons (car xs) pubs))))))

(def (main . args)
  (def json-mode? (and (member "--json" args) #t))
  (def clean-args (filter (lambda (a) (not (equal? a "--json"))) args))
  (when (null? clean-args)
    (error "usage: [--json] --verify-report|--verify-fleet|--verify-cache <artifact.json> <trust-store.json> | [--json] --verify-trust-store <trust-store.json> | [--json] --export-trust-bundle <out.json> [--revoke <keyId>]... <pub1.pem>..."
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
          (let-values (((pub-paths revoked-ids) (parse-export-bundle-args (cddr clean-args))))
            (let* ((res (export-trust-bundle-offline out-path pub-paths revoked-ids))
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
             (trusted (car trust-pair))
             (revoked (sort-by (cdr trust-pair) string<?))
             (active (sort-by
                       (filter (lambda (kid) (not (member kid revoked)))
                               (map car trusted))
                       string<?)))
        (if (pair? active)
          (if json-mode?
            (emit-json-result! #t "verify-trust-store" store-path store-path
              "trust-store-valid-with-active-keys"
              (list (cons "activeKeyIds" active)
                    (cons "revokedKeyIds" revoked)))
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
          (if (verify-fleet-offline target-path trust-pair)
            (if json-mode?
              (emit-json-result! #t "verify-fleet" target-path store-path "authentic-2-level-merkle-fleet")
              (displayln "MULTI-METHOD-VERIFY-FLEET-OK " target-path))
            (if json-mode?
              (begin
                (emit-json-result! #f "verify-fleet" target-path store-path "offline fleet verification failed")
                (exit 1))
              (error "offline fleet verification failed" target-path))))
         ((equal? mode "--verify-cache")
          (let ((n (verify-cache-offline target-path trust-pair)))
            (if n
              (if json-mode?
                (emit-json-result! #t "verify-cache" target-path store-path "all-cache-witnesses-verified"
                  (list (cons "entries" n)))
                (displayln "MULTI-METHOD-VERIFY-CACHE-OK " target-path " entries=" n))
              (if json-mode?
                (begin
                  (emit-json-result! #f "verify-cache" target-path store-path "offline cache verification failed")
                  (exit 1))
                (error "offline cache verification failed" target-path)))))
         (else
          (error "usage: [--json] --verify-report|--verify-fleet|--verify-cache <artifact.json> <trust-store.json>"
                 mode))))))))

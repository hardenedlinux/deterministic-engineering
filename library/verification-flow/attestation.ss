;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero-dependency pure canonical signing & Multi-Key Trust Store predicates (10.154).
;;; Imports NO Fun-Flow, NO ASCENT, NO POO, and performs ZERO I/O so both
;;; `library/verification-flow/func.ss` and ultra-lightweight air-gapped offline
;;; verifiers (`t/support/offline-attestation-verifier.ss`) share the exact same
;;; single source of truth with sub-second cold startup.
(export
  sym->str
  sort-by
  frame-canonical-kv
  canonical-witness-signing-payload
  canonical-report-signing-payload
  canonical-fleet-signing-payload
  dsse-v1-pae
  trust-store-alist-key-admitted?
  safe-relative-child-path?
  witness-epoch-fresh?)

(def (sym->str x)
  (if (symbol? x) (symbol->string x) x))

(def (sort-by lst less?)
  (define (insert x sorted)
    (cond
     ((null? sorted) (list x))
     ((less? x (car sorted)) (cons x sorted))
     (else (cons (car sorted) (insert x (cdr sorted))))))
  (let loop ((xs lst) (acc '()))
    (if (null? xs) acc (loop (cdr xs) (insert (car xs) acc)))))

(def (frame-canonical-kv k v)
  (def ks (sym->str k))
  (def vs (sym->str v))
  (string-append ks "=" (number->string (string-length vs)) ":" vs "\n"))

;; Pure Multi-Key Trust Store admission predicate over plain alists:
;; Returns the pinned public-key material associated with `key-id` iff `key-id` is present
;; in `trusted-keys` alist AND NOT present in `revoked-key-ids`; otherwise returns `#f`.
(def (trust-store-alist-key-admitted? trusted-keys revoked-key-ids key-id)
  (and (string? key-id)
       (not (member key-id revoked-key-ids))
       (let ((entry (assoc key-id trusted-keys)))
         (and entry (cdr entry)))))

;; Pure path-traversal containment predicate for 2-level Merkle Fleet child report paths:
;; Rejects empty paths, leading slashes (absolute paths), backslashes, NUL bytes,
;; empty segments (`//`), `.` segments, and `..` parent-traversal segments.
(def (safe-relative-child-path? rel)
  (and (string? rel)
       (> (string-length rel) 0)
       (not (char=? (string-ref rel 0) #\/))
       (not (char=? (string-ref rel 0) #\\))
       (let ((len (string-length rel)))
         (let loop ((i 0))
           (cond
            ((>= i len) #t)
            ((or (char=? (string-ref rel i) #\\)
                 (char=? (string-ref rel i) #\nul))
             #f)
            (else (loop (+ i 1))))))
       (let ((segs (string-split rel #\/)))
         (and (pair? segs)
              (andmap
                (lambda (seg)
                  (and (> (string-length seg) 0)
                       (not (equal? seg "."))
                       (not (equal? seg ".."))))
                segs)))))

;; Pure deterministic anti-replay freshness window predicate for cached witnesses:
;; When `max-age-seconds` is `#f`, freshness window enforcement is disabled (returns `#t`).
;; When `max-age-seconds` is a non-negative exact integer, enforces BOTH:
;;   1. Lower-bound TTL (anti-replay): `now-epoch <= issued-epoch + max-age-seconds`
;;   2. Upper-bound future-skew guard: `issued-epoch <= now-epoch + max-future-skew-seconds`
;; Missing or non-integer `issued-epoch` is unconditionally rejected when freshness is active.
(def (witness-epoch-fresh? issued-epoch now-epoch max-age-seconds (max-future-skew-seconds 60))
  (if (not max-age-seconds)
    #t
    (and (exact-integer? issued-epoch)
         (>= issued-epoch 0)
         (exact-integer? now-epoch)
         (>= now-epoch 0)
         (exact-integer? max-age-seconds)
         (>= max-age-seconds 0)
         (exact-integer? max-future-skew-seconds)
         (>= max-future-skew-seconds 0)
         (<= now-epoch (+ issued-epoch max-age-seconds))
         (<= issued-epoch (+ now-epoch max-future-skew-seconds)))))

;; Deterministic, collision-free byte representation of a cached verification witness.
;; `input-pairs` is an alist of (path-string . sha256-hex-string) sorted lexicographically.
;; Optional `issued-at` (epoch string) binds issuance timestamp into Ed25519 to defeat rollback/backdating.
(def (canonical-witness-signing-payload step obligation method claim-kind outcome detail toolchain input-pairs (issued-at ""))
  (def sorted-inputs
    (sort-by (map (lambda (p) (cons (sym->str (car p)) (sym->str (cdr p)))) input-pairs)
             (lambda (a b) (string<? (car a) (car b)))))
  (def issued-str (if (number? issued-at) (number->string issued-at) (sym->str issued-at)))
  (apply string-append
    (append
      (list "de.verification-witness.v2\n"
            (frame-canonical-kv "step" step)
            (frame-canonical-kv "obligation" obligation)
            (frame-canonical-kv "method" method)
            (frame-canonical-kv "claimKind" claim-kind)
            (frame-canonical-kv "outcome" outcome)
            (frame-canonical-kv "detail" detail)
            (frame-canonical-kv "toolchain" toolchain))
      (if (> (string-length issued-str) 0)
        (list (frame-canonical-kv "issuedAt" issued-str))
        '())
      (list (frame-canonical-kv "inputCount" (number->string (length sorted-inputs))))
      (map (lambda (p) (frame-canonical-kv (string-append "in:" (car p)) (cdr p)))
           sorted-inputs))))

;; Deterministic canonical payload for an emitted multi-method verification report.
;; `evidence-rows` is a list of (step obligation method claim-kind outcome detail) lists.
;; `toolchain-pairs` is an alist of (step . toolchain-fingerprint).
(def (canonical-report-signing-payload subject request-id replay-status replay-valid? admitted-subjects evidence-rows toolchain-pairs)
  (def sorted-admitted (sort-by (map sym->str admitted-subjects) string<?))
  (def sorted-ev
    (sort-by (map (lambda (r) (map sym->str r)) evidence-rows)
             (lambda (a b) (string<? (car a) (car b)))))
  (def sorted-tc
    (sort-by (map (lambda (p) (cons (sym->str (car p)) (sym->str (cdr p)))) toolchain-pairs)
             (lambda (a b) (string<? (car a) (car b)))))
  (apply string-append
    (append
      (list "de.verification-report.v2\n"
            (frame-canonical-kv "subject" subject)
            (frame-canonical-kv "requestId" request-id)
            (frame-canonical-kv "replayStatus" replay-status)
            (frame-canonical-kv "replayValid" (if replay-valid? "true" "false"))
            (frame-canonical-kv "admittedCount" (number->string (length sorted-admitted))))
      (map (lambda (s) (frame-canonical-kv "admitted" s)) sorted-admitted)
      (list (frame-canonical-kv "toolchainCount" (number->string (length sorted-tc))))
      (map (lambda (p) (frame-canonical-kv (string-append "tc:" (car p)) (cdr p))) sorted-tc)
      (list (frame-canonical-kv "evidenceCount" (number->string (length sorted-ev))))
      (map (lambda (ev)
             (string-append
               (frame-canonical-kv "ev.step" (list-ref ev 0))
               (frame-canonical-kv "ev.obligation" (list-ref ev 1))
               (frame-canonical-kv "ev.method" (list-ref ev 2))
               (frame-canonical-kv "ev.claimKind" (list-ref ev 3))
               (frame-canonical-kv "ev.outcome" (list-ref ev 4))
               (frame-canonical-kv "ev.detail" (list-ref ev 5))))
           sorted-ev))))

;; Deterministic 2-level Merkle payload for a multi-subject Fleet verification report.
;; `subject-entries` is a list of (subject-key subject-id report-payload-sha256 replay-valid? admitted?) lists.
(def (canonical-fleet-signing-payload fleet-id sysml-sha256 subject-entries)
  (def sorted-entries
    (sort-by (map (lambda (e)
                    (list (sym->str (list-ref e 0))
                          (sym->str (list-ref e 1))
                          (sym->str (list-ref e 2))
                          (if (list-ref e 3) "true" "false")
                          (if (list-ref e 4) "true" "false")))
                  subject-entries)
             (lambda (a b) (string<? (car a) (car b)))))
  (apply string-append
    (append
      (list "de.verification-fleet-report.v1\n"
            (frame-canonical-kv "fleetId" fleet-id)
            (frame-canonical-kv "sysmlSha256" sysml-sha256)
            (frame-canonical-kv "subjectCount" (number->string (length sorted-entries))))
      (map (lambda (e)
             (string-append
               (frame-canonical-kv "sub.key" (list-ref e 0))
               (frame-canonical-kv "sub.id" (list-ref e 1))
               (frame-canonical-kv "sub.reportSha256" (list-ref e 2))
               (frame-canonical-kv "sub.replayValid" (list-ref e 3))
               (frame-canonical-kv "sub.admitted" (list-ref e 4))))
           sorted-entries))))

;; Standard DSSE v1 Pre-Authentication Encoding (PAE) using exact UTF-8 byte lengths:
;;   "DSSEv1 " + utf8ByteLen(payloadType) + " " + payloadType + " " + utf8ByteLen(payload) + " " + payload
(def (dsse-v1-pae payload-type payload-str)
  (def pt (sym->str payload-type))
  (def body (sym->str payload-str))
  (def pt-bytes (u8vector-length (string->utf8 pt)))
  (def body-bytes (u8vector-length (string->utf8 body)))
  (string-append "DSSEv1 "
                 (number->string pt-bytes) " " pt " "
                 (number->string body-bytes) " " body))

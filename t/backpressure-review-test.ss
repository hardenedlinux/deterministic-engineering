;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import (only-in :std/os/pid getpid) (only-in :gerbil/runtime/loader list-modules) :std/test :std/encoding/json
        (only-in :std/misc/ports read-all-as-u8vector) :clan/poo/object
        (only-in :deterministic-engineering/library/drivers/rust-resources/oracle resource-native-oracle)
        :yuanxu/contribution/verification
        :agentic-ai-lab/lambda-aitia/modules/sdlc/standards/nasa-review
        :agentic-ai-lab/lambda-aitia/modules/sdlc/standards/nasa-lifecycle
        :deterministic-engineering/scenarios/resource-lifecycle/review/profile
        :deterministic-engineering/scenarios/resource-lifecycle/review/func)
(export backpressure-review-applicability-test backpressure-review-reuse-test backpressure-review-counter-test backpressure-review-corruption-test)
(def acceptance (getenv "BACKPRESSURE_ACCEPTANCE"))
(def (status review receipts now) (.ref (backpressure-stage review receipts now) 'status))
(def backpressure-review-applicability-test
  (test-suite "Actual backpressure native applicability"
    (test-case "applicability and genuine content receipts have separate boundaries"
      ;; Observe the actual loader, not a fixture or a claimed backend label.
      (when (getenv "BACKPRESSURE_REVIEW_LIB" #f)
        (let ((files (hash-ref (call-with-input-file (getenv "BACKPRESSURE_REVIEW_SOURCES")
                       (cut read-json <> object-as-hash: #t)) "files")))
        (for-each (lambda (name)
          (def id (string-append "deterministic-engineering/scenarios/resource-lifecycle/review/" name "~0"))
          (def found (assoc id (list-modules)))
          (def prefix (string-append (getenv "BACKPRESSURE_REVIEW_LIB") "/" id ".o"))
          (displayln "NATIVE-OWNER " id " " (and found (cdr found))) (force-output)
          (check-equal? (and found (string? (cdr found))
            (>= (string-length (cdr found)) (string-length prefix))
            (equal? prefix (substring (cdr found) 0 (string-length prefix)))) #t)
          (def reference (and found (assoc (cdr found) files)))
          (check-equal? (and reference (equal? (review-file-digest (car reference)) (cadr reference))) #t))
          '("func"))))
      (def review (make-backpressure-review BackpressureReviewProfile acceptance))
      (check-equal? (.ref (.ref review 'audit) 'records) 22)
      (check-equal? (.ref (.ref review 'audit) 'expected-counters) 4)
      ;; A genuine completed content audit may be reused, never its public edits.
      (def caller-audit (audit-backpressure-content acceptance 'caller-owned))
      (check-equal? (.ref caller-audit 'reused-content?) #t)
      (check-equal? (.ref caller-audit 'outcome) 'fail)
      (.put! caller-audit 'outcome 'pass)
      (set-car! (car (.ref caller-audit 'dependencies)) "/untrusted/cache-path")
      (check-equal? (.ref (audit-backpressure-content acceptance 'caller-owned) 'outcome) 'fail)
      ;; Change real raw bytes early in this process; restore the exact captured
      ;; bytes on unwind. A cache hit still reads every dependency and refuses.
      (def raw-path (car (find (lambda (pair) (string-contains (car pair) "/observations.json"))
                              (.ref (.ref review 'audit) 'dependencies))))
      (def raw-bytes (call-with-input-file raw-path read-all-as-u8vector))
      (def raw-sha (review-file-digest raw-path))
      (def raw-backup (path-expand (string-append "raw-cache-backup-" (number->string (getpid)) ".bin")
                       (path-directory (getenv "BACKPRESSURE_REVIEW_SOURCES"))))
      (call-with-output-file raw-backup (cut write-u8vector raw-bytes <>))
      (check-equal? (review-file-digest raw-backup) raw-sha)
      (displayln "CACHE-RAW-BACKUP " raw-backup " " raw-sha " " raw-path) (force-output)
      (def raw (call-with-input-string (utf8->string raw-bytes) (cut read-json <> object-as-hash: #t)))
      (def held (find (lambda (event) (equal? (hash-ref event "event") "held"))
                     (hash-ref (car (hash-ref raw "cases")) "events")))
      (hash-put! held "live" 0)
      (dynamic-wind
        (lambda () (call-with-output-file (list path: raw-path truncate: #t) (cut write-json <> raw)))
        (lambda ()
          (check-exception (audit-backpressure-content acceptance 'worker-owned) (lambda (_) #t))
          (check-equal? (and (verify-review-context review 10 20) #t) #t)
          (check-exception (verify-review-content review 10 20) (lambda (_) #t)))
        (lambda () (call-with-output-file (list path: raw-path truncate: #t) (cut write-u8vector raw-bytes <>))))
      (check-equal? (review-file-digest raw-path) raw-sha)
      (check-equal? (.ref (audit-backpressure-content acceptance 'worker-owned) 'outcome) 'pass)

      (check-equal? (status review '() 11) 'context-verification-required)
      (def cr (verify-review-context review 10 20))
      (check-equal? (status review (list cr) 11) 'content-verification-required)
      (def er (verify-review-content review 10 20))
      (def gate (backpressure-stage review (list cr er) 11))
      (check-equal? (.ref gate 'status) 'stage-admitted)
      (check-equal? (.ref gate 'release-authorized?) #f)
      (check-equal? (status review (list cr er) 20) 'context-verification-required)
      (check-equal? (status review (list cr (.o (:: @ er))) 11) 'content-verification-required)
      (yuanxu-revoke-verification! (.ref review 'adapter) er)
      (check-equal? (status review (list cr er) 11) 'content-verification-required)
      ;; Native applicability is checked separately, not inferred from a pass label.
      (def report (nasa-assess-project 'e (.ref review 'project) (.ref review 'context) (.ref review 'evidence)))
      (def row (find (lambda (r) (equal? (.ref r 'requirement) "SWE-061")) (.ref report 'requirements)))
      (check-equal? (.ref row 'status) 'not-invoked)
      ;; The complete catalog remains the independent reference for scoped work.
      (for-each (lambda (class-value)
        (def full (nasa-assess-project class-value (.ref review 'project) (.ref review 'context) (.ref review 'evidence)))
        (def scoped (nasa-assess-project class-value (.ref review 'project) (.ref review 'context) (.ref review 'evidence)
                       requirements: '("SWE-061")))
        (def expected (find (lambda (r) (equal? (.ref r 'requirement) "SWE-061")) (.ref full 'requirements)))
        (check-equal? (length (.ref scoped 'requirements)) 1)
        (for-each (lambda (key)
          (check-equal? (.ref (car (.ref scoped 'requirements)) key) (.ref expected key)))
          '(requirement status evidence-identities excluded-evidence missing-criteria activity authority compliance))) '(a e))
      (check-exception (nasa-assess-project 'a (.ref review 'project) (.ref review 'context) (.ref review 'evidence)
                         requirements: '("SWE-061" "SWE-061")) (lambda (_) #t))
      (check-exception (nasa-assess-project 'a (.ref review 'project) (.ref review 'context) (.ref review 'evidence)
                         requirements: '("SWE-unknown")) (lambda (_) #t)))))

(def backpressure-review-reuse-test
  (test-suite "Actual backpressure native reuse"
    (test-case "content reuse needs the same basis and fresh revision-bound receipts"
      (def first (make-backpressure-review BackpressureReviewProfile acceptance))
      (def cr (verify-review-context first 10 20))
      (def er (verify-review-content first 10 20))
      (check-equal? (status first (list cr er) 12) 'stage-admitted)
      (def next-profile (.o (:: @ BackpressureReviewProfile) revision: (string-copy "accepted-owner-slice/r2")))
      (def next (make-backpressure-review next-profile acceptance previous: first))
      (check-equal? (.ref (.ref first 'audit) 'report-digest) (.ref (.ref next 'audit) 'report-digest))
      (check-equal? (status next (list cr er) 12) 'context-verification-required)
      (def nc (verify-review-context next 11 21))
      (check-equal? (status next (list nc er) 12) 'content-verification-required)
      (def ne (verify-review-content next 11 21))
      (check-equal? (status next (list nc ne) 12) 'stage-admitted)
      ;; A caller cannot get a genuine receipt merely by supplying a real digest.
      (def clone (.o (:: @ (car (.ref next 'evidence))) identity: "relabeled"))
      (check-equal? (yuanxu-verify (.ref next 'adapter) (nasa-evidence-request clone) 12 22) #f)
      (string-set! (.ref next-profile 'revision) 0 #\X)
      (check-exception (backpressure-stage next (list nc ne) 12) (lambda (_) #t)))))

(def backpressure-review-counter-test
  (test-suite "Actual backpressure native counter"
    (test-case "actual caller-owned counter blocks and survives revision and scope narrowing"
      (def unsafe-profile (.o (:: @ BackpressureReviewProfile) target: 'caller-owned scope: "bounded-permit-method/M06"))
      (def unsafe-review (make-backpressure-review unsafe-profile acceptance))
      (check-equal? (.ref (car (.ref unsafe-review 'evidence)) 'outcome) 'fail)
      (def c (verify-review-context unsafe-review 10 20))
      (def e (verify-review-content unsafe-review 10 20))
      (check-equal? (status unsafe-review (list c e) 11) 'requirements-blocked)
      (def next-profile (.o (:: @ BackpressureReviewProfile) revision: "counter-disposition-pending/r2"))
      (def next (make-backpressure-review next-profile acceptance previous: unsafe-review))
      (def nc (verify-review-context next 10 20))
      (def ne (verify-review-content next 10 20))
      (def gate (backpressure-stage next (list nc ne) 11))
      (check-equal? (.ref (car (.ref next 'evidence)) 'outcome) 'pass)
      (check-equal? (.ref gate 'status) 'requirements-blocked)
      (check-equal? (length (.ref gate 'reported-failures)) 1)
      (check-equal? (.ref gate 'release-authorized?) #f))))

(def backpressure-review-corruption-test
  (test-suite "Actual backpressure native corruption"
    (test-case "raw event corruption and changed acceptance are independently refused"
      (def (load path) (call-with-input-file path (cut read-json <> object-as-hash: #t)))
      (def a (load acceptance))
      (def report (load (hash-ref a "report")))
      (def native-row (find (lambda (r) (equal? (hash-ref (hash-ref r "observation") "method") "native")) (hash-ref report "results")))
      (def raw-path (car (find (lambda (p) (string-contains (car p) "/observations.json")) (hash-ref (hash-ref native-row "observation") "artifacts"))))
      (def raw (load raw-path))
      (def held (find (lambda (event) (equal? (hash-ref event "event") "held")) (hash-ref (car (hash-ref raw "cases")) "events")))
      (hash-put! held "live" 0)
      (check-exception (resource-native-oracle raw) (lambda (_) #t))
      (hash-put! a "reportSha256" (make-string 64 #\0))
      (def altered (path-expand ".data/aitia-backpressure-20261019/rejected-acceptance-fixed.json" (current-directory)))
      (call-with-output-file (list path: altered truncate: #t) (cut write-json <> a))
      (check-exception (audit-backpressure-content altered 'worker-owned) (lambda (_) #t)))))

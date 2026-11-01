;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

;;; -*- Gerbil -*-
;;; Integration audit of real Core Ops/QNT/TLC/Lean/native ASCENT artifacts.
;;; Run the example first and bind GATEWAY_REAL_REPORT to its immutable report.
(import :std/test :std/encoding/json :clan/poo/object :deterministic-engineering/init)
(export gateway-real-results-test)
(def gateway-real-results-test
  (test-suite "Real gateway method evidence, provenance and scoped reuse"
    (test-case "actual method outputs and independent native queries match review gold"
      (def scope (.get (.get deterministic-engineering.init.exports Scenarios) gateway-review scope))
      (def digest (.get scope methods file-digest))
      (def report-path (getenv "GATEWAY_REAL_REPORT" #f))
      (unless report-path (error "run examples/gateway-evidence.ss and set GATEWAY_REAL_REPORT"))
      (def (load-json path) (call-with-input-file path (cut read-json <> object-as-hash: #t)))
      (def report (load-json report-path))
      (check-equal? (hash-ref report "schema") "gateway.real-investigation.v1")
      (check-equal? (hash-ref report "status") "passed")
      (check-equal? (hash-ref report "rustImplementationVerified") #f)
      (check-equal? (hash-ref report "nativePerformanceMeasured") #f)
      (def (current-files pairs)
        (for-each (lambda (p) (check-equal? (digest (car p)) (cadr p))) pairs))
      (current-files (hash-ref report "sourceInputs"))
      (current-files (hash-ref report "queries"))
      (current-files (hash-ref report "nativeExchanges"))
      (def results (hash-ref report "results"))
      (check-equal? (length results) 7)
      (def refs (map (lambda (r) (string-append "sha256:" (digest (hash-ref r "recordPath")))) results))
      (for-each (lambda (r)
        (def record (load-json (hash-ref r "recordPath")))
        (def review (load-json (hash-ref r "reviewPath")))
        (check-equal? (hash-ref record "schema") "rust.resource.method-observation.v1")
        (check-equal? (hash-ref review "result")
          (string-append "sha256:" (digest (hash-ref r "recordPath"))))
        (current-files (hash-ref record "inputs"))
        (current-files (hash-ref record "artifacts"))
        (for-each (lambda (command)
          (check-equal? (hash-ref command "timeoutSeconds") 45)
          (check-equal? (digest (hash-ref command "log")) (hash-ref command "logSha256")))
          (hash-ref record "commands"))
        (def oracle (hash-ref review "oracle"))
        (if (equal? (hash-ref record "method") "lean")
          (begin
            (check-equal? (hash-ref (cadr (hash-ref record "commands")) "exit") 0)
            (check-equal? (hash-ref oracle "planned")
              (if (equal? (hash-ref record "outcome") "fail") 640
                (if (= (hash-ref oracle "planned") 384) 384 512))))
          (if (equal? (hash-ref record "outcome") "pass")
            (begin
              (check-equal? (hash-ref oracle "safe") #t)
              ;; Closed-form occupancy enumeration independently fixes the state counts.
              (check-equal? (hash-ref oracle "states") (if (= (hash-ref oracle "limit") 2) 1632 6582)))
            (begin
              (check-equal? (hash-ref oracle "violation") #t)
              (check-equal? (hash-ref oracle "reservationAfter") #f)
              (check-equal? (hash-ref oracle "cleanupAfter") #t))))) results)
      (def expected
        '(("02-C1-real-support" 2 0 2)
          ("03-C2-old-results" 0 0 2)
          ("04-C2-rechecked" 2 0 4)
          ("05-cache-before-budget" 1 0 4)
          ("06-cache-budget-counter" 1 1 5)
          ("07-source-reuse" 2 0 5)
          ("08-real-model-counter" 1 1 6)
          ("09-late-real-result" 1 1 7)
          ("10-rejection-preserves-current" 1 1 7)))
      (for-each (lambda (gold)
        (def q (find (lambda (p) (string-contains (car p) (string-append (car gold) ".json")))
                     (hash-ref report "queries")))
        (check-equal? (and q #t) #t)
        (def value (load-json (car q)))
        (check-equal? (length (hash-ref value "support")) (cadr gold))
        (check-equal? (length (hash-ref value "counter")) (caddr gold))
        (check-equal? (length (hash-ref value "witness")) (cadddr gold))
        (for-each (lambda (row) (check-equal? (and (member (list-ref row 3) refs) #t) #t))
          (append (hash-ref value "support") (hash-ref value "counter")))) expected)
      (check-equal? (hash-ref report "rejections")
        '("changed-artifact" "plain-JSON-is-not-an-issuer")))))

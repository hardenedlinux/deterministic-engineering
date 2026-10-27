#!/usr/bin/env gxi
;;; -*- Gerbil -*-
;;; Actual source-changing native experiment, handed off through Core Ops.
(import :clan/poo/object :std/encoding/json :std/misc/ports :std/list/list
        (only-in :yuanxu/ops/process-script ProcessScript.)
        (only-in :std/string/misc string-subst)
        :deterministic-engineering/scenarios/resource-lifecycle/review/func
        :deterministic-engineering/library/concurrency/resource-control/backpressure-memory/rust/reassessment-oracle)
(export main)
(def (read-text p) (call-with-input-file p read-all-as-string))
(def (write-text p s) (call-with-output-file (list path: p truncate: #t) (cut display s <>)))
(def (replace-once source from to)
  (unless (string-contains source from) (error "source mutation anchor absent" from))
  (string-subst source from to count: 1))
(def (load p) (call-with-input-file p (cut read-json <> object-as-hash: #t)))
(def (main output cargo rustc)
  (when (file-exists? output) (error "fresh reassessment output required"))
  (create-directory output)
  (def root (current-directory))
  (def original (path-expand "library/concurrency/resource-control/backpressure-memory/rust/native" root))
  (def text (read-text (path-expand "src/main.rs" original)))
  (def regression (replace-once (replace-once text
    "_permit: if name == \"M06\" { None } else { permit.take() }"
    "_permit: if name == \"M06\" || name == \"M04\" { None } else { permit.take() }")
    "let caller_permit = if name == \"M06\" { permit.take() } else { None };"
    "let caller_permit = if name == \"M06\" || name == \"M04\" { permit.take() } else { None };"))
  (def repair (replace-once (replace-once regression
    "_permit: if name == \"M06\" || name == \"M04\" { None } else { permit.take() }"
    "_permit: permit.take()")
    "let caller_permit = if name == \"M06\" || name == \"M04\" { permit.take() } else { None };"
    "let caller_permit: Option<OwnedSemaphorePermit> = None;"))
  ;; The old accepted closure supplies dependency/tool inputs; it is not a new issuer.
  ;; Establish the existing host-selected custody mapping before checking the
  ;; historical producer closure; it never reissues the old review authority.
  (audit-backpressure-content (getenv "BACKPRESSURE_ACCEPTANCE") 'worker-owned)
  (def accepted (load (getenv "BACKPRESSURE_ACCEPTANCE")))
  (def report (load (hash-ref accepted "report")))
  (def native (find (lambda (r) (equal? (hash-ref (hash-ref r "observation") "method") "native")) (hash-ref report "results")))
  (def dependencies (hash-ref (hash-ref native "observation") "inputs"))
  (def (pairs files) (map (lambda (p) (list p (review-file-digest p))) files))
  (def (current! pairs) (for-each (lambda (p) (unless (equal? (review-file-digest (review-reference-path (car p) (cadr p))) (cadr p)) (error "experiment source changed" (car p)))) pairs))
  (def runs '())
  (def (run label source-text size expected)
    (def out (path-expand label output)) (create-directory out)
    (def crate (path-expand "input" out)) (create-directory crate) (create-directory (path-expand "src" crate))
    (for-each (lambda (f) (write-text (path-expand f crate) (read-text (path-expand f original)))) '("Cargo.toml" "Cargo.lock"))
    (def source (path-expand "src/main.rs" crate)) (write-text source source-text)
    (def raw (path-expand "observations.json" out))
    (def log (path-expand "cargo-run.log" out))
    (def before (append dependencies (pairs (list source (path-expand "Cargo.toml" crate) (path-expand "Cargo.lock" crate) cargo rustc
      (path-expand "examples/backpressure-reassessment-evidence.ss" root)
      (path-expand "library/concurrency/resource-control/backpressure-memory/rust/reassessment-oracle.ss" root)))))
    (current! before)
    (def argv (list cargo "--config" (string-append "build.rustc=\"" rustc "\"") "run" "--offline" "--locked"
      "--manifest-path" (path-expand "Cargo.toml" crate) "--target-dir" (path-expand "target" out) "--" raw (number->string size)))
    (def receipt (.call (.cc ProcessScript. 'command argv 'directory out 'timeout 45 'log log 'check-status #f) .run))
    (unless (= (.ref receipt 'status) 0) (error "real native experiment failed" log))
    (current! before)
    (def oracle (backpressure-reassessment-oracle (load raw)))
    (unless (equal? (map (cut hash-ref <> "case") (filter (lambda (g) (equal? (hash-ref g "outcome") "fail")) oracle)) expected)
      (error "independent native experiment gold differs" label))
    (def artifact (path-expand "run.json" out))
    (def value (hash ("schema" "rust.backpressure-source-reassessment/v1") ("observations" raw)
      ("source" source) ("sourceSha256" (review-file-digest source)) ("payloadBytes" size)
      ("argv" argv) ("exit" (.ref receipt 'status)) ("oracle" oracle)
      ("dependencies" (append before (pairs (list raw log (path-expand "target/debug/rust-resource-lifecycle" out)))))))
    (call-with-output-file artifact (cut write-json <> value))
    (set! runs (append runs (list (list label artifact (review-file-digest artifact))))))
  (run "A-original64" text 64 '("M06"))
  (run "B-regression64" regression 64 '("M04" "M06"))
  (run "C-repair64" repair 64 '())
  (run "C-repair128" repair 128 '())
  (def path (path-expand "runs.json" output))
  (call-with-output-file path (cut write-json <> runs))
  (displayln "REAL-SOURCE-REASSESSMENT-OK " path))

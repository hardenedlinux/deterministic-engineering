;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; M5 Ops Runtime Adapter & End-to-End Multi-Method Verification Runner (10.154).
;;; Lives outside pure library/ (t/support/) per 10.148 & Fun-Flow 10.07.
;;;
;;; Executes a Fun-Flow DAG authored with hygienic defrules via upstream Fun-Flow's
;;; native `make-runner` / `runner-run` / `validate-replay-report` against real
;;; Quint/Apalache/MBT, Lean 4/LeanPoo, Rust Clippy, and Rust OS SIGKILL Oracle
;;; toolchains, then admits all receipts against live OpenSysML api-json via
;;; ASCENT MR01-MR06 + ER01-ER04.
(import
  :std/encoding/json
  :std/misc/ports
  :std/misc/process
  :clan/poo/object
  (only-in :std/source this-source-file)
  (only-in :clan/poo/type validate)
  (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
           make-runtime-adapter
           make-adapter-result
           make-local-eager-strategy
           make-cached-local-eager-strategy
           make-runner
           runner-plan
           runner-run
           run-result-value
           run-result-receipt
           validate-replay-report
           replay-report-valid?
           replay-report-status
           replay-report-reasons
           execution-request-name
           execution-request-request
           execution-request-plan-id
           execution-request-node-id
           receipt->run-summary)
  :deterministic-engineering/library/verification-flow/types
  :deterministic-engineering/library/verification-flow/objects
  :deterministic-engineering/library/verification-flow/func
  :deterministic-engineering/library/verification-flow/rules
  :deterministic-engineering/library/verification-flow/sysml-compiler
  :deterministic-engineering/library/verification-flow/methods)
(export
  load-compiled-sysml-subjects
  make-process-tree-verification-subject
  make-backpressure-memory-verification-subject
  make-lease-fencing-verification-subject
  default-process-tree-step-mutability
  default-backpressure-step-mutability
  compute-step-input-digests
  load-verification-cache
  save-verification-cache!
  make-real-verification-runtime-adapter
  run-multi-method-verification-pipeline
  main)

;; ── Zero-Glue SysML v2 -> Fun-Flow DAG Compilation (Single Source of Truth) ──
;; All engineering subjects (process-tree-reclamation, backpressure-memory,
;; lease-fencing-token, and any future subject declared in 10.154-*.sysml) are
;; compiled directly from live OpenSysML api-json via `sysml-projected->compiled-subjects`.

(def runner-repo-root
  (path-normalize (path-expand "../.." (path-directory (this-source-file)))))

(def (project-sysml-model (repo-root runner-repo-root))
  (def sysml-path
    (path-expand
      "docs/10-19-design/10-architecture/10.154-multi-method-funflow-runnable-and-leanpoo-architecture.sysml"
      repo-root))
  (let* ((json-text (run-process (list "sysml" "-convert" "api-json" sysml-path)))
         (parsed (call-with-input-string json-text (cut read-json <> object-as-hash: #t))))
    (sysml-api-json->governance-facts parsed)))

;; Cache only lightweight SysML projection metadata (no heavyweight FlowContract DAGs pinned globally).
(def *cached-sysml-projected* #f)

(def (load-sysml-projected (repo-root runner-repo-root))
  (unless *cached-sysml-projected*
    (set! *cached-sysml-projected* (project-sysml-model repo-root)))
  *cached-sysml-projected*)

(def (load-compiled-sysml-subjects (repo-root runner-repo-root))
  (sysml-projected->compiled-subjects (load-sysml-projected repo-root)))

(def (make-process-tree-verification-subject)
  (.get (compile-sysml-subject-by-key (load-sysml-projected) 'process-tree-reclamation) subject))

(def (make-backpressure-memory-verification-subject)
  (.get (compile-sysml-subject-by-key (load-sysml-projected) 'backpressure-memory) subject))

(def (make-lease-fencing-verification-subject)
  (.get (compile-sysml-subject-by-key (load-sysml-projected) 'lease-fencing-token) subject))

;; ── Subprocess execution with POSIX waitpid decoding ──

(def (exec-bash-captured cwd script)
  (def proc
    (open-process
      (list path: "/bin/bash"
            arguments: (list "-euo" "pipefail" "-c" script)
            directory: cwd
            stdin-redirection: #f
            stdout-redirection: #t
            stderr-redirection: #t)))
  (def output (read-all-as-string proc))
  (def raw-status (process-status proc))
  (close-port proc)
  (def exit-code
    (if (= (bitwise-and raw-status #x7f) 0)
      (arithmetic-shift raw-status -8)
      (+ 128 (bitwise-and raw-status #x7f))))
  (values exit-code output))

(def (last-nonempty-line text fallback)
  (def lines
    (filter (lambda (ln) (> (string-length ln) 0))
            (string-split text #\newline)))
  (if (pair? lines)
    (car (reverse lines))
    fallback))

(def (subject-itf-artifact-dir repo-root subdir)
  (path-expand (string-append ".data/verification-artifacts/" subdir "/itf-traces") repo-root))

(def (run-quint-op repo-root step-name payload)
  (def qfile (alist-ref payload 'quint-file ""))
  (def qmain (alist-ref payload 'quint-main "concurrency_process_tree_reclamation"))
  (def itf-subdir (alist-ref payload 'itf-subdir "process-tree-reclamation"))
  (def verify? (alist-ref payload 'verify? #t))
  (def verify-flag (if verify? " --verify" ""))
  (def n-traces (alist-ref payload 'n-traces 20))
  (def max-samples (alist-ref payload 'max-samples 60))
  (def max-steps (alist-ref payload 'max-steps 24))
  (def n-str (number->string n-traces))
  (def itf-dir (subject-itf-artifact-dir repo-root itf-subdir))
  (def script
    (string-append
      "export PATH=\"$HOME/.bun/bin:$PATH\"\n"
      ;; Capture run-plan into a regular file so Apalache's background server daemon
      ;; cannot inherit and hold open the stdout/stderr pipe to gxtest/tee.
      "tmp_log=\"$(mktemp)\"\n"
      "trap 'rm -f \"$tmp_log\"' EXIT\n"
      "bun packages/quint-modules-resolver/src/cli.ts run-plan \"" qfile "\"" verify-flag " >\"$tmp_log\" 2>&1\n"
      "cat \"$tmp_log\"\n"
      "bun packages/quint-modules-resolver/src/cli.ts mbt-audit \"" qfile "\"\n"
      "rm -rf \"" itf-dir "\" && mkdir -p \"" itf-dir "\"\n"
      "quint run \"" qfile "\" --main \"" qmain "\" --mbt "
      "--max-samples " (number->string max-samples)
      " --n-traces " n-str
      " --max-steps " (number->string max-steps)
      " --invariant safety --seed 0x154 "
      "--out-itf \"" itf-dir "/trace_{seq}.itf.json\" >/dev/null\n"
      "echo \"ITF-EXPORT-OK count=$(ls -1 \"" itf-dir "\"/*.itf.json | wc -l | tr -d ' ')\"\n"))
  (let-values (((code out) (exec-bash-captured repo-root script)))
    (def ok? (and (= code 0)
                  (and (string-contains out "PLAN-OK") #t)
                  (and (string-contains out "MBT-AUDIT-OK") #t)
                  (and (string-contains out "100.0%") #t)
                  (and (string-contains out (string-append "ITF-EXPORT-OK count=" n-str)) #t)))
    (validate VerificationRawReceiptType
      (.o step: step-name
          exit-code: (if ok? 0 (if (= code 0) 1 code))
          artifacts: (list (cons 'quint-file qfile)
                           (cons 'artifact 'itf-trace)
                           (cons 'itf-trace-dir itf-dir)
                           (cons 'itf-trace-count n-traces))
          summary: (if ok?
                     (string-append "Quint verify+mbt-audit+" n-str "-ITF-export passed: "
                                    (last-nonempty-line out "ITF-EXPORT-OK"))
                     (string-append "Quint verification/ITF export failed: "
                                    (last-nonempty-line out "non-zero exit")))))))

(def (run-lean-op repo-root step-name payload)
  (def lake-root (path-expand (alist-ref payload 'lake-root "packages/lean-models") repo-root))
  (def theorems (alist-ref payload 'theorems '()))
  (def axiom-lines
    (apply string-append
      (map (lambda (thm) (string-append "#print axioms " thm "\n")) theorems)))
  (def script
    (string-append
      "export PATH=\"$HOME/.elan/bin:$PATH\"\n"
      "lake build\n"
      "lake env lean --stdin <<'LEAN_EOF'\n"
      "import DeterministicEngineering\n"
      axiom-lines
      "LEAN_EOF\n"))
  (let-values (((code out) (exec-bash-captured lake-root script)))
    (def has-sorry? (and (string-contains out "sorryAx") #t))
    (def ok? (and (= code 0) (not has-sorry?)))
    (validate VerificationRawReceiptType
      (.o step: step-name
          exit-code: (if ok? 0 (if (= code 0) 1 code))
          artifacts: (list (cons 'lake-root lake-root)
                           (cons 'theorem-count (length theorems)))
          summary: (if ok?
                     (string-append "Lean 4 / LeanPoo lake build + zero sorryAx verified ("
                                    (number->string (length theorems)) " theorems)")
                     (string-append "Lean 4 / LeanPoo check failed: "
                                    (last-nonempty-line out "lake error")))))))

(def (run-source-contract-op repo-root step-name payload)
  (def subj-dir (path-expand (alist-ref payload 'subject-dir "") repo-root))
  (def offline-flag (if (alist-ref payload 'offline? #f) "--offline " ""))
  (def script
    (string-append
      "CARGO_BIN=\"${RESOURCE_CARGO:-$(\"$HOME/.cargo/bin/rustup\" which cargo 2>/dev/null || command -v cargo)}\"\n"
      "export PATH=\"$(dirname \"$CARGO_BIN\"):$HOME/.cargo/bin:$PATH\"\n"
      "\"$CARGO_BIN\" clippy " offline-flag "--all-targets -- -D warnings\n"))
  (let-values (((code out) (exec-bash-captured subj-dir script)))
    (def ok? (= code 0))
    (validate VerificationRawReceiptType
      (.o step: step-name
          exit-code: code
          artifacts: (list (cons 'subject-dir subj-dir) (cons 'tool 'clippy))
          summary: (if ok?
                     "Rust Clippy source-contract (-D warnings) passed"
                     (string-append "Clippy source-contract failed: "
                                    (last-nonempty-line out "clippy error")))))))

(def (verify-lifecycle-json-zero-leak json-path)
  (and (file-exists? json-path)
       (let* ((doc (call-with-input-file json-path (cut read-json <> object-as-hash: #t)))
              (cases (and (hash-table? doc) (hash-get doc "cases"))))
         (and (list? cases)
              (= (length cases) 6)
              (andmap
                (lambda (c)
                  (let* ((events (and (hash-table? c) (hash-get c "events")))
                         (finals (and (list? events)
                                      (filter (lambda (ev)
                                                (and (hash-table? ev)
                                                     (equal? (hash-get ev "event") "final")))
                                              events))))
                    (and (pair? finals)
                         (= (hash-get (car finals) "live") 0)
                         (= (hash-get (car finals) "available") 1))))
                cases)))))

(def (run-contained-oracle-op repo-root step-name payload)
  (def crate-dir (path-expand (alist-ref payload 'crate-dir "") repo-root))
  (def itf-subdir (alist-ref payload 'itf-subdir "process-tree-reclamation"))
  (def itf-dir (subject-itf-artifact-dir repo-root itf-subdir))
  (def mode (alist-ref payload 'oracle-mode 'cargo-test-itf))
  (def premise (alist-ref payload 'premise 'SpawnPreservesContainer))
  (if (eq? mode 'cargo-run-lifecycle-json)
    (let* ((obs-path (path-expand (string-append ".data/verification-artifacts/" itf-subdir "/rust-lifecycle.json")
                                  repo-root))
           (script
            (string-append
              "test -f \"" itf-dir "/trace_0.itf.json\"\n"
              "mkdir -p \"$(dirname \"" obs-path "\")\"\n"
              "CARGO_BIN=\"${RESOURCE_CARGO:-$(\"$HOME/.cargo/bin/rustup\" which cargo 2>/dev/null || command -v cargo)}\"\n"
              "export PATH=\"$(dirname \"$CARGO_BIN\"):$HOME/.cargo/bin:$PATH\"\n"
              "\"$CARGO_BIN\" run --offline --quiet -- \"" obs-path "\" 64\n")))
      (let-values (((code out) (exec-bash-captured crate-dir script)))
        (def zero-leak? (and (= code 0)
                             (and (string-contains out "RUST-RESOURCE-LIFECYCLE-OBSERVED") #t)
                             (verify-lifecycle-json-zero-leak obs-path)))
        (validate VerificationRawReceiptType
          (.o step: step-name
              exit-code: (if zero-leak? 0 (if (= code 0) 1 code))
              artifacts: (list (cons 'crate-dir crate-dir)
                               (cons 'consumed-itf-dir itf-dir)
                               (cons 'lifecycle-report obs-path)
                               (cons 'premise premise))
              summary: (if zero-leak?
                         "Rust Tokio+Rayon 6/6 backpressure lifecycle cases (M01-M06) verified live=0, available=1"
                         (string-append "Rust backpressure lifecycle oracle failed: "
                                        (last-nonempty-line out "oracle error")))))))
    (let ((script
           (string-append
             "test -f \"" itf-dir "/trace_0.itf.json\"\n"
             "CARGO_BIN=\"${RESOURCE_CARGO:-$(\"$HOME/.cargo/bin/rustup\" which cargo 2>/dev/null || command -v cargo)}\"\n"
             "export PATH=\"$(dirname \"$CARGO_BIN\"):$HOME/.cargo/bin:$PATH\"\n"
             "export PTREE_ITF_TRACE_DIR=\"" itf-dir "\"\n"
             "\"$CARGO_BIN\" test -- --nocapture --test-threads=1\n")))
      (let-values (((code out) (exec-bash-captured crate-dir script)))
        (def ok? (and (= code 0)
                      (and (string-contains out "http_1_post_shutdown_allows_gateway_to_drain_grandchild_cleanly ... ok") #t)
                      (and (string-contains out "3 passed; 0 failed") #t)
                      (and (string-contains out "4 passed; 0 failed") #t)))
        (validate VerificationRawReceiptType
          (.o step: step-name
              exit-code: (if ok? 0 (if (= code 0) 1 code))
              artifacts: (list (cons 'crate-dir crate-dir)
                               (cons 'consumed-itf-dir itf-dir)
                               (cons 'premise premise))
              summary: (if ok?
                         "Rust ProcessTreeGuard 3/3 HTTP /shutdown E2E + 3/3 live Quint ITF MBT replay + 4/4 OS SIGKILL leak oracle passed"
                         (string-append "Rust HTTP / ITF MBT / OS SIGKILL oracle failed: "
                                        (last-nonempty-line out "cargo test error")))))))))

(def (dispatch-verification-operation repo-root step-name op payload)
  (cond
   ((eq? op 'run-quint-plan) (run-quint-op repo-root step-name payload))
   ((eq? op 'run-lean-lake-check) (run-lean-op repo-root step-name payload))
   ((eq? op 'run-source-contract) (run-source-contract-op repo-root step-name payload))
   ((eq? op 'run-contained-oracle) (run-contained-oracle-op repo-root step-name payload))
   (else
    (validate VerificationRawReceiptType
      (.o step: step-name
          exit-code: 2
          artifacts: '()
          summary: (string-append "Unsupported verification operation: "
                                  (symbol->string op)))))))

;; ── Content-Addressed Input Closure & Persistent JSON Cache Store ──

(def default-process-tree-step-mutability
  (subject-spec->mutability
    (find-sysml-subject-spec (load-sysml-projected) 'process-tree-reclamation)))

(def default-backpressure-step-mutability
  (subject-spec->mutability
    (find-sysml-subject-spec (load-sysml-projected) 'backpressure-memory)))

(def (sha256-files-table repo-root rel-paths)
  ;; Single batched shasum -a 256 invocation across all unique paths.
  (def uniq '())
  (for-each (lambda (p) (unless (member p uniq) (set! uniq (cons p uniq)))) rel-paths)
  (def ordered (reverse uniq))
  (def out
    (run-process
      (cons "shasum" (cons "-a" (cons "256" ordered)))
      directory: repo-root))
  (def tbl (make-hash-table))
  (for-each
    (lambda (line)
      (when (> (string-length line) 66)
        (let ((digest (substring line 0 64))
              (rel (substring line 66 (string-length line))))
          (hash-put! tbl rel digest))))
    (string-split out #\newline))
  tbl)

(def (compute-step-input-digests repo-root
       (step-files (subject-spec->input-files
                     (find-sysml-subject-spec (load-sysml-projected repo-root)
                                              'process-tree-reclamation))))
  (def all-files (apply append (map cdr step-files)))
  (def tbl (sha256-files-table repo-root all-files))
  (apply append
    (map (lambda (entry)
           (def step-str (car entry))
           (map (lambda (rel)
                  (def dig (hash-get tbl rel))
                  (unless (string? dig)
                    (error "failed to compute sha256 for verification input" rel))
                  (list step-str rel dig))
                (cdr entry)))
         step-files)))

;; Loads persisted verification cache -> (values cached-witness-rows cached-input-rows entry-by-step-hash).
(def (load-verification-cache cache-file)
  (def by-step (make-hash-table))
  (if (and cache-file (file-exists? cache-file))
    (let* ((doc (call-with-input-file cache-file (cut read-json <> object-as-hash: #t)))
           (entries (and (hash-table? doc) (hash-get doc "entries")))
           (w-rows '())
           (i-rows '()))
      (when (hash-table? entries)
        (hash-for-each
          (lambda (step-str rec)
            (when (hash-table? rec)
              (hash-put! by-step step-str rec)
              (set! w-rows
                (cons (list step-str
                            (or (hash-get rec "obligation") "")
                            (or (hash-get rec "method") "")
                            (or (hash-get rec "claimKind") "")
                            (or (hash-get rec "outcome") "")
                            (or (hash-get rec "detail") ""))
                      w-rows))
              (let ((digs (hash-get rec "inputDigests")))
                (when (hash-table? digs)
                  (hash-for-each
                    (lambda (k v)
                      (set! i-rows (cons (list step-str k v) i-rows)))
                    digs)))))
          entries))
      (values (reverse w-rows) (reverse i-rows) by-step))
    (values '() '() by-step)))

(def (save-verification-cache! cache-file evidence-records input-digest-rows prev-by-step)
  (def entries (make-hash-table))
  ;; Preserve prior passing entries for any steps not overwritten.
  (hash-for-each (lambda (k v) (hash-put! entries k v)) prev-by-step)
  ;; Index current input digests by step-str.
  (def digs-by-step (make-hash-table))
  (for-each
    (lambda (row)
      (def st (car row))
      (def k (cadr row))
      (def d (caddr row))
      (let ((sub (or (hash-get digs-by-step st) (make-hash-table))))
        (hash-put! sub k d)
        (hash-put! digs-by-step st sub)))
    input-digest-rows)
  ;; Only persist PASSING evidence records (never cache failures!).
  (for-each
    (lambda (ev)
      (when (eq? (.get ev outcome) 'pass)
        (let ((st (symbol->string (.get ev step))))
          (hash-put! entries st
            (hash ("obligation" (symbol->string (.get ev obligation)))
                  ("method" (symbol->string (.get ev method)))
                  ("claimKind" (symbol->string (.get ev claim-kind)))
                  ("outcome" "pass")
                  ("detail" (.get ev detail))
                  ("inputDigests" (or (hash-get digs-by-step st) (make-hash-table))))))))
    evidence-records)
  (def parent-dir (path-directory cache-file))
  (unless (file-exists? parent-dir)
    (create-directory* parent-dir))
  (call-with-output-file cache-file
    (lambda (port)
      (write-json
        port
        (hash ("schema" "deterministic-engineering.verification-cache.v1")
              ("entries" entries)))
      (newline port))))

;; Cache-aware Fun-Flow RuntimeAdapter: skips subprocess execution iff ASCENT IR01-IR04
;; explicitly admitted the step into `step_reusable`.
(def (make-real-verification-runtime-adapter repo-root (reuse-plan #f) (cached-by-step #f))
  (def reusable-list (if reuse-plan (.get reuse-plan reusable) '()))
  (def executed '())
  (def reused '())
  (def adapter
    (make-runtime-adapter
      'de-ops-contained-runner
      '(external)
      (lambda (request)
        (def step-name (execution-request-name request))
        (def step-str (symbol->string step-name))
        (def req-body (execution-request-request request))
        (def op (and (pair? req-body) (pair? (cdr req-body)) (cadr req-body)))
        (def payload (and (pair? req-body) (pair? (cdr req-body)) (pair? (cddr req-body)) (caddr req-body)))
        (def cached-rec (and cached-by-step
                             (member step-str reusable-list)
                             (hash-get cached-by-step step-str)))
        (def raw-receipt
          (if cached-rec
            (begin
              (set! reused (cons step-str reused))
              (validate VerificationRawReceiptType
                (.o step: step-name
                    exit-code: 0
                    artifacts: (list (cons 'cache-hit #t))
                    summary: (let ((prev (or (hash-get cached-rec "detail") "cached pass")))
                               (if (and (>= (string-length prev) 12)
                                        (equal? (substring prev 0 12) "[CACHE-HIT] "))
                                 prev
                                 (string-append "[CACHE-HIT] " prev))))))
            (begin
              (set! executed (cons step-str executed))
              (dispatch-verification-operation repo-root step-name op payload))))
        (def ok? (= (.get raw-receipt exit-code) 0))
        (make-adapter-result
          (list 'de-ops-request step-name op)
          (if ok? 'ok 'failed)
          raw-receipt
          (list 'de-ops-artifact (execution-request-plan-id request) (execution-request-node-id request))
          (if ok? #f (.get raw-receipt summary))))
      (lambda (req-id)
        (make-adapter-result req-id 'ok #f #f #f))
      (lambda (request)
        (make-adapter-result (list 'de-ops-store (execution-request-name request)) 'ok #f #f #f))
      (lambda (handle)
        (make-adapter-result (list 'de-ops-get handle) 'ok #f handle #f))))
  (.o bind-these: #f
      adapter: adapter
      stats: (lambda ()
               (.o bind-these: #f
                   executed: (reverse executed)
                   reused: (reverse reused)))))

(def (wire-rows rows)
  (map (lambda (row)
         (map (lambda (v) (if (symbol? v) (symbol->string v) v)) row))
       rows))

(def (evidence-record->json-hash ev)
  (hash ("step" (symbol->string (.get ev step)))
        ("obligation" (symbol->string (.get ev obligation)))
        ("method" (symbol->string (.get ev method)))
        ("claimKind" (symbol->string (.get ev claim-kind)))
        ("outcome" (symbol->string (.get ev outcome)))
        ("detail" (.get ev detail))))

;; Full closed-loop M5 verification pipeline (multi-subject + content-addressed cache):
;; SysML v2 -> ASCENT MR01-MR06 (all subjects) -> ASCENT IR01-IR04 Selective Reuse Frontier
;; -> Fun-Flow DAG Manifest & Real/Cached Runner -> Fun-Flow Replay Validation
;; -> ASCENT ER01-ER04 Evidence Admission.
(def (run-multi-method-verification-pipeline
       repo-root
       subject-key: (subject-key 'process-tree-reclamation)
       output-dir: (output-dir #f)
       cache-dir: (cache-dir #f)
       policy-flags: (policy-flags '())
       request-id: (request-id "req-pt-m5-001"))
  (def sysml-path
    (path-expand
      "docs/10-19-design/10-architecture/10.154-multi-method-funflow-runnable-and-leanpoo-architecture.sysml"
      repo-root))
  ;; 1. Live OpenSysML strict validation & api-json projection (single source of truth).
  ;;    Release the raw JSON string & parsed AST immediately after projection so GC reclaims them.
  (def strict-out (run-process (list "sysml" "-validate" "-strict" sysml-path)))
  (unless (string-contains strict-out "no errors")
    (error "OpenSysML strict validation failed" strict-out))
  (def sysml-projected (project-sysml-model repo-root))
  (def sysml-gov-sources (.get sysml-projected governance-sources))

  ;; 2. Pre-flight ASCENT MR01-MR06 governance gate directly on ALL SysML v2 subjects.
  (def mr-result (reason-multi-method-governance sysml-gov-sources))
  (def mr-findings ((.ref mr-result 'rows-of) 'mr_finding))
  (def mr-open-premises ((.ref mr-result 'rows-of) 'mr03_open_premise))
  (unless (and (null? mr-findings) (null? mr-open-premises))
    (error "ASCENT MR01-MR06 pre-flight refused SysML v2 specification"
           (list mr-findings mr-open-premises)))

  ;; 3. Compile ONLY the requested target subject directly from live SysML v2 (zero Scheme glue)
  ;;    and slice SysML v2 governance facts to that subject.
  (let* ((bundle (compile-sysml-subject-by-key sysml-projected subject-key))
         (subject-obj (.get bundle subject))
         (step-mutability (.get bundle mutability))
         (step-input-files (.get bundle input-files)))
    (def subject-id (.get subject-obj identity))
    (def subject-gov-sources (filter-governance-sources-for-subject sysml-gov-sources subject-id))
    (def dag-receipt (subject->dag-receipt subject-obj))
    (def dag-manifest (subject->dag-runtime-manifest subject-obj request-id))

    ;; 4. Compute SHA-256 input closure & run ASCENT IR01-IR04 incremental reuse gate.
    (def cache-file
      (and cache-dir (path-expand "verification-cache.v1.json" (path-expand cache-dir repo-root))))
    (def current-digests (if cache-file (compute-step-input-digests repo-root step-input-files) '()))
    (let-values (((cached-w-rows cached-i-rows cached-by-step)
                  (load-verification-cache cache-file)))
      (def reuse-plan
        (if cache-file
          (reuse-result->plan
            (reason-incremental-reuse
              (build-incremental-reuse-sources
                subject-gov-sources
                step-mutability
                policy-flags
                current-digests
                cached-w-rows
                cached-i-rows)))
          #f))

      ;; 5. Execute the 4-engine Fun-Flow DAG via upstream make-runner / runner-run.
      (def strategy
        (if cache-file (make-cached-local-eager-strategy) (make-local-eager-strategy)))
      (def adapter-bundle
        (make-real-verification-runtime-adapter repo-root reuse-plan cached-by-step))
      (def runner (make-runner strategy (.get adapter-bundle adapter)))
      (def dag-flow (.get subject-obj dag-flow))
      (def input-env
        (validate VerificationInputEnvelopeType
          (.o subject: subject-id
              profile: (if cache-file 'multi-method.m5-cached 'multi-method.m5)
              input-digests: (list (cons 'sysml sysml-path)))))
      (def plan (runner-plan runner dag-flow))
      (def run-res (runner-run runner dag-flow input-env))
      (def root-receipt (run-result-receipt run-res))
      (def replay-rep (validate-replay-report plan root-receipt))

      ;; 6. Extract all 4 VerificationEvidenceRecordType from Fun-Flow Receipt tree
      ;;    and admit against LIVE SysML v2 obligations/premises via ASCENT ER01-ER04!
      (def evidence-records (receipt-tree->evidence-records root-receipt))
      (def er-sources (governance+evidence->admission-sources subject-gov-sources evidence-records))
      (def er-result (reason-verification-evidence-admission er-sources))
      (def exec-stats ((.get adapter-bundle stats)))

      ;; Persist passing receipts into content-addressed cache if cache-dir enabled.
      (when cache-file
        (save-verification-cache! cache-file evidence-records current-digests cached-by-step))

      (def cache-summary
        (.o bind-these: #f
            enabled?: (and cache-file #t)
            cache-path: (or cache-file "")
            executed: (.get exec-stats executed)
            reused: (.get exec-stats reused)
            invalidations: (if reuse-plan (.get reuse-plan invalidations) '())))

      (def report-path
        (if output-dir
          (let ((resolved-out (path-expand output-dir repo-root)))
            (when (file-exists? resolved-out)
              (error "fresh verification output directory required" resolved-out))
            (create-directory resolved-out)
            (let ((rpath (path-expand "report.json" resolved-out)))
              (call-with-output-file rpath
                (lambda (port)
                  (write-json
                    port
                    (hash
                      ("schema" "deterministic-engineering.multi-method-verification-report.v1")
                      ("subject" (symbol->string subject-id))
                      ("requestId" request-id)
                      ("sysmlSource" sysml-path)
                      ("funflowManifestSchema" (symbol->string (cdr (assoc 'schema dag-manifest))))
                      ("replayStatus" (symbol->string (replay-report-status replay-rep)))
                      ("replayValid" (replay-report-valid? replay-rep))
                      ("mrFindings" (wire-rows mr-findings))
                      ("mrOpenPremises" (wire-rows mr-open-premises))
                      ("erFindings" (wire-rows ((.ref er-result 'rows-of) 'er_finding)))
                      ("obligationsPassed" (wire-rows ((.ref er-result 'rows-of) 'obligation_passed)))
                      ("premisesVerified" (wire-rows ((.ref er-result 'rows-of) 'premise_verified)))
                      ("verificationAdmitted" (wire-rows ((.ref er-result 'rows-of) 'verification_admitted)))
                      ("cacheSummary"
                       (hash ("enabled" (.get cache-summary enabled?))
                             ("cachePath" (.get cache-summary cache-path))
                             ("executed" (.get cache-summary executed))
                             ("reused" (.get cache-summary reused))
                             ("invalidations" (wire-rows (.get cache-summary invalidations)))))
                      ("evidence" (map evidence-record->json-hash evidence-records))))
                  (newline port)))
              rpath))
          #f))

      (.o bind-these: #f
          sysml-projected: sysml-projected
          mr-result: mr-result
          reuse-plan: reuse-plan
          cache-summary: cache-summary
          dag-receipt: dag-receipt
          dag-manifest: dag-manifest
          run-result: run-res
          replay-report: replay-rep
          evidence-records: evidence-records
          er-result: er-result
          report-path: report-path))))

(def (main output-dir . rest)
  (def cache-dir (and (pair? rest) (> (string-length (car rest)) 0) (car rest)))
  (def subject-key
    (if (and (pair? rest) (pair? (cdr rest)) (> (string-length (cadr rest)) 0))
      (string->symbol (cadr rest))
      'process-tree-reclamation))
  (def repo-root (path-normalize (path-expand "../.." (path-directory (this-source-file)))))
  (def outcome
    (run-multi-method-verification-pipeline repo-root
      subject-key: subject-key
      output-dir: output-dir
      cache-dir: cache-dir))
  (def er-res (.get outcome er-result))
  (def admitted ((.ref er-res 'rows-of) 'verification_admitted))
  (def er-findings ((.ref er-res 'rows-of) 'er_finding))
  (unless (and (replay-report-valid? (.get outcome replay-report))
               (null? er-findings)
               (pair? admitted))
    (error "multi-method verification pipeline refused admission"
           (list (replay-report-status (.get outcome replay-report))
                 er-findings
                 admitted)))
  (displayln "MULTI-METHOD-VERIFICATION-OK " (.get outcome report-path)))

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
  compute-step-toolchain-fingerprints
  ensure-cache-signing-keypair!
  verify-verification-report-attestation
  verify-report-with-pinned-key
  verify-fleet-report-with-pinned-key
  load-verification-cache
  save-verification-cache!
  make-real-verification-runtime-adapter
  run-multi-method-verification-pipeline
  run-multi-method-fleet
  predict-fleet-reuse-plan
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
  ;; Change directory inside the forked bash child rather than via Gambit's
  ;; process-wide `directory:` chdir, making concurrent green-thread spawns 100% race-free.
  (def full-script (string-append "cd \"" cwd "\"\n" script))
  (def proc
    (open-process
      (list path: "/bin/bash"
            arguments: (list "-euo" "pipefail" "-c" full-script)
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

(def (theorem->module-name thm)
  (let loop ((i (- (string-length thm) 1)))
    (cond
     ((< i 0) #f)
     ((char=? (string-ref thm i) #\.) (substring thm 0 i))
     (else (loop (- i 1))))))

(def (unique-nonempty-strings xs)
  (def acc '())
  (for-each
    (lambda (s)
      (when (and (string? s) (> (string-length s) 0) (not (member s acc)))
        (set! acc (cons s acc))))
    xs)
  (reverse acc))

(def (run-lean-op repo-root step-name payload)
  (def lake-root (path-expand (alist-ref payload 'lake-root "packages/lean-models") repo-root))
  (def lean-mod (alist-ref payload 'lean-module ""))
  (def theorems (alist-ref payload 'theorems '()))
  ;; Build & import ONLY the exact modules required by this subject's theorems so
  ;; unrelated WIP Lean modules in packages/lean-models cannot break or pollute it.
  (def target-mods
    (let ((mods (unique-nonempty-strings
                  (cons lean-mod (filter string? (map theorem->module-name theorems))))))
      (if (pair? mods) mods '("DeterministicEngineering"))))
  (def build-args (apply string-append (map (lambda (m) (string-append " " m)) target-mods)))
  (def import-lines (apply string-append (map (lambda (m) (string-append "import " m "\n")) target-mods)))
  (def axiom-lines
    (apply string-append
      (map (lambda (thm) (string-append "#print axioms " thm "\n")) theorems)))
  (def script
    (string-append
      "export PATH=\"$HOME/.elan/bin:$PATH\"\n"
      "lake build" build-args "\n"
      "lake env lean --stdin <<'LEAN_EOF'\n"
      import-lines
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
  (def tool (alist-ref payload 'tool 'clippy))
  (if (eq? tool 'cbmc)
    (let* ((files (alist-ref payload 'cbmc-files '()))
           (files-arg (apply string-append (map (lambda (f) (string-append " \"" f "\"")) files)))
           (script
            (string-append
              "export PATH=\"/opt/homebrew/bin:/usr/local/bin:$PATH\"\n"
              "cbmc" files-arg " --bounds-check --pointer-check --unsigned-overflow-check\n")))
      (let-values (((code out) (exec-bash-captured subj-dir script)))
        (def ok? (and (= code 0) (and (string-contains out "VERIFICATION SUCCESSFUL") #t)))
        (validate VerificationRawReceiptType
          (.o step: step-name
              exit-code: (if ok? 0 (if (= code 0) 1 code))
              artifacts: (list (cons 'subject-dir subj-dir)
                               (cons 'tool 'cbmc)
                               (cons 'files files))
              summary: (if ok?
                         "CBMC C source-memory-ub proof (bounds/pointer/unsigned-overflow) VERIFICATION SUCCESSFUL"
                         (string-append "CBMC source-contract failed: "
                                        (last-nonempty-line out "cbmc error")))))))
    (let* ((offline-flag (if (alist-ref payload 'offline? #f) "--offline " ""))
           (script
            (string-append
              "CARGO_BIN=\"${RESOURCE_CARGO:-$(\"$HOME/.cargo/bin/rustup\" which cargo 2>/dev/null || command -v cargo)}\"\n"
              "export PATH=\"$(dirname \"$CARGO_BIN\"):$HOME/.cargo/bin:$PATH\"\n"
              "\"$CARGO_BIN\" clippy " offline-flag "--all-targets -- -D warnings\n")))
      (let-values (((code out) (exec-bash-captured subj-dir script)))
        (def ok? (= code 0))
        (validate VerificationRawReceiptType
          (.o step: step-name
              exit-code: code
              artifacts: (list (cons 'subject-dir subj-dir) (cons 'tool 'clippy))
              summary: (if ok?
                         "Rust Clippy source-contract (-D warnings) passed"
                         (string-append "Clippy source-contract failed: "
                                        (last-nonempty-line out "clippy error")))))))))

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
                      (and (string-contains out "mbt_4_online_os_process_driver_executes_live_quint_itf_actions_step_by_step ... ok") #t)
                      (and (string-contains out "control_5_darwin_setsid_pgid_escape_caught_by_pipe_eof_fate_sharing ... ok") #t)
                      (and (string-contains out "control_6_negative_control_untrusted_setsid_without_watchdog_falsifies_pgid_only_containment ... ok") #t)
                      (and (string-contains out "3 passed; 0 failed") #t)
                      (and (string-contains out "4 passed; 0 failed") #t)
                      (and (string-contains out "6 passed; 0 failed") #t)))
        (validate VerificationRawReceiptType
          (.o step: step-name
              exit-code: (if ok? 0 (if (= code 0) 1 code))
              artifacts: (list (cons 'crate-dir crate-dir)
                               (cons 'consumed-itf-dir itf-dir)
                               (cons 'premise premise))
              summary: (if ok?
                         "Rust ProcessTreeGuard 3/3 HTTP /shutdown E2E + 4/4 live Quint ITF & online OS MBT + 6/6 OS SIGKILL & Darwin setsid escape controls passed"
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

;; ── Live Verifier Toolchain Fingerprinting (IR05) & OpenSSL Ed25519 Attestation (IR06) ──

(def *cached-host-toolchain-map* #f)

(def (probe-host-toolchain-versions repo-root)
  (unless *cached-host-toolchain-map*
    (let ((script
           (string-append
             "export PATH=\"/opt/homebrew/bin:/usr/local/bin:$HOME/.bun/bin:$HOME/.elan/bin:$HOME/.cargo/bin:$PATH\"\n"
             "CARGO_BIN=\"${RESOURCE_CARGO:-$(\"$HOME/.cargo/bin/rustup\" which cargo 2>/dev/null || command -v cargo || true)}\"\n"
             "if [ -n \"$CARGO_BIN\" ]; then export PATH=\"$(dirname \"$CARGO_BIN\"):$PATH\"; fi\n"
             "printf 'os=%s/%s\\n' \"$(uname -s)\" \"$(uname -m)\"\n"
             "printf 'sysml=%s\\n' \"$(sysml -version 2>&1 | head -n 1 | tr -d '\\r')\"\n"
             "printf 'quint=%s\\n' \"$(quint --version 2>/dev/null | head -n 1 | tr -d '\\r' || echo unknown)\"\n"
             "printf 'bun=%s\\n' \"$(bun --version 2>/dev/null | head -n 1 | tr -d '\\r' || echo unknown)\"\n"
             "printf 'lean=%s\\n' \"$(lean --version 2>/dev/null | head -n 1 | tr -d '\\r' || echo unknown)\"\n"
             "printf 'rustc=%s\\n' \"$(rustc --version 2>/dev/null | head -n 1 | tr -d '\\r' || echo unknown)\"\n"
             "printf 'clippy=%s\\n' \"$(cargo clippy --version 2>/dev/null | head -n 1 | tr -d '\\r' || echo unknown)\"\n"
             "printf 'cbmc=%s\\n' \"$(cbmc --version 2>/dev/null | head -n 1 | tr -d '\\r' || echo unknown)\"\n")))
      (let-values (((_code out) (exec-bash-captured repo-root script)))
        (def tbl (make-hash-table))
        (for-each
          (lambda (line)
            (def idx
              (let ((n (string-length line)))
                (let loop ((i 0))
                  (cond ((>= i n) #f)
                        ((char=? (string-ref line i) #\=) i)
                        (else (loop (+ i 1)))))))
            (when (and idx (> idx 0))
              (hash-put! tbl
                         (substring line 0 idx)
                         (substring line (+ idx 1) (string-length line)))))
          (string-split out #\newline))
        (set! *cached-host-toolchain-map* tbl))))
  *cached-host-toolchain-map*)

(def (method-toolchain-fingerprint tbl method-str)
  (def (v k) (or (hash-get tbl k) "unknown"))
  (cond
   ((equal? method-str "de-quint")
    (string-append "quint=" (v "quint") "|bun=" (v "bun") "|sysml=" (v "sysml") "|os=" (v "os")))
   ((equal? method-str "de-lean-poo")
    (string-append "lean=" (v "lean") "|sysml=" (v "sysml") "|os=" (v "os")))
   ((equal? method-str "de-source-contract")
    (string-append "rustc=" (v "rustc") "|clippy=" (v "clippy") "|cbmc=" (v "cbmc") "|os=" (v "os")))
   ((equal? method-str "de-native-oracle")
    (string-append "rustc=" (v "rustc") "|os=" (v "os")))
   (else
    (string-append "sysml=" (v "sysml") "|os=" (v "os")))))

;; Computes ((step-str toolchain-fingerprint) ...) for every step in `subject-gov-sources`.
(def (compute-step-toolchain-fingerprints repo-root subject-gov-sources)
  (def tbl (probe-host-toolchain-versions repo-root))
  (map (lambda (row)
         (def st (car row))
         (def meth (list-ref row 3))
         (list st (method-toolchain-fingerprint tbl meth)))
       (alist-ref subject-gov-sources 'flow_step '())))

(def (trim-nl s)
  (let loop ((n (string-length s)))
    (if (and (> n 0)
             (let ((c (string-ref s (- n 1))))
               (or (char=? c #\newline) (char=? c #\return) (char=? c #\space))))
      (loop (- n 1))
      (substring s 0 n))))

(def (sha256-of-file path)
  (def out (run-process (list "shasum" "-a" "256" path)))
  (if (>= (string-length out) 64)
    (substring out 0 64)
    (error "failed to compute sha256 for file" path out)))

(def (sha256-of-string text)
  (def tmpd (trim-nl (run-process (list "mktemp" "-d"))))
  (try
    (let ((p (path-expand "payload.txt" tmpd)))
      (call-with-output-file p (lambda (port) (display text port)))
      (sha256-of-file p))
    (finally (run-process (list "rm" "-rf" tmpd)))))

(def (ensure-cache-signing-keypair! key-dir)
  (unless (file-exists? key-dir)
    (create-directory* key-dir))
  (def priv (path-expand "attestation-ed25519.pem" key-dir))
  (def pub (path-expand "attestation-ed25519.pub.pem" key-dir))
  (unless (and (file-exists? priv) (file-exists? pub))
    (run-process (list "openssl" "genpkey" "-algorithm" "ED25519" "-out" priv))
    (run-process (list "chmod" "600" priv))
    (run-process (list "openssl" "pkey" "-in" priv "-pubout" "-out" pub)))
  (def key-id (substring (sha256-of-file pub) 0 16))
  (.o bind-these: #f
      private-key: priv
      public-key: pub
      key-id: key-id))

(def (ed25519-sign-string priv-pem payload-str)
  (def tmpd (trim-nl (run-process (list "mktemp" "-d"))))
  (try
    (let ((msg-path (path-expand "msg.bin" tmpd))
          (sig-path (path-expand "sig.bin" tmpd)))
      (call-with-output-file msg-path (lambda (port) (display payload-str port)))
      (run-process (list "openssl" "pkeyutl" "-sign" "-rawin"
                         "-inkey" priv-pem "-in" msg-path "-out" sig-path))
      (trim-nl (run-process (list "openssl" "base64" "-A" "-in" sig-path))))
    (finally (run-process (list "rm" "-rf" tmpd)))))

(def (ed25519-verify-string pub-pem payload-str sig-b64)
  (if (and (string? pub-pem) (file-exists? pub-pem)
           (string? sig-b64) (> (string-length sig-b64) 0))
    (let ((tmpd (trim-nl (run-process (list "mktemp" "-d")))))
      (try
        (let ((msg-path (path-expand "msg.bin" tmpd))
              (b64-path (path-expand "sig.b64" tmpd))
              (sig-path (path-expand "sig.bin" tmpd)))
          (call-with-output-file msg-path (lambda (port) (display payload-str port)))
          (call-with-output-file b64-path (lambda (port) (display sig-b64 port)))
          (let-values (((dcode _dout)
                        (exec-bash-captured tmpd
                          "openssl base64 -A -d -in sig.b64 -out sig.bin")))
            (if (= dcode 0)
              (let-values (((vcode _vout)
                            (exec-bash-captured tmpd
                              (string-append "openssl pkeyutl -verify -rawin -pubin -inkey \""
                                             pub-pem "\" -sigfile sig.bin -in msg.bin"))))
                (= vcode 0))
              #f)))
        (finally (run-process (list "rm" "-rf" tmpd)))))
    #f))

(def (hash-table->alist-strings ht)
  (def acc '())
  (when (hash-table? ht)
    (hash-for-each (lambda (k v) (set! acc (cons (cons k v) acc))) ht))
  acc)

;; Loads persisted verification cache & cryptographically verifies Ed25519 signatures ->
;; (values cached-witness-rows cached-input-rows cached-toolchain-rows attested-steps entry-by-step-hash).
(def (load-verification-cache cache-file (pub-key-path #f))
  (def by-step (make-hash-table))
  (if (and cache-file (file-exists? cache-file))
    (let* ((doc (call-with-input-file cache-file (cut read-json <> object-as-hash: #t)))
           (entries (and (hash-table? doc) (hash-get doc "entries")))
           (w-rows '())
           (i-rows '())
           (tc-rows '())
           (attested '()))
      (when (hash-table? entries)
        (hash-for-each
          (lambda (step-str rec)
            (when (hash-table? rec)
              (let* ((obl (or (hash-get rec "obligation") ""))
                     (meth (or (hash-get rec "method") ""))
                     (ck (or (hash-get rec "claimKind") ""))
                     (out (or (hash-get rec "outcome") ""))
                     (det (or (hash-get rec "detail") ""))
                     (tc (hash-get rec "toolchainFingerprint"))
                     (sig (hash-get rec "signature"))
                     (digs (hash-get rec "inputDigests"))
                     (dig-pairs (hash-table->alist-strings digs)))
                (hash-put! by-step step-str rec)
                (set! w-rows (cons (list step-str obl meth ck out det) w-rows))
                (for-each (lambda (p) (set! i-rows (cons (list step-str (car p) (cdr p)) i-rows)))
                          dig-pairs)
                (when (string? tc)
                  (set! tc-rows (cons (list step-str tc) tc-rows)))
                (when (and pub-key-path (string? tc) (string? sig))
                  (let ((canonical
                         (canonical-witness-signing-payload
                           step-str obl meth ck out det tc dig-pairs)))
                    (when (ed25519-verify-string pub-key-path canonical sig)
                      (set! attested (cons step-str attested))))))))
          entries))
      (values (reverse w-rows) (reverse i-rows) (reverse tc-rows) (reverse attested) by-step))
    (values '() '() '() '() by-step)))

(def (save-verification-cache!
       cache-file
       evidence-records
       input-digest-rows
       prev-by-step
       (toolchain-rows '())
       (keypair #f)
       (reused-steps '()))
  (def entries (make-hash-table))
  ;; Preserve prior passing entries for any steps not overwritten.
  (hash-for-each (lambda (k v) (hash-put! entries k v)) prev-by-step)
  ;; Index current input digests and toolchain fingerprints by step-str.
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
  (def tc-by-step (make-hash-table))
  (for-each (lambda (row) (hash-put! tc-by-step (car row) (cadr row))) toolchain-rows)
  ;; Only persist PASSING evidence records (never cache failures!).
  ;; Reused steps keep their exact prior signed entry untouched.
  (for-each
    (lambda (ev)
      (when (eq? (.get ev outcome) 'pass)
        (let ((st (symbol->string (.get ev step))))
          (unless (and (member st reused-steps) (hash-key? prev-by-step st))
            (let* ((obl (symbol->string (.get ev obligation)))
                   (meth (symbol->string (.get ev method)))
                   (ck (symbol->string (.get ev claim-kind)))
                   (det (.get ev detail))
                   (tc (or (hash-get tc-by-step st) ""))
                   (digs (or (hash-get digs-by-step st) (make-hash-table)))
                   (dig-pairs (hash-table->alist-strings digs))
                   (entry
                     (hash ("obligation" obl)
                           ("method" meth)
                           ("claimKind" ck)
                           ("outcome" "pass")
                           ("detail" det)
                           ("toolchainFingerprint" tc)
                           ("inputDigests" digs))))
              (when keypair
                (let* ((canonical
                        (canonical-witness-signing-payload
                          st obl meth ck "pass" det tc dig-pairs))
                       (sig (ed25519-sign-string (.get keypair private-key) canonical)))
                  (hash-put! entry "keyId" (.get keypair key-id))
                  (hash-put! entry "signature" sig)))
              (hash-put! entries st entry))))))
    evidence-records)
  (def parent-dir (path-directory cache-file))
  (unless (file-exists? parent-dir)
    (create-directory* parent-dir))
  (def doc
    (hash ("schema" "deterministic-engineering.verification-cache.v2")
          ("entries" entries)))
  (when keypair
    (hash-put! doc "attestation"
      (hash ("algorithm" "Ed25519")
            ("keyId" (.get keypair key-id))
            ("publicKeyPath" (.get keypair public-key)))))
  (call-with-output-file cache-file
    (lambda (port)
      (write-json port doc)
      (newline port))))

;; Offline verifier for a signed multi-method verification report (`report.json`).
(def (verify-verification-report-attestation report-path (override-pub-key #f))
  (and (file-exists? report-path)
       (let* ((doc (call-with-input-file report-path (cut read-json <> object-as-hash: #t)))
              (att (and (hash-table? doc) (hash-get doc "attestation"))))
         (and (hash-table? att)
              (equal? (hash-get att "algorithm") "Ed25519")
              (let* ((pub (or override-pub-key (hash-get att "publicKeyPath")))
                     (sig (hash-get att "signature"))
                     (expected-kid (hash-get att "keyId"))
                     (expected-sha (hash-get att "payloadSha256"))
                     (actual-kid (and (string? pub) (file-exists? pub)
                                      (substring (sha256-of-file pub) 0 16)))
                     (admitted-raw (or (hash-get doc "verificationAdmitted") '()))
                     (admitted-flat (map (lambda (r) (if (pair? r) (car r) r)) admitted-raw))
                     (ev-raw (or (hash-get doc "evidence") '()))
                     (ev-rows
                       (map (lambda (e)
                              (list (or (hash-get e "step") "")
                                    (or (hash-get e "obligation") "")
                                    (or (hash-get e "method") "")
                                    (or (hash-get e "claimKind") "")
                                    (or (hash-get e "outcome") "")
                                    (or (hash-get e "detail") "")))
                            ev-raw))
                     (tc-pairs (hash-table->alist-strings (hash-get doc "toolchainFingerprints")))
                     (canonical
                       (canonical-report-signing-payload
                         (or (hash-get doc "subject") "")
                         (or (hash-get doc "requestId") "")
                         (or (hash-get doc "replayStatus") "")
                         (and (hash-get doc "replayValid") #t)
                         admitted-flat
                         ev-rows
                         tc-pairs))
                     (actual-sha (sha256-of-string canonical)))
                (and (equal? actual-kid expected-kid)
                     (equal? actual-sha expected-sha)
                     (ed25519-verify-string pub canonical sig)))))))

;; Strict offline trust-anchor verifier: NEVER reads publicKeyPath from untrusted report.json!
;; Checks both cryptographic Ed25519 signature against externally pinned `trusted-pub-key`
;; AND semantic admission (replayValid, zero mr/er findings, non-empty verificationAdmitted).
(def (verify-report-with-pinned-key report-path trusted-pub-key)
  (and (string? trusted-pub-key)
       (file-exists? trusted-pub-key)
       (verify-verification-report-attestation report-path trusted-pub-key)
       (let ((doc (call-with-input-file report-path (cut read-json <> object-as-hash: #t))))
         (and (hash-table? doc)
              (eq? (hash-get doc "replayValid") #t)
              (equal? (hash-get doc "mrFindings") '())
              (equal? (hash-get doc "mrOpenPremises") '())
              (equal? (hash-get doc "erFindings") '())
              (pair? (hash-get doc "verificationAdmitted"))))))

;; Strict 2-level Merkle verifier for a multi-subject Fleet report:
;; Verifies Fleet Ed25519 signature against pinned `trusted-pub-key`, AND verifies every
;; subject's individual report.json against the same pinned key & Merkle payloadSha256!
(def (verify-fleet-report-with-pinned-key fleet-report-path trusted-pub-key)
  (and (string? trusted-pub-key)
       (file-exists? trusted-pub-key)
       (file-exists? fleet-report-path)
       (let* ((doc (call-with-input-file fleet-report-path (cut read-json <> object-as-hash: #t)))
              (att (and (hash-table? doc) (hash-get doc "attestation")))
              (subjects (and (hash-table? doc) (hash-get doc "subjects"))))
         (and (hash-table? att)
              (list? subjects)
              (pair? subjects)
              (equal? (hash-get att "algorithm") "Ed25519")
              (let* ((expected-kid (hash-get att "keyId"))
                     (expected-sha (hash-get att "payloadSha256"))
                     (sig (hash-get att "signature"))
                     (actual-kid (substring (sha256-of-file trusted-pub-key) 0 16))
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
                         entries))
                     (actual-sha (sha256-of-string canonical)))
                (and (equal? actual-kid expected-kid)
                     (equal? actual-sha expected-sha)
                     (ed25519-verify-string trusted-pub-key canonical sig)
                     (andmap
                       (lambda (s)
                         (let* ((rel-path (hash-get s "reportRelativePath"))
                                (child-path (and (string? rel-path) (path-expand rel-path fleet-dir)))
                                (expected-child-sha (hash-get s "reportPayloadSha256")))
                           (and child-path
                                (verify-report-with-pinned-key child-path trusted-pub-key)
                                (let* ((cdoc (call-with-input-file child-path
                                               (cut read-json <> object-as-hash: #t)))
                                       (catt (and (hash-table? cdoc) (hash-get cdoc "attestation"))))
                                  (and (hash-table? catt)
                                       (equal? (hash-get catt "payloadSha256") expected-child-sha))))))
                       subjects)))))))

;; Pre-execute independent pending Fun-Flow waves concurrently across Gambit green threads
;; (each invoking an isolated OS subprocess), returning (values precomputed-tbl execution-metrics).
(def (execute-parallel-frontier-waves repo-root subject-obj spec reuse-plan)
  (def pending-names (and reuse-plan (.get reuse-plan pending)))
  (def waves (partition-parallel-frontier-waves (.get subject-obj steps)
                                                (.get subject-obj dag-edges)
                                                pending-names))
  (def tspec-by-name (make-hash-table))
  (for-each (lambda (ts) (hash-put! tspec-by-name (.get ts name) ts)) (.get spec targets))
  (def precomputed (make-hash-table))
  (def sum-ms 0)
  (def t0 (real-time))
  (for-each
    (lambda (wave)
      (def (run-one step-str)
        (def ts (hash-get tspec-by-name step-str))
        (def st0 (real-time))
        (def raw (dispatch-verification-operation
                   repo-root
                   (string->symbol step-str)
                   (.get ts operation)
                   (target-spec->payload ts)))
        (def dt-ms (inexact->exact (round (* 1000.0 (- (real-time) st0)))))
        (list step-str raw dt-ms))
      (def results
        (if (> (length wave) 1)
          (let ((threads (map (lambda (s) (spawn run-one s)) wave)))
            (map thread-join! threads))
          (map run-one wave)))
      (for-each
        (lambda (r)
          (hash-put! precomputed (car r) (cadr r))
          (set! sum-ms (+ sum-ms (caddr r))))
        results))
    waves)
  (def wall-ms (inexact->exact (round (* 1000.0 (- (real-time) t0)))))
  (values precomputed
          (.o bind-these: #f
              parallel?: #t
              wave-count: (length waves)
              waves: waves
              wall-ms: wall-ms
              sum-step-ms: sum-ms)))

;; Cache-aware Fun-Flow RuntimeAdapter: skips subprocess execution iff ASCENT IR01-IR06
;; explicitly admitted the step into `step_reusable`; serves parallel pre-executed receipts
;; in exact deterministic Fun-Flow order so `validate-replay-report` remains 100% valid.
(def (make-real-verification-runtime-adapter repo-root (reuse-plan #f) (cached-by-step #f) (precomputed-by-step #f))
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
        (def pre-rec (and precomputed-by-step (hash-get precomputed-by-step step-str)))
        (def raw-receipt
          (cond
           (cached-rec
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
           (pre-rec
            (set! executed (cons step-str executed))
            pre-rec)
           (else
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
       parallel?: (parallel? #t)
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

    ;; 4. Compute SHA-256 input closure, live verifier toolchain fingerprints (IR05),
    ;;    Ed25519 cache attestation verification (IR06), & ASCENT IR01-IR06 reuse gate.
    (def resolved-cache-dir (and cache-dir (path-expand cache-dir repo-root)))
    (def cache-file
      (and resolved-cache-dir (path-expand "verification-cache.v1.json" resolved-cache-dir)))
    (def keypair
      (cond
       (resolved-cache-dir (ensure-cache-signing-keypair! resolved-cache-dir))
       (output-dir (ensure-cache-signing-keypair!
                     (path-expand ".data/verification-keys" repo-root)))
       (else #f)))
    (def current-digests (if cache-file (compute-step-input-digests repo-root step-input-files) '()))
    (def current-toolchains (compute-step-toolchain-fingerprints repo-root subject-gov-sources))
    (def effective-policy-flags
      (if (and cache-file (not (member "require-signed-cache" policy-flags)))
        (cons "require-signed-cache" policy-flags)
        policy-flags))
    (let-values (((cached-w-rows cached-i-rows cached-tc-rows attested-steps cached-by-step)
                  (load-verification-cache cache-file (and keypair (.get keypair public-key)))))
      (def reuse-plan
        (if cache-file
          (reuse-result->plan
            (reason-incremental-reuse
              (build-incremental-reuse-sources
                subject-gov-sources
                step-mutability
                effective-policy-flags
                current-digests
                cached-w-rows
                cached-i-rows
                current-toolchains
                cached-tc-rows
                attested-steps)))
          #f))

      ;; 5. Execute independent pending DAG waves concurrently (if parallel?: #t),
      ;;    then drive the Fun-Flow DAG via upstream make-runner / runner-run so
      ;;    receipts and `validate-replay-report` stay 100% deterministic.
      (let-values (((precomputed-by-step exec-metrics)
                    (if parallel?
                      (execute-parallel-frontier-waves repo-root subject-obj (.get bundle spec) reuse-plan)
                      (values #f (.o bind-these: #f parallel?: #f wave-count: 0 waves: '() wall-ms: 0 sum-step-ms: 0)))))
      (def strategy
        (if cache-file (make-cached-local-eager-strategy) (make-local-eager-strategy)))
      (def adapter-bundle
        (make-real-verification-runtime-adapter repo-root reuse-plan cached-by-step precomputed-by-step))
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

      ;; 6. Extract VerificationEvidenceRecordType from Fun-Flow Receipt tree
      ;;    and admit against LIVE SysML v2 obligations/premises via ASCENT ER01-ER04!
      (def evidence-records (receipt-tree->evidence-records root-receipt))
      (def er-sources (governance+evidence->admission-sources subject-gov-sources evidence-records))
      (def er-result (reason-verification-evidence-admission er-sources))
      (def exec-stats ((.get adapter-bundle stats)))

      ;; Persist Ed25519-signed passing receipts into content-addressed cache if cache-dir enabled.
      (when cache-file
        (save-verification-cache!
          cache-file evidence-records current-digests cached-by-step
          current-toolchains keypair (.get exec-stats reused)))

      (def cache-summary
        (.o bind-these: #f
            enabled?: (and cache-file #t)
            cache-path: (or cache-file "")
            key-id: (if keypair (.get keypair key-id) "")
            attested-hits: attested-steps
            executed: (.get exec-stats executed)
            reused: (.get exec-stats reused)
            invalidations: (if reuse-plan (.get reuse-plan invalidations) '())))

      (def report-path
        (if output-dir
          (let ((resolved-out (path-expand output-dir repo-root)))
            (when (file-exists? resolved-out)
              (error "fresh verification output directory required" resolved-out))
            (create-directory resolved-out)
            (let* ((rpath (path-expand "report.json" resolved-out))
                   (admitted-rows (wire-rows ((.ref er-result 'rows-of) 'verification_admitted)))
                   (tc-hash (make-hash-table))
                   (tc-pairs (map (lambda (r)
                                    (hash-put! tc-hash (car r) (cadr r))
                                    (cons (car r) (cadr r)))
                                  current-toolchains))
                   (ev-rows (map (lambda (ev)
                                   (list (symbol->string (.get ev step))
                                         (symbol->string (.get ev obligation))
                                         (symbol->string (.get ev method))
                                         (symbol->string (.get ev claim-kind))
                                         (symbol->string (.get ev outcome))
                                         (.get ev detail)))
                                 evidence-records))
                   (canonical-rep
                     (canonical-report-signing-payload
                       (symbol->string subject-id)
                       request-id
                       (symbol->string (replay-report-status replay-rep))
                       (replay-report-valid? replay-rep)
                       (map car admitted-rows)
                       ev-rows
                       tc-pairs))
                   (report-doc
                     (hash
                       ("schema" "deterministic-engineering.multi-method-verification-report.v2")
                       ("subject" (symbol->string subject-id))
                       ("requestId" request-id)
                       ("sysmlSource" sysml-path)
                       ("funflowManifestSchema" (symbol->string (cdr (assoc 'schema dag-manifest))))
                       ("replayStatus" (symbol->string (replay-report-status replay-rep)))
                       ("replayValid" (replay-report-valid? replay-rep))
                       ("toolchainFingerprints" tc-hash)
                       ("mrFindings" (wire-rows mr-findings))
                       ("mrOpenPremises" (wire-rows mr-open-premises))
                       ("erFindings" (wire-rows ((.ref er-result 'rows-of) 'er_finding)))
                       ("obligationsPassed" (wire-rows ((.ref er-result 'rows-of) 'obligation_passed)))
                       ("premisesVerified" (wire-rows ((.ref er-result 'rows-of) 'premise_verified)))
                       ("verificationAdmitted" admitted-rows)
                       ("cacheSummary"
                        (hash ("enabled" (.get cache-summary enabled?))
                              ("cachePath" (.get cache-summary cache-path))
                              ("keyId" (.get cache-summary key-id))
                              ("executed" (.get cache-summary executed))
                              ("reused" (.get cache-summary reused))
                              ("invalidations" (wire-rows (.get cache-summary invalidations)))))
                       ("evidence" (map evidence-record->json-hash evidence-records)))))
              (when keypair
                (hash-put! report-doc "attestation"
                  (hash ("algorithm" "Ed25519")
                        ("keyId" (.get keypair key-id))
                        ("publicKeyPath" (.get keypair public-key))
                        ("payloadSha256" (sha256-of-string canonical-rep))
                        ("signature" (ed25519-sign-string (.get keypair private-key) canonical-rep)))))
              (call-with-output-file rpath
                (lambda (port)
                  (write-json port report-doc)
                  (newline port)))
              rpath))
          #f))

      (.o bind-these: #f
          sysml-projected: sysml-projected
          mr-result: mr-result
          reuse-plan: reuse-plan
          cache-summary: cache-summary
          execution-metrics: exec-metrics
          dag-receipt: dag-receipt
          dag-manifest: dag-manifest
          run-result: run-res
          replay-report: replay-rep
          evidence-records: evidence-records
          er-result: er-result
          report-path: report-path)))))

;; Multi-Subject Fleet Orchestrator: discovers EVERY subject declared in 10.154-*.sysml
;; dynamically, runs each in a GC-isolated scope against a shared Ed25519-signed cache,
;; and emits a 2-level Merkle-bound Ed25519-signed `fleet-report.json`.
(def (run-multi-method-fleet
       repo-root
       output-dir
       cache-dir: (cache-dir #f)
       policy-flags: (policy-flags '())
       fleet-id: (fleet-id "fleet-m5-001"))
  (def sysml-path
    (path-expand
      "docs/10-19-design/10-architecture/10.154-multi-method-funflow-runnable-and-leanpoo-architecture.sysml"
      repo-root))
  (def sysml-sha (sha256-of-file sysml-path))
  (def projected (project-sysml-model repo-root))
  (def subject-keys
    (map (lambda (sp) (string->symbol (.get sp subject-key)))
         (.get projected subject-specs)))
  (def resolved-out (path-expand output-dir repo-root))
  (when (file-exists? resolved-out)
    (error "fresh fleet output directory required" resolved-out))
  (create-directory* resolved-out)
  (def resolved-cache-dir (and cache-dir (path-expand cache-dir repo-root)))
  (def keypair
    (ensure-cache-signing-keypair!
      (or resolved-cache-dir (path-expand ".data/verification-keys" repo-root))))

  (def subject-hashes '())
  (def subject-canonical-entries '())
  (def total-executed 0)
  (def total-reused 0)
  (def all-admitted? #t)

  (for-each
    (lambda (skey)
      (let* ((skey-str (symbol->string skey))
             (sub-out (path-expand skey-str resolved-out))
             (outcome (run-multi-method-verification-pipeline repo-root
                        subject-key: skey
                        output-dir: sub-out
                        cache-dir: cache-dir
                        policy-flags: policy-flags
                        request-id: (string-append fleet-id "-" skey-str)))
             (rpath (.get outcome report-path))
             (rdoc (call-with-input-file rpath (cut read-json <> object-as-hash: #t)))
             (ratt (hash-get rdoc "attestation"))
             (rsha (or (and (hash-table? ratt) (hash-get ratt "payloadSha256")) ""))
             (sid (or (hash-get rdoc "subject") ""))
             (rvalid? (replay-report-valid? (.get outcome replay-report)))
             (er-res (.get outcome er-result))
             (admitted? (and rvalid?
                             (null? ((.ref er-res 'rows-of) 'er_finding))
                             (pair? ((.ref er-res 'rows-of) 'verification_admitted))))
             (csum (.get outcome cache-summary))
             (exec-list (.get csum executed))
             (reuse-list (.get csum reused)))
        (set! total-executed (+ total-executed (length exec-list)))
        (set! total-reused (+ total-reused (length reuse-list)))
        (unless admitted? (set! all-admitted? #f))
        (set! subject-canonical-entries
          (cons (list skey-str sid rsha rvalid? admitted?) subject-canonical-entries))
        (set! subject-hashes
          (cons (hash ("subjectKey" skey-str)
                      ("subjectId" sid)
                      ("reportRelativePath" (string-append skey-str "/report.json"))
                      ("reportPayloadSha256" rsha)
                      ("replayValid" rvalid?)
                      ("admitted" admitted?)
                      ("executed" exec-list)
                      ("reused" reuse-list))
                subject-hashes)))
      (##gc))
    subject-keys)

  (def ordered-entries (reverse subject-canonical-entries))
  (def canonical-fleet (canonical-fleet-signing-payload fleet-id sysml-sha ordered-entries))
  (def fleet-sha (sha256-of-string canonical-fleet))
  (def fleet-sig (ed25519-sign-string (.get keypair private-key) canonical-fleet))
  (def fleet-report-path (path-expand "fleet-report.json" resolved-out))
  (call-with-output-file fleet-report-path
    (lambda (port)
      (write-json
        port
        (hash ("schema" "deterministic-engineering.multi-method-fleet-report.v1")
              ("fleetId" fleet-id)
              ("sysmlSource" sysml-path)
              ("sysmlSha256" sysml-sha)
              ("allAdmitted" all-admitted?)
              ("totalExecuted" total-executed)
              ("totalReused" total-reused)
              ("subjects" (reverse subject-hashes))
              ("attestation"
               (hash ("algorithm" "Ed25519")
                     ("keyId" (.get keypair key-id))
                     ("publicKeyPath" (.get keypair public-key))
                     ("payloadSha256" fleet-sha)
                     ("signature" fleet-sig)))))
      (newline port)))
  (.o bind-these: #f
      fleet-report-path: fleet-report-path
      public-key-path: (.get keypair public-key)
      key-id: (.get keypair key-id)
      subject-keys: subject-keys
      all-admitted?: all-admitted?
      total-executed: total-executed
      total-reused: total-reused))

;; Zero-execution dry-run Change-Impact & Proof-Reuse Predictor across ALL SysML v2 subjects:
;; Evaluates ASCENT IR01-IR06 against live SHA-256 input closures, live toolchains, and the
;; Ed25519-signed cache WITHOUT spawning any formal engine (<1s).
(def (predict-fleet-reuse-plan
       repo-root
       cache-dir: (cache-dir #f)
       policy-flags: (policy-flags '()))
  (def projected (project-sysml-model repo-root))
  (def sysml-gov-sources (.get projected governance-sources))
  (def resolved-cache-dir (and cache-dir (path-expand cache-dir repo-root)))
  (def cache-file
    (and resolved-cache-dir (path-expand "verification-cache.v1.json" resolved-cache-dir)))
  (def pub-key
    (and resolved-cache-dir
         (let ((p (path-expand "attestation-ed25519.pub.pem" resolved-cache-dir)))
           (and (file-exists? p) p))))
  (def effective-flags
    (if (and cache-file (not (member "require-signed-cache" policy-flags)))
      (cons "require-signed-cache" policy-flags)
      policy-flags))
  (let-values (((cached-w-rows cached-i-rows cached-tc-rows attested-steps _by-step)
                (load-verification-cache cache-file pub-key)))
    (def total-pending 0)
    (def total-reusable 0)
    (def per-subject
      (map (lambda (spec)
             (def skey (string->symbol (.get spec subject-key)))
             (def sid (string->symbol (.get spec identity)))
             (def sub-gov (filter-governance-sources-for-subject sysml-gov-sources sid))
             (def mut (subject-spec->mutability spec))
             (def in-files (subject-spec->input-files spec))
             (def cur-digests (compute-step-input-digests repo-root in-files))
             (def cur-tc (compute-step-toolchain-fingerprints repo-root sub-gov))
             (def plan
               (reuse-result->plan
                 (reason-incremental-reuse
                   (build-incremental-reuse-sources
                     sub-gov mut effective-flags
                     cur-digests cached-w-rows cached-i-rows
                     cur-tc cached-tc-rows attested-steps))))
             (def p-steps (.get plan pending))
             (def r-steps (.get plan reusable))
             (set! total-pending (+ total-pending (length p-steps)))
             (set! total-reusable (+ total-reusable (length r-steps)))
             (.o bind-these: #f
                 subject-key: skey
                 identity: sid
                 pending: p-steps
                 reusable: r-steps
                 invalidations: (.get plan invalidations)))
           (.get projected subject-specs)))
    (.o bind-these: #f
        subjects: per-subject
        total-pending: total-pending
        total-reusable: total-reusable)))

(def (main mode-or-output . rest)
  (def repo-root (path-normalize (path-expand "../.." (path-directory (this-source-file)))))
  (cond
   ((equal? mode-or-output "--plan")
    (let* ((cache-dir (and (pair? rest) (> (string-length (car rest)) 0) (car rest)))
           (plan (predict-fleet-reuse-plan repo-root cache-dir: cache-dir)))
      (for-each
        (lambda (s)
          (displayln "SUBJECT " (.get s subject-key)
                     " pending=" (.get s pending)
                     " reusable=" (.get s reusable)))
        (.get plan subjects))
      (displayln "MULTI-METHOD-PLAN-OK pending=" (.get plan total-pending)
                 " reusable=" (.get plan total-reusable))))
   ((equal? mode-or-output "--fleet")
    (let* ((output-dir (car rest))
           (cache-dir (and (pair? (cdr rest)) (> (string-length (cadr rest)) 0) (cadr rest)))
           (res (run-multi-method-fleet repo-root output-dir cache-dir: cache-dir)))
      (unless (.get res all-admitted?)
        (error "multi-method fleet verification refused admission" (.get res fleet-report-path)))
      (displayln "MULTI-METHOD-FLEET-OK " (.get res fleet-report-path)
                 " subjects=" (length (.get res subject-keys))
                 " executed=" (.get res total-executed)
                 " reused=" (.get res total-reused))))
   (else
    (let* ((output-dir mode-or-output)
           (cache-dir (and (pair? rest) (> (string-length (car rest)) 0) (car rest)))
           (subject-key
             (if (and (pair? rest) (pair? (cdr rest)) (> (string-length (cadr rest)) 0))
               (string->symbol (cadr rest))
               'process-tree-reclamation))
           (outcome
             (run-multi-method-verification-pipeline repo-root
               subject-key: subject-key
               output-dir: output-dir
               cache-dir: cache-dir))
           (er-res (.get outcome er-result))
           (admitted ((.ref er-res 'rows-of) 'verification_admitted))
           (er-findings ((.ref er-res 'rows-of) 'er_finding)))
      (unless (and (replay-report-valid? (.get outcome replay-report))
                   (null? er-findings)
                   (pair? admitted))
        (error "multi-method verification pipeline refused admission"
               (list (replay-report-status (.get outcome replay-report))
                     er-findings
                     admitted)))
      (displayln "MULTI-METHOD-VERIFICATION-OK " (.get outcome report-path))))))

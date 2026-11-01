;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
;;; Rust mechanism method observation. Core Ops owns spawning/deadlines; native ASCENT
;;; evaluates relations. Flow owns context exchange; the method issuer verifies receipts.
(import
  :clan/poo/object
  :std/encoding/json
  (only-in :yuanxu/ops/process-script ProcessScript.)
  (only-in :std/crypto/digest sha256)
  (only-in :std/encoding/hex hex-encode)
  (only-in :std/misc/ports read-all-as-u8vector read-all-as-string)
  :gerbil-ascent/program/session
  (only-in :agentic-ai-lab/modules/ai-agentic-context/clue-exchange open-trajectory-clue-exchange)
  "oracle.ss"
  "correspondence.ss"
  (only-in
   "types.ss"
   resource-model-initializer
   ResourceNativeProfileContract
   ResourceNativeContextContract)
  (only-in :clan/poo/mop validate))
(export
  resource-digest-file
  resource-digest-value
  resource-write-json
  resource-real-scopes
  resource-run-qnt
  resource-run-lean
  resource-result-record
  resource-result-reference
  resource-result-claim
  resource-result-id
  resource-register-results!
  resource-result-current!
  resource-native-scopes
  resource-run-native
  resource-native-context
  resource-context-current!
  resource-run-integration
  resource-integration-scopes)

;; A saved JSON record is review material, never a constructor for an issued run.
(defstruct resource-result (payload identity footprint files) final: #t)
(def (resource-result-record result)
  (call-with-input-string
   (json->string (resource-result-payload result))
   (cut read-json <> object-as-hash: #t)))
(def (resource-result-id result)
  (unless (resource-result? result) (error "issued native method result required"))
  (string-copy (hash-ref (resource-result-payload result) "id")))
(def (resource-result-reference result) (string-copy (resource-result-identity result)))
(def (resource-digest-file path)
  (unless (eq? (file-info-type (file-info path #f)) 'regular)
    (error "method source/artifact must be an ordinary file" path))
  (hex-encode (sha256 (call-with-input-file path read-all-as-u8vector))))
(def (resource-digest-value value)
  (hex-encode (sha256 (string->utf8 (json->string value)))))
(def (resource-write-json path value)
  (call-with-output-file
      (list path: path truncate: #t)
    (lambda (port) (write-json port value) (newline port))))
(def (text path) (call-with-input-file path read-all-as-string))
(def (write-text path value)
  (call-with-output-file (list path: path truncate: #t) (cut display value <>)))
;; Domain-owned interpretation inputs; framework import/build closure is observed
;; by Core, rather than reconstructed by an application import walker.
(def (resource-interpretation-files root)
  (map
   (cut path-expand <> root)
   '("types.ss"
     "library/concurrency/resource-control/backpressure-memory/abstract/types.ss"
     "library/concurrency/resource-control/backpressure-memory/abstract/objects.ss"
     "library/concurrency/resource-control/backpressure-memory/abstract/config.ss"
     "library/concurrency/resource-control/backpressure-memory/abstract/interface.ss"
     "library/drivers/rust-resources/types.ss"
     "library/drivers/rust-resources/objects.ss"
     "library/drivers/rust-resources/config.ss"
     "library/drivers/rust-resources/interface.ss"
     "library/drivers/rust-resources/func.ss"
     "library/drivers/rust-resources/methods.ss"
     "library/drivers/rust-resources/oracle.ss"
     "library/drivers/rust-resources/correspondence.ss"
     "library/concurrency/resource-control/backpressure-memory/tokio-rayon/objects.ss"
     "library/concurrency/resource-control/backpressure-memory/tokio-rayon/types.ss"
     "library/concurrency/resource-control/backpressure-memory/tokio-rayon/config.ss"
     "library/concurrency/resource-control/backpressure-memory/tokio-rayon/interface.ss")))
(def (file-pairs paths) (map (lambda (path) (cons path (resource-digest-file path))) paths))
(def (assert-files! pairs)
  (for-each
   (lambda (pair)
     (unless (equal? (cdr pair) (resource-digest-file (car pair)))
       (error "method inputs or recorded artifacts changed" (car pair))))
   pairs))
(def (json-files pairs) (map (lambda (p) (list (car p) (cdr p))) pairs))
(def (command process-script out name argv)
  (def log (path-expand (string-append name ".log") out))
  (def receipt
    (.call
     (.cc process-script 'command argv 'directory out
          'timeout 45 'log log 'check-status #f)
     .run))
  (hash
   ("argv" argv)
   ("exit" (.ref receipt 'status))
   ("seconds" (.ref receipt 'seconds))
   ("timeoutSeconds" 45)
   ("log" log)
   ("logSha256" (resource-digest-file log))))
(def (json-read path) (call-with-input-file path (cut read-json <> object-as-hash: #t)))
(def (model-initializer profile mode)
  (or
   (resource-model-initializer profile mode)
   (error "unsupported QNT Profile/mode" (.get profile capacity) (.get profile queue) mode)))
(def (model-basis/input digest profile mode)
  (resource-digest-value
   (list
    "quint-tlc/safe/v1"
    digest
    (model-initializer profile mode)
    (if (eq? mode 'normal) "step" "earlyRelease")
    "five-jobs")))
(def (model-basis root profile mode)
  (model-basis/input
   (resource-digest-file
    (path-expand "library/concurrency/resource-control/backpressure-memory/model.qnt" root))
   profile
   mode))
(def (arithmetic-basis root profile)
  (resource-digest-value
   (list
    "lean/selected-budget/v1"
    (resource-digest-file
     (path-expand "library/concurrency/resource-control/backpressure-memory/budget.lean" root))
    "abstract-accounting-units"
    (map (cut .ref profile <>) '(queue capacity item fixed cache-bytes budget)))))
(def (resource-real-scopes root profile usage source (mode 'normal))
  (list
   (list usage 'model (model-basis root profile mode))
   (list usage 'arithmetic (arithmetic-basis root profile))
   (list usage 'source (resource-digest-file source))
   (list usage 'inventory (resource-digest-value '(waiting queued running returned cleanup done)))
   (list
    usage
    'runtime
    (resource-digest-value
     (map (cut .ref profile <>) '(runtime lock tokio-workers rayon-workers cpu-budget))))
   (list
    usage
    'workload
    (resource-digest-value
     (map (cut .ref profile <>) '(workload capacity queue cache-bytes))))
   (list usage 'cache (resource-digest-value (list (.ref profile 'cache-bytes))))))
(def (issue
      out
      obligation
      method
      outcome
      footprint
      commands
      inputs
      artifacts
      oracle
      (boundary
       "Local model/proof result; no Rust source correspondence, performance or execution authority"))
  (assert-files! inputs)
  (def record-path (path-expand "record.json" out))
  (def review-path (path-expand "review.json" out))
  (def record
    (hash
     ("schema" "rust.resource.method-observation.v1")
     ("obligation" (symbol->string obligation))
     ("method" (symbol->string method))
     ("outcome" (symbol->string outcome))
     ("footprint" (map (lambda (p) (list (symbol->string (car p)) (cdr p))) footprint))
     ("commands" commands)
     ("inputs" (json-files inputs))
     ("artifacts" (json-files (file-pairs artifacts)))
     ("boundary" boundary)))
  (resource-write-json record-path record)
  (def reference (string-append "sha256:" (resource-digest-file record-path)))
  (resource-write-json
   review-path
   (hash
    ("schema" "rust.resource.method-review.v1")
    ("result" reference)
    ("oracle" oracle)
    ("inputClosureUnchanged" #t)
    ("issuer" "local-Core-Ops-and-method-observer")
    ("authentication" "local-host-trust; no external signature")))
  (make-resource-result
   (hash
    ("observation" record)
    ("recordPath" record-path)
    ("reviewPath" review-path)
    ("id" (string-append "method-" (resource-digest-file record-path))))
   reference
   footprint
   (append inputs (file-pairs (append artifacts (list record-path review-path))))))
(def (resource-result-current! result)
  (unless (resource-result? result)
    (error "issued native method result required; JSON assertions are not issuers"))
  (assert-files! (resource-result-files result)))
(def (resource-run-qnt root profile executable out (mode 'normal))
  (def process-script ProcessScript.)
  (create-directory out)
  (def source (path-expand "library/concurrency/resource-control/backpressure-memory/model.qnt" root))
  (def before (file-pairs (append (list source executable) (resource-interpretation-files root))))
  (def selected-capacity (.ref profile 'capacity))
  (def selected-queue (.ref profile 'queue))
  (def frozen-profile
    (.o
      capacity: selected-capacity
      queue: selected-queue))
  (def basis (model-basis/input (cdr (assoc source before)) frozen-profile mode))
  (def copy (path-expand "BackpressureOwners.qnt" out))
  (write-text copy (text source))
  (unless (equal? (resource-digest-file copy) (cdr (assoc source before)))
    (error "model changed while capturing its owned input"))
  (def version (command process-script out "version" (list executable "--version")))
  (def result-path (path-expand "tlc-result.json" out))
  (def init (model-initializer frozen-profile mode))
  (def step (if (eq? mode 'normal) "step" "earlyRelease"))
  (def run
    (command
     process-script
     out
     "tlc"
     (list
      executable
      "verify"
      copy
      "--backend"
      "tlc"
      "--init"
      init
      "--step"
      step
      "--invariant"
      "safe"
      "--out"
      result-path)))
  (unless (file-exists? result-path) (error "QNT produced no structured result" run))
  (def report (json-read result-path))
  (def expected (if (eq? mode 'normal) "ok" "violation"))
  (unless (and
           (= (hash-ref version "exit") 0)
           (= (hash-ref run "exit") (if (eq? mode 'normal) 0 1))
           (equal? (hash-ref report "stage") "verifying")
           (equal? (hash-ref report "status") expected))
    (error "QNT did not complete the selected property check" run))
  (def commands (list version run))
  (def artifacts (list copy result-path (hash-ref version "log") (hash-ref run "log")))
  (def oracle
    (if (eq? mode 'normal)
        (resource-ownership-oracle selected-capacity selected-queue)
        (let* ((trace (path-expand "counter.itf.json" out))
               (machine (path-expand "counter-run.json" out))
               (negative
                (command
                 process-script
                 out
                 "counter"
                 (list
                  executable
                  "run"
                  copy
                  "--backend"
                  "typescript"
                  "--init"
                  init
                  "--step"
                  step
                  "--invariant"
                  "safe"
                  "--max-samples"
                  "1"
                  "--max-steps"
                  "1"
                  "--seed"
                  "42"
                  "--out-itf"
                  trace
                  "--out"
                  machine))))
          (unless (and
                   (= (hash-ref negative "exit") 1)
                   (equal? (hash-ref (json-read machine) "status") "violation"))
            (error "counter trace is not a method counterexample"))
          (set! commands (append commands (list negative)))
          (set! artifacts (append artifacts (list trace machine (hash-ref negative "log"))))
          (resource-counter-oracle trace))))
  (issue
   out
   'BP-O02
   'quint
   (if (eq? mode 'normal) 'pass 'fail)
   (list (cons 'model basis))
   commands
   before
   artifacts
   oracle))
(def (resource-run-lean root profile executable out)
  (def process-script ProcessScript.)
  (create-directory out)
  (def source
    (path-expand "library/concurrency/resource-control/backpressure-memory/budget.lean" root))
  (def before (file-pairs (append (list source executable) (resource-interpretation-files root))))
  (def params (map (cut .ref profile <>) '(queue capacity item fixed cache-bytes budget)))
  (def basis
    (resource-digest-value
     (list
      "lean/selected-budget/v1"
      (cdr (assoc source before))
      "abstract-accounting-units"
      params)))
  (def source-text (text source))
  (unless (equal? (hex-encode (sha256 (string->utf8 source-text))) (cdr (assoc source before)))
    (error "proof changed while capturing its owned input"))
  (def oracle (apply resource-budget-oracle params))
  (def within (hash-ref oracle "within"))
  (def selected (path-expand "SelectedBudget.lean" out))
  (def olean (path-expand "SelectedBudget.olean" out))
  (def (n index) (number->string (list-ref params index)))
  (write-text
   selected
   (string-append
    source-text
    "\ntheorem RustResources.selected_budget : "
    (if within "" "¬ ")
    "RustResources.retained "
    (n 0)
    " "
    (n 1)
    " "
    (n 2)
    " "
    (n 3)
    " "
    (n 4)
    " ≤ "
    (n 5)
    " := by decide\n"
    "#print axioms RustResources.selected_budget\n"
    "#print axioms RustResources.capacity_monotone\n"
    "#print axioms RustResources.budget_reuse\n"))
  (def version (command process-script out "version" (list executable "--version")))
  (def run (command process-script out "lean" (list executable "-o" olean selected)))
  (def output (text (hash-ref run "log")))
  (unless (and
           (= (hash-ref version "exit") 0)
           (= (hash-ref run "exit") 0)
           (andmap
            (lambda (name)
              (string-contains output (string-append "'RustResources." name "' does not depend on any axioms")))
            '("selected_budget" "capacity_monotone" "budget_reuse"))
           (not (string-contains output "sorryAx"))
           (not (string-contains output "error:"))
           (file-exists? olean))
    (error "Lean kernel/proposition/axiom receipt incomplete" run))
  (issue
   out
   'BP-O03
   'lean
   (if within 'pass 'fail)
   (list (cons 'arithmetic basis))
   (list version run)
   before
   (list selected olean (hash-ref version "log") (hash-ref run "log"))
   oracle))
(def (resource-result-claim result)
  (string-append
   (hash-ref (hash-ref (resource-result-payload result) "observation") "obligation")
   ":"
   (resource-digest-value
    (map
     (lambda (p) (list (symbol->string (car p)) (cdr p)))
     (resource-result-footprint result)))))
(def (result-clue result)
  (def record (resource-result-payload result))
  (def observation (hash-ref record "observation"))
  (hash
   ("id" (hash-ref record "id"))
   ("claim" (resource-result-claim result))
   ("polarity" (if (equal? (hash-ref observation "outcome") "pass") "support" "counter"))
   ("role" "observation")
   ("source" (hash-ref record "recordPath"))
   ("factors" (hash-ref observation "footprint"))
   ("links" '())))
(def (clue-digest clue context)
  (resource-digest-value
   (list
    (hash-ref context "sourceIdentity")
    (hash-ref clue "id")
    (hash-ref clue "claim")
    (hash-ref clue "polarity")
    (hash-ref clue "role")
    (hash-ref clue "source")
    (hash-ref clue "factors")
    (hash-ref clue "links"))))
(def (result-set-current! results)
  ;; Only this registration boundary shares checks; no prior read is trusted.
  (def expected (make-hash-table))
  (for-each
   (lambda (r)
     (unless (resource-result? r) (error "issued native method result required"))
     (for-each
      (lambda (pair)
        (def old (hash-get expected (car pair)))
        (when (and old (not (equal? old (cdr pair))))
          (error "conflicting expected content for one dependency path" (car pair)))
        (hash-put! expected (car pair) (cdr pair)))
      (resource-result-files r)))
   results)
  (hash-for-each
   (lambda (path digest)
     (unless (equal? digest (resource-digest-file path))
       (error "method inputs or recorded artifacts changed" path)))
   expected))
;; Private projection value, never a constructor for an issued method result.
(def (result-registration-rows result)
  (def record (resource-result-payload result))
  (def observation (hash-ref record "observation"))
  (def id (string->symbol (hash-ref record "id")))
  (def reference (resource-result-reference result))
  (def review-digest (resource-digest-file (hash-ref record "reviewPath")))
  (.o
    witness: (list
              id
              (string->symbol (hash-ref observation "obligation"))
              (string->symbol (hash-ref observation "method"))
              reference
              (string->symbol (hash-ref observation "outcome")))
    inputs: (map (lambda (pair) (list id (car pair) (cdr pair))) (resource-result-footprint result))
    checked: (list id reference (string-append "sha256:" review-digest))))
(def (resource-register-results! session results trajectory rules-path)
  (def rule-digest (resource-digest-file rules-path))
  (def by-id (make-hash-table))
  (result-set-current! results)
  (for-each (lambda (r) (hash-put! by-id (resource-result-id r) r)) results)
  (def exchange
    (open-trajectory-clue-exchange
     trajectory
     (lambda (id digest source context)
       (def found (hash-get by-id id))
       (and
        found
        (equal? rule-digest (resource-digest-file rules-path))
        (equal? source (hash-ref (resource-result-payload found) "recordPath"))
        (equal? digest (clue-digest (result-clue found) context))
        (let ((descriptor (resource-result-payload found)))
          (assert-files!
           (map
            (lambda (key)
              (or
               (assoc (hash-ref descriptor key) (resource-result-files found))
               (error "issued result closure incomplete" key)))
            '("recordPath" "reviewPath")))
          (resource-result-reference found))))
     (resource-digest-file rules-path)))
  (exchange 'submit (map result-clue results) 0)
  ;; Native attestation is read before any domain source transaction is made.
  (for-each
   (lambda (r)
     (def view (exchange 'query (resource-result-claim r)))
     (def descriptor (resource-result-payload r))
     (def observation (hash-ref descriptor "observation"))
     (def relation (if (equal? (hash-ref observation "outcome") "pass") "support" "counterevidence"))
     (unless (and
              (null? (hash-ref view "unavailable"))
              (find
               (lambda (row)
                 (and
                  (equal? (list-ref row 1) (hash-ref descriptor "id"))
                  (equal? (list-ref row 4) (resource-result-reference r))))
               (hash-ref view relation)))
       (error "native method attestation unavailable")))
   results)
  ;; Digest acquisition remains effectful; only the subsequent field/row
  ;; projection is declarative. Keep digest reads in result order, then retain
  ;; the existing reverse-result wire order.
  (def additions (reverse (map result-registration-rows results)))
  (result-set-current! results)
  (unless (equal? rule-digest (resource-digest-file rules-path))
    (error "rule source changed before registration"))
  ;; Historical observations are retained; only freshly attested method checks
  ;; enter this current view. The native Session remains the sole fact store.
  (def old (gerbil-ascent-session-run session))
  (def (union-rows relation additions)
    (foldl
     (lambda (row out) (if (member row out) out (cons row out)))
     ((.ref old 'rows-of) relation)
     additions))
  (gerbil-ascent-session-replace-sources!
   session
   (list
    (cons 'witness (union-rows 'witness (map (cut .get <> witness) additions)))
    (cons
     'witness_input
     (union-rows 'witness_input (apply append (map (cut .get <> inputs) additions))))
    (cons 'checked (map (cut .get <> checked) additions))))
  exchange)

(def (native-context-files root)
  (def (configs directory)
    (filter
     file-exists?
     (list
      (path-expand ".cargo/config" directory)
      (path-expand ".cargo/config.toml" directory))))
  (def parent-files
    (let loop
        ((dir root) (files '()))
      (def parent (path-directory (path-strip-trailing-directory-separator dir)))
      (def next (append files (configs dir)))
      (if (or (equal? parent dir) (equal? dir "/")) next (loop parent next))))
  (def cargo-home (getenv "CARGO_HOME" (path-expand ".cargo" (getenv "HOME"))))
  (append
   parent-files
   (filter
    file-exists?
    (list
     (path-expand "config" cargo-home)
     (path-expand "config.toml" cargo-home)))))
(def (native-environment)
  (map
   (lambda (key) (list key (getenv key "")))
   '("RUSTFLAGS" "CARGO_ENCODED_RUSTFLAGS" "RUSTC_WRAPPER" "RUSTC_WORKSPACE_WRAPPER"
     "CARGO_BUILD_TARGET" "CARGO_BUILD_RUSTFLAGS" "CARGO_PROFILE_DEV_PANIC" "CARGO_PROFILE_DEV_OPT_LEVEL"
     "RUSTUP_TOOLCHAIN" "CARGO_HOME")))
(def (native-source-basis crate)
  (resource-digest-value
   (map
    (lambda (p) (list p (resource-digest-file (path-expand p crate))))
    '("Cargo.toml" "src/main.rs"))))
(def (resource-native-scopes root crate cargo rustc size usage)
  (list
   (list usage 'source (native-source-basis crate))
   (list
    usage
    'runtime
    (resource-digest-value
     (list
      "cargo-locked-offline/current-thread/rayon1/unwind/v1"
      (resource-digest-file (path-expand "Cargo.toml" crate))
      (resource-digest-file (path-expand "Cargo.lock" crate))
      (resource-digest-file cargo)
      (resource-digest-file rustc)
      (native-environment)
      (json-files (file-pairs (native-context-files root))))))
   (list usage 'workload (resource-digest-value (list "native-six-case-suite/v1" size)))
   (list
    usage
    'inventory
    (resource-digest-file
     (path-expand "library/drivers/rust-resources/oracle.ss" root)))))
(def (resource-native-context
      selected-root
      selected-entry
      profile-input
      selected-crate
      selected-cargo
      selected-rustc
      selected-usage
      (selected-mode 'normal))
  (def selected-profile (validate ResourceNativeProfileContract profile-input))
  (unless (and (symbol? selected-usage) (string? selected-root) (string? selected-crate))
    (error "invalid native context selection"))
  (def generic
    (resource-real-scopes
     selected-root
     selected-profile
     selected-usage
     (path-expand "src/main.rs" selected-crate)
     selected-mode))
  (def captured-scopes
    (append
     (filter (lambda (r) (memq (cadr r) '(model arithmetic cache))) generic)
     (resource-native-scopes
      selected-root
      selected-crate
      selected-cargo
      selected-rustc
      (.ref selected-profile 'item)
      selected-usage)))
  (def captured-snapshot
    (resource-digest-value
     (list
      "native-resource/v2"
      (.ref selected-entry 'revision)
      (.ref selected-entry 'rules)
      (.ref selected-entry 'dependencies)
      (map
       (cut .ref selected-profile <>)
       '(identity
         capacity
         queue
         item
         fixed
         budget
         cache-bytes
         factors
         workload
         runtime
         inventory
         tokio-workers
         rayon-workers
         cpu-budget
         lock))
      (map (lambda (r) (list (symbol->string (cadr r)) (caddr r))) captured-scopes))))
  (def context
    (.o
      root: selected-root
      entry: selected-entry
      profile: selected-profile
      crate: selected-crate
      cargo: selected-cargo
      rustc: selected-rustc
      usage: selected-usage
      mode: selected-mode
      snapshot: captured-snapshot
      scopes: captured-scopes))
  (validate ResourceNativeContextContract context))
(def (resource-context-current! selected-context)
  (def context (validate ResourceNativeContextContract selected-context))
  (def expected
    (resource-native-context
     (.ref context 'root)
     (.ref context 'entry)
     (.ref context 'profile)
     (.ref context 'crate)
     (.ref context 'cargo)
     (.ref context 'rustc)
     (.ref context 'usage)
     (.ref context 'mode)))
  (unless (and
           (equal? (.ref expected 'snapshot) (.ref context 'snapshot))
           (equal? (.ref expected 'scopes) (.ref context 'scopes)))
    (error "native context no longer matches selected source/Profile/tools"))
  ;; Structural validation can rebind computed Profile fields. A currentness
  ;; check must retain the captured context identity after all checks succeed;
  ;; its normalized checking view is not a newly issued capture.
  selected-context)

(def (append-map fn xs) (apply append (map fn xs)))
(def (registry-inputs directory)
  (append-map
   (lambda (name)
     (def path (path-expand name directory))
     (case
         (file-info-type (file-info path #f))
       ((directory) (registry-inputs path))
       ((regular)
        (if (or
             (and
              (>= (string-length name) 3)
              (equal? (substring name (- (string-length name) 3) (string-length name)) ".rs"))
             (equal? name "Cargo.toml"))
            (list path)
            '()))
       (else '())))
   (directory-files directory)))
(def (resource-run-native root crate cargo rustc size out)
  (def process-script ProcessScript.)
  (unless (and (integer? size) (> size 0) (<= size 4096))
    (error "native bounded payload domain" size))
  (create-directory out)
  (unless (equal? (native-context-files root) (native-context-files out))
    (error "native output has an unbound Cargo configuration" out))
  (def source-scopes (resource-native-scopes root crate cargo rustc size 'native))
  (def footprint (map (lambda (r) (cons (cadr r) (caddr r))) source-scopes))
  (def source-files
    (append
     (native-context-files root)
     (map (cut path-expand <> crate) '("Cargo.toml" "Cargo.lock" "src/main.rs"))))
  (def before
    (file-pairs (append source-files (list cargo rustc) (resource-interpretation-files root))))
  (def owned (path-expand "input" out))
  (create-directory owned)
  (create-directory (path-expand "src" owned))
  (for-each
   (lambda (name)
     (def from (path-expand name crate))
     (def to (path-expand name owned))
     (write-text to (text from))
     (unless (equal? (resource-digest-file to) (cdr (assoc from before)))
       (error "native source changed while capturing" name)))
   '("Cargo.toml" "Cargo.lock" "src/main.rs"))
  (def manifest (path-expand "Cargo.toml" owned))
  (def cargo-version (command process-script out "cargo-version" (list cargo "--version")))
  (def compiler (command process-script out "rustc-version" (list rustc "-vV")))
  (def metadata
    (command
     process-script
     out
     "metadata"
     (list
      cargo
      "--config"
      (string-append "build.rustc=\"" rustc "\"")
      "metadata"
      "--offline"
      "--locked"
      "--format-version"
      "1"
      "--manifest-path"
      manifest)))
  (unless (and
           (= (hash-ref cargo-version "exit") 0)
           (= (hash-ref compiler "exit") 0)
           (= (hash-ref metadata "exit") 0))
    (error "native toolchain/metadata failed"))
  (def resolved (json-read (hash-ref metadata "log")))
  (unless (equal? (path-normalize (hash-ref resolved "workspace_root")) (path-normalize owned))
    (error "native experiment requires its captured isolated Cargo workspace"))
  (def dependency-files
    (append-map
     (lambda (pkg)
       (registry-inputs (path-directory (hash-ref pkg "manifest_path"))))
     (hash-ref resolved "packages")))
  (set! before (append before (file-pairs dependency-files)))
  (def target (path-expand "target" out))
  (def build
    (command
     process-script
     out
     "cargo-build"
     (list
      cargo
      "--config"
      (string-append "build.rustc=\"" rustc "\"")
      "build"
      "--offline"
      "--locked"
      "--manifest-path"
      manifest
      "--target-dir"
      target)))
  (unless (= (hash-ref build "exit") 0) (error "native Cargo build failed" build))
  (def executable (path-expand "debug/rust-resource-lifecycle" target))
  (def executable-before (resource-digest-file executable))
  (def result (path-expand "observations.json" out))
  (def run (command process-script out "native-run" (list executable result (number->string size))))
  (unless (and (= (hash-ref run "exit") 0) (equal? executable-before (resource-digest-file executable)))
    (error "native process failed or executable changed" run))
  (unless (equal? (native-context-files root) (native-context-files out))
    (error "native Cargo configuration changed at the execution directory" out))
  (def observed (json-read result))
  (unless (= size (hash-ref observed "payloadBytes")) (error "native payload invocation differs"))
  (def gold (resource-native-oracle observed))
  (unless (equal? source-scopes (resource-native-scopes root crate cargo rustc size 'native))
    (error "native scope changed during execution"))
  (def commands (list cargo-version compiler metadata build run))
  (def artifacts
    (append
     (list result executable)
     (map (cut path-expand <> owned) '("Cargo.toml" "Cargo.lock" "src/main.rs"))
     (map (cut hash-ref <> "log") commands)))
  (map
   (lambda (oracle)
     (def name (hash-ref oracle "case"))
     (def destination (path-expand name out))
     (create-directory destination)
     (issue
      destination
      (string->symbol (string-append "RL-" name))
      'native
      (if (equal? (hash-ref oracle "outcome") "pass") 'pass 'fail)
      footprint
      commands
      before
      artifacts
      oracle))
   gold))

;; Opt-in facets retain the native result issuer and its complete observation closure.
(def (resource-integration-scopes context sysml quint)
  (resource-context-current! context)
  (def root (.ref context 'root))
  (resource-slice-tool-scopes
   (.ref context 'usage)
   (resource-digest-value
    (list
     (resource-mapping-value (.get context entry mapping))
     (resource-mapping-value (.get context entry catalog))
     (resource-digest-file
      (path-expand
       (.get context entry catalog asset relative-path)
       root))
     (resource-digest-file
      (path-expand "library/drivers/rust-resources/objects.ss" root))
     (resource-digest-file
      (path-expand "library/drivers/rust-resources/types.ss" root))
     (resource-digest-file
      (path-expand "library/drivers/rust-resources/correspondence.ss" root))
     (resource-digest-file
      (path-expand "library/concurrency/resource-control/backpressure-memory/model.qnt" root))))
   (resource-digest-file sysml)
   (resource-digest-file quint)))
(def (resource-run-integration context native sysml quint out)
  (def process-script ProcessScript.)
  (resource-context-current! context)
  (unless (and (= (length native) 6) (andmap resource-result? native))
    (error "six issued native results required"))
  (result-set-current! native)
  (unless (equal?
           (map
            (lambda (r) (hash-ref (hash-ref (resource-result-payload r) "observation") "obligation"))
            native)
           '("RL-M01" "RL-M02" "RL-M03" "RL-M04" "RL-M05" "RL-M06"))
    (error "native integration case inventory differs"))
  (def root (.ref context 'root))
  (def original (resource-result-footprint (car native)))
  (unless (andmap
           (lambda (r)
             (and
              (equal? original (resource-result-footprint r))
              (equal? (hash-ref (hash-ref (resource-result-payload r) "observation") "method") "native")))
           native)
    (error "integration native inputs differ"))
  (for-each
   (lambda (p)
     (unless (member (list (.ref context 'usage) (car p) (cdr p)) (.ref context 'scopes))
       (error "native result differs from captured integration context" p)))
   original)
  (def observed-paths
    (map
     (lambda (r)
       (def artifacts (hash-ref (hash-ref (resource-result-payload r) "observation") "artifacts"))
       (def row (find (lambda (p) (equal? (path-strip-directory (car p)) "observations.json")) artifacts))
       (unless row (error "native observation artifact missing"))
       (car row))
     native))
  (unless (andmap (cut equal? <> (car observed-paths)) observed-paths)
    (error "native cases did not observe one captured run"))
  (def model (path-expand "library/concurrency/resource-control/backpressure-memory/model.qnt" root))
  (def mapper
    (path-expand "library/drivers/rust-resources/correspondence.ss" root))
  (def catalog-path
    (path-expand
     (.get context entry catalog asset relative-path)
     root))
  (def scopes (resource-integration-scopes context sysml quint))
  (def (scope key) (cons key (caddr (find (lambda (r) (eq? (cadr r) key)) scopes))))
  (def before
    (append
     (resource-result-files (car native))
     (file-pairs
      (append
       (list model mapper catalog-path sysml quint "/usr/bin/env")
       (resource-interpretation-files root)))
     (file-pairs
      (apply
       append
       (map
        (lambda (r)
          (list
           (hash-ref (resource-result-payload r) "recordPath")
           (hash-ref (resource-result-payload r) "reviewPath")))
        native)))))
  (def projections (resource-trace-projections (.get context entry) (json-read (car observed-paths))))
  (create-directory out)
  (def home (path-expand "sysml-home" out))
  (create-directory home)
  (def (sysml-command . args)
    (append (list "/usr/bin/env" "-i" (string-append "HOME=" home) "PATH=/usr/bin:/bin" sysml) args))
  (def sv (command process-script out "sysml-version" (sysml-command "-version")))
  (def qv (command process-script out "quint-version" (list quint "--version")))
  (unless (and (= (hash-ref sv "exit") 0) (= (hash-ref qv "exit") 0))
    (error "integration tool identity failed"))
  (def all-results
    (apply
     append
     (map
      (lambda (p)
        (def name (hash-ref p "case"))
        (def dir (path-expand name out))
        (create-directory dir)
        (def projection (path-expand "projection.json" dir))
        (resource-write-json projection p)
        (def notation (path-expand "ownership.sysml" dir))
        (write-text notation (resource-trace-sysml (.get context entry) p))
        (def runs
          (map
           (lambda (cut)
             (def label (hash-ref cut "label"))
             (def good (= (hash-ref cut "live") (hash-ref cut "reserved")))
             (def target (string-append "BackpressureSlice::" name "::cut_" label))
             (def run
               (command
                process-script
                dir
                (string-append "sysml-" label)
                (sysml-command
                 "-strict"
                 "-json"
                 "-instantiate"
                 (string-append "BackpressureSlice::" name)
                 (string-append "-validate=" target)
                 notation
                 catalog-path)))
             (def report (json-read (hash-ref run "log")))
             (unless (and
                      (= (hash-ref run "exit") (if good 0 1))
                      (= (hash-ref report "exit") (if good 0 1))
                      (equal? (hash-ref report "status") (if good "holds" "fails"))
                      (= (length (hash-ref report "checks")) 2)
                      (string-prefix?
                       (string-append
                        "assert constraint "
                        (symbol->string (.get context entry catalog constraint))
                        " on ")
                       (hash-ref (car (hash-ref report "checks")) "subject"))
                      (equal? (hash-ref (car (hash-ref report "checks")) "status") (if good "holds" "fails")))
               (error "SysML cut assertion differs from independent ownership check" name label run))
             run)
           (hash-ref p "cuts")))
        (def sysdir (path-expand "sysml" dir))
        (create-directory sysdir)
        (def sysresult
          (issue
           sysdir
           (string->symbol (string-append "SI-" name))
           'sysml
           (string->symbol (hash-ref p "outcome"))
           (append original (list (scope 'correspondence) (scope 'sysml-tool)))
           (cons sv runs)
           before
           (append (list projection notation) (map (cut hash-ref <> "log") (cons sv runs)))
           p
           "Concrete ownership assertions over observed native cuts; no behavioral refinement or native authority"))
        (def trace (path-expand "Trace.qnt" dir))
        (write-text trace (resource-trace-qnt (.get context entry) (text model) p))
        (def machine (path-expand "quint.json" dir))
        (def replay
          (command
           process-script
           dir
           "quint-path"
           (list
            quint
            "verify"
            trace
            "--backend"
            "tlc"
            "--main"
            "BackpressureOwners"
            "--init"
            "replayInit"
            "--step"
            "replayStep"
            "--invariant"
            "unfinished"
            "--out"
            machine)))
        (def reached (equal? (hash-ref p "outcome") "pass"))
        (unless (file-exists? machine)
          (error "Quint correspondence produced no structured result" name replay))
        (def report (json-read machine))
        ;; A violation of unfinished witnesses a complete path through the original
        ;; transitions plus the explicitly named queued-cancellation extension.
        (unless (and
                 (= (hash-ref replay "exit") (if reached 1 0))
                 (equal? (hash-ref report "stage") "verifying")
                 (equal? (hash-ref report "status") (if reached "violation" "ok")))
          (error "Quint path existence differs from independent native ownership result" name replay))
        (def qdir (path-expand "correspondence" dir))
        (create-directory qdir)
        (list
         sysresult
         (issue
          qdir
          (string->symbol (string-append "TM-" name))
          'correspondence
          (if reached 'pass 'fail)
          (append original (list (scope 'correspondence) (scope 'quint-tool)))
          (list qv replay)
          before
          (list projection trace machine (hash-ref qv "log") (hash-ref replay "log"))
          p
          "Bounded abstract path existence for one observed sequence; TLC exports no ITF witness here; queued cancellation extends base QNT; not all Rust executions")))
      projections)))
  (resource-context-current! context)
  (unless (equal? scopes (resource-integration-scopes context sysml quint))
    (error "integration mapping/tools changed"))
  (result-set-current! native)
  all-results)

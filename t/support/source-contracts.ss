;;; Real source observations through Core Ops. No project-specific rule engine.
(import
  :clan/poo/object
  :std/encoding/json
  :gerbil-ascent/program/session
  (only-in :gerbil-ascent/rules/declaration rule-module-program)
  (only-in :clan/poo/mop validate)
  (only-in :yuanxu/ops/process-script ProcessScript.)
  (only-in :std/crypto/digest sha256)
  (only-in :std/encoding/hex hex-encode)
  (only-in :std/misc/ports read-all-as-u8vector)
  (only-in :yuanxu/module-system/source/observations call-with-collected-module-sources)
  "source-contract-input.ss")
(export source-contract-test-support)

;; The constructor is private. A saved JSON report is not an issued observation.
(defstruct observation (record scopes files admit-current) final: #t)
(def (digest-file path)
  (unless (eq? (file-info-type (file-info path #f)) 'regular)
    (error "source-contract input must be an ordinary file" path))
  (hex-encode (sha256 (call-with-input-file path read-all-as-u8vector))))
(def (digest-value value)
  (hex-encode (sha256 (string->utf8 (json->string value)))))
(def (file-pairs paths)
  (map (lambda (path) (cons path (digest-file path))) paths))
(def (current-files! files)
  (for-each
    (lambda (pair)
      (unless (equal? (cdr pair) (digest-file (car pair)))
        (error "source-contract dependency changed" (car pair))))
    files))
(def (write-json-file path value)
  (call-with-output-file (list path: path truncate: #t)
    (lambda (port) (write-json port value) (newline port))))
(def (profile-value profile)
  (map (lambda (key) (list (symbol->string key) (.ref profile key)))
    '(identity language executor obligation factor method function enforce instrumentation units inputs expected-properties)))
(def (json-value value)
  ;; Stable JSON-compatible symbols in authored POO projections.
  (cond ((symbol? value) (symbol->string value))
        ((pair? value) (map json-value value))
        ((object? value)
         (map (lambda (key) (list (symbol->string key) (json-value (.ref value key))))
              (.all-slots value)))
        (else value)))
(def (admit-profile! entry profile)
  (unless (eq? (.get profile method) (.get profile executor method))
    (error "Profile method disagrees with its selected executor"))
  (unless (eq? (.get profile instrumentation requires-function?)
               (not (string=? (.get profile enforce) "")))
    (error "inconsistent contract instrumentation strategy"))
  (unless (member (list (.get profile factor) (.get profile obligation) (.get profile method))
                  (.get entry rules))
    (error "Profile is not an obligation of the selected Catalog"))
  (unless (and (pair? (.get profile units)) (pair? (.get profile inputs))
               (or (not (.get profile executor requires-properties?))
                   (pair? (.get profile expected-properties))))
    (error "source-contract Profile has an empty input/property closure"))
  (for-each
    (lambda (unit)
      (unless (member unit (.get profile inputs))
        (error "translation unit missing from declared inputs" unit)))
    (.get profile units)))

(def (contract-basis subject)
  ;; A projection of the selected leaf, not a source resolver or graph walker.
  ;; Module/currentness authority stays with Yuanxu's admitted owner.
  (def profile (validate (.get subject driver plan-library contracts profile) (.get subject profile)))
  (def tools (validate (.get subject driver plan-library contracts tools) (.get subject tools)))
  (def entry (.get subject entry))
  (admit-profile! entry profile)
  (list
    (cons 'source (digest-value
      (map (lambda (input) (list (car input) (cdr input))) (.get subject source-inputs))))
    (cons 'profile
      (digest-value (json-value
        (list (profile-value profile) (.get entry identity)
              (.get entry rules) (.get entry dependencies)))))
    (cons 'method
      (digest-value
        (list (map cdr (file-pairs (map (cut .ref tools <>)
                                   '(cbmc goto-cc goto-instrument cc cxx))))
              (json-value (.call (.get subject driver plan-library) plan (.get profile executor) profile)))))))

(def (contract-scopes subject usage)
  (map (lambda (pair) (list usage (car pair) (cdr pair))) (contract-basis subject)))
(def (contract-snapshot subject)
  (digest-value (map (lambda (pair) (list (symbol->string (car pair)) (cdr pair)))
                     (contract-basis subject))))
(def (command! out name arguments deadline)
  (def log-path (path-expand (string-append name ".log") out))
  (def receipt
    (.call (.cc ProcessScript. 'command arguments 'directory out
                 'timeout deadline 'log log-path 'check-status #f) .run))
  (.o status: (.get receipt status) log: log-path argv: arguments))
(def (require-success! command)
  (unless (equal? (.get command status) 0)
    (error "source-contract preparation/native command failed" (.get command log))))

(def (cbmc-outcome path status expected)
  (def messages (call-with-input-file path (cut read-json <> object-as-hash: #t)))
  (def results (apply append (map (lambda (row) (hash-ref row "result" '())) messages)))
  (def statuses (filter-map (lambda (row) (hash-get row "cProverStatus")) messages))
  (unless (and (pair? results) (= (length statuses) 1)
               (not (find (lambda (row) (equal? (hash-ref row "messageType" "") "ERROR")) messages)))
    (error "CBMC result is incomplete or unsupported" path))
  (unless (andmap (lambda (row) (member (hash-ref row "status") '("SUCCESS" "FAILURE"))) results)
    (error "CBMC has unknown properties; no witness issued" path))
  (when (find (lambda (row)
                (and (equal? (hash-ref row "status") "FAILURE")
                     (string-contains (hash-ref row "description" "") "unwind"))) results)
    (error "insufficient unwinding; no safety counter issued" path))
  (for-each
    (lambda (name)
      (unless (find (lambda (row) (equal? name (hash-ref row "description" ""))) results)
        (error "required independent property missing from CBMC result" name)))
    expected)
  (cond
    ((and (equal? status 0) (equal? statuses '("success"))
          (andmap (lambda (row) (equal? (hash-ref row "status") "SUCCESS")) results)) 'pass)
    ((and (equal? status 10) (equal? statuses '("failure"))
          (find (lambda (row) (equal? (hash-ref row "status") "FAILURE")) results)) 'fail)
    (else (error "unknown CBMC outcome; no witness issued" path))))

(def (contract-run subject out)
  (call-with-collected-module-sources
    (lambda (sources-current!)
      ;; This closure is issued by the existing native observation collector.
      ;; It observes the selected leaf and retains no hand-written Module list.
      (.call subject admit-current)
      (def profile (validate (.get subject driver plan-library contracts profile) (.get subject profile)))
      (def tools (validate (.get subject driver plan-library contracts tools) (.get subject tools)))
      (def basis (contract-basis subject))
      (when (file-exists? out) (error "fresh output directory required" out))
      (create-directory out)
      (def commands '())
      (def artifacts '())
      (def tool-inputs
        (file-pairs (map (cut .ref tools <>) '(cbmc goto-cc goto-instrument cc cxx))))
      (def (run name argv)
        (def result (command! out name argv (.get subject driver plan-library config timeout)))
        (set! commands (cons result commands))
        (set! artifacts (cons (.get result log) artifacts))
        result)
      (def absolute-units (.get subject translation-units))
      (def plan-library (.get subject driver plan-library))
      (def plan (.call plan-library plan (.get profile executor) profile))
      (def native-path (path-expand "subject" out))
      (def symbols
        (.o sources: absolute-units
            raw-module: (path-expand "subject.goto" out)
            checked-module: (path-expand "checked.goto" out)
            native-binary: native-path))
      (def tool-paths (.o (:: @ tools) native-binary: native-path))
      (def outcome 'pass)
      (for-each
        (lambda (step)
          (def arguments
            (apply append
              (map (lambda (argument)
                     (if (symbol? argument)
                         (let (bound (.ref symbols argument))
                           (if (list? bound) bound (list bound)))
                         (list argument)))
                   (.get step arguments))))
          (def command
            (run (symbol->string (.get step tool))
              (cons (.ref tool-paths (.get step tool)) arguments)))
          (if (eq? (.get step expected) 'solver)
              (let (checked (cbmc-outcome (.get command log) (.get command status)
                                         (.get plan expected-properties)))
                (when (eq? checked 'fail) (set! outcome 'fail)))
              (require-success! command))
          (set! artifacts
            (append (map (cut .ref symbols <>) (.get step artifacts)) artifacts)))
        (.get plan steps))
      (sources-current!)
      (.call subject admit-current)
      (unless (equal? basis (contract-basis subject))
        (error "selected source-contract leaf changed during execution"))
      (def report
        (hash ("schema" "source-contract.observation.v1")
              ("profile" (json-value (profile-value profile)))
              ("obligation" (symbol->string (.get profile obligation)))
              ("method" (symbol->string (.get profile method)))
              ("outcome" (symbol->string outcome))
              ("scopes" (map (lambda (pair) (list (symbol->string (car pair)) (cdr pair))) basis))
              ("commands" (map (lambda (row)
                                  (hash ("argv" (.get row argv)) ("status" (.get row status))
                                        ("log" (.get row log)))) (reverse commands)))
              ("boundary" "Native selected leaf; local issued result; no approval or whole-project claim")))
      (def path (path-expand "record.json" out))
      (write-json-file path report)
      (make-observation report basis
        (append tool-inputs (file-pairs (cons path artifacts)))
        (lambda ()
          (sources-current!)
          (.call subject admit-current)
          (unless (equal? basis (contract-basis subject))
            (error "issued result no longer matches the selected leaf")))))))

(def (contract-current! result)
  (unless (observation? result) (error "private issued source-contract result required"))
  ((observation-admit-current result))
  (current-files! (observation-files result))
)
(def (contract-result-record result)
  (unless (observation? result) (error "issued source-contract result required"))
  (call-with-input-string (json->string (observation-record result))
    (cut read-json <> object-as-hash: #t)))

(def (contract-register! session results)
  ;; No rehydration or approval is inferred. Currentness precedes the one native
  ;; Session mutation. Old witnesses remain; changed usage scopes reject reuse.
  (for-each contract-current! results)
  (def old (gerbil-ascent-session-run session))
  (def (rows relation) ((.get old rows-of) relation))
  (def witnesses '())
  (def inputs '())
  (def checked '())
  (for-each
    (lambda (result)
      (def record (observation-record result))
      (def reference (digest-value record))
      (def id (string->symbol (string-append "source-contract-" reference)))
      (set! witnesses
        (cons (list id (string->symbol (hash-ref record "obligation"))
                    (string->symbol (hash-ref record "method")) reference
                    (string->symbol (hash-ref record "outcome"))) witnesses))
      (set! inputs
        (append (map (lambda (pair) (list id (car pair) (cdr pair)))
                     (observation-scopes result)) inputs))
      ;; Attestation is the local, private issuer plus current artifact checks.
      ;; It is not a signature or external independent review approval.
      (set! checked (cons (list id reference reference) checked)))
    results)
  (def (union relation additions)
    (foldl (lambda (row rest) (if (member row rest) rest (cons row rest)))
           (rows relation) additions))
  (gerbil-ascent-session-replace-sources! session
    (list (cons 'witness (union 'witness witnesses))
          (cons 'witness_input (union 'witness_input inputs))
          (cons 'checked (union 'checked checked)))))

;; A development consumer interprets the selected declarative plan with Core Ops.
;; ASCENT remains the existing SDK engine; no runtime/store is implemented here.
(def (source-contract-test-support selected-plan-library evidence-library)
  (.o
    input: SourceContractInput.
    plan-library: selected-plan-library
    strategies: (.get selected-plan-library strategies)
    run: contract-run
    basis: contract-basis
    scopes: contract-scopes
    snapshot: contract-snapshot
    current!: contract-current!
    register!: contract-register!
    record: contract-result-record
    evidence:
    (.o open-review:
      (lambda (entry profile usage snapshot scopes)
        (def session
          (gerbil-ascent-open-session
            (rule-module-program ((.get evidence-library make-evidence)))))
        (gerbil-ascent-session-replace-sources! session
          ((.get evidence-library sources) entry profile usage snapshot scopes))
        session))))

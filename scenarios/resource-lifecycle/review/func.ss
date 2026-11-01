;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
;;; SDLC consumer of captured Library evidence; no result issuer or rule engine.
(import
  :clan/poo/object
  :std/encoding/json
  :std/list/list
  (only-in :std/crypto/digest sha256 Digest::sha256 digest-update! digest-final!)
  (only-in :std/encoding/hex hex-encode)
  :yuanxu/contribution/verification
  :agentic-ai-lab/lambda-aitia/modules/sdlc/objects
  :agentic-ai-lab/lambda-aitia/modules/sdlc/standards/nasa-review
  :agentic-ai-lab/lambda-aitia/modules/sdlc/standards/nasa-lifecycle
  (only-in
   :deterministic-engineering/library/drivers/rust-resources/oracle
   resource-native-oracle
   resource-ownership-oracle
   resource-counter-oracle
   resource-budget-oracle))
(export
  audit-backpressure-content
  make-backpressure-review
  verify-review-context
  verify-review-content
  backpressure-stage
  review-file-digest
  review-reference-path
  validate-producer-source-custody
  review-json-equal?)
(def (review-file-digest path buffer: (shared-buffer #f))
  (call-with-input-file
      path
    (lambda (port)
      (def context (Digest::sha256))
      (def buffer (or shared-buffer (make-u8vector 65536)))
      (unless (and (u8vector? buffer) (> (u8vector-length buffer) 0))
        (error "digest buffer must be nonempty bytes"))
      (let loop
          ()
        (def count (read-subu8vector buffer 0 (u8vector-length buffer) port))
        (unless (= count 0) (digest-update! context buffer 0 count) (loop)))
      (hex-encode (digest-final! context)))))
(def (load-json path) (call-with-input-file path (cut read-json <> object-as-hash: #t)))
(def (require-equal actual expected message)
  (unless (equal? actual expected) (error message actual expected)))
;; Historical producer source locations are explicit, sealed input custody.
;; The public validator issues no receipt and cannot install a reader binding.
(def producer-custody-selection 'not-selected)
(def (custody-directory path) (path-strip-trailing-directory-separator (path-normalize path)))
(def (load-producer-source-custody custody-path sources-path acceptance-path)
  (def sources (load-json sources-path))
  (def declared (assoc custody-path (hash-ref sources "files")))
  (unless declared (error "producer custody is absent from consumer source declaration" custody-path))
  (def custody-sha (review-file-digest custody-path))
  (require-equal custody-sha (cadr declared) "producer custody declaration changed")
  (def custody (load-json custody-path))
  (def acceptance (load-json acceptance-path))
  (def acceptance-sha (review-file-digest acceptance-path))
  (def report-path (hash-ref acceptance "report"))
  (def report-sha (review-file-digest report-path))
  (require-equal
   (hash-ref custody "schema")
   "backpressure.producer-source-custody/v1"
   "unsupported producer custody")
  (require-equal
   acceptance-sha
   (hash-ref custody "acceptanceSha256")
   "custody belongs to another acceptance")
  (require-equal report-sha (hash-ref acceptance "reportSha256") "accepted producer report changed")
  (require-equal report-sha (hash-ref custody "reportSha256") "custody belongs to another report")
  (def report (load-json report-path))
  (def inputs (hash-ref report "sourceInputs"))
  (def references (hash-ref custody "references"))
  (def origin (custody-directory (hash-ref custody "originRoot")))
  (def execution (custody-directory (hash-ref custody "executionRoot")))
  (require-equal execution (custody-directory (current-directory)) "custody execution root differs")
  (require-equal
   origin
   (custody-directory (path-directory (caar inputs)))
   "custody producer root differs")
  (unless (and (list? references) (= (length references) (length inputs)))
    (error "producer custody inventory is incomplete"))
  (def prefix (string-append origin "/"))
  (def selected (make-hash-table))
  (for-each
   (lambda (row)
     (unless (and (list? row) (= (length row) 3) (every string? row))
       (error "malformed producer custody reference"))
     (def original (car row))
     (def digest (cadr row))
     (def location (caddr row))
     (def expected (assoc original inputs))
     (unless (and
              expected
              (equal? digest (cadr expected))
              (not (hash-key? selected original))
              (> (string-length original) (string-length prefix))
              (equal? prefix (substring original 0 (string-length prefix))))
       (error "producer custody origin or version differs" original))
     (def relative (substring original (string-length prefix) (string-length original)))
     (require-equal
      (path-normalize location)
      (path-normalize (path-expand relative execution))
      "producer custody location is outside its selected source copy")
     (require-equal (review-file-digest location) digest "producer custody bytes differ")
     (hash-put! selected original (list (string-copy digest) (string-copy location))))
   references)
  (require-equal (review-file-digest custody-path) custody-sha "custody changed while checking")
  (vector
   (string-copy custody-path)
   custody-sha
   selected
   (string-copy sources-path)
   (review-file-digest sources-path)
   acceptance-sha
   report-sha))
(def (validate-producer-source-custody custody-path sources-path acceptance-path)
  (load-producer-source-custody custody-path sources-path acceptance-path)
  #t)
(def (select-producer-custody! acceptance-path)
  (def configured (getenv "BACKPRESSURE_PRODUCER_CUSTODY" #f))
  (if (eq? producer-custody-selection 'not-selected)
      (set!
       producer-custody-selection
       (and
        configured
        (load-producer-source-custody
         configured
         (getenv "BACKPRESSURE_REVIEW_SOURCES")
         acceptance-path)))
      (require-equal
       configured
       (and producer-custody-selection (vector-ref producer-custody-selection 0))
       "producer custody selection cannot change within a process"))
  (when producer-custody-selection
    (require-equal
     (review-file-digest acceptance-path)
     (vector-ref producer-custody-selection 5)
     "custody cannot retarget another acceptance"))
  producer-custody-selection)
(def (review-reference-path path expected)
  (def selected
    (and
     (vector? producer-custody-selection)
     (hash-ref (vector-ref producer-custody-selection 2) path #f)))
  (if selected
      (begin
        (require-equal expected (car selected) "producer reference version differs")
        (string-copy (cadr selected)))
      path))
(def (current-files pairs)
  (def buffer (make-u8vector 65536))
  (for-each
   (lambda (pair)
     (require-equal
      (review-file-digest (review-reference-path (car pair) (cadr pair)) buffer: buffer)
      (cadr pair)
      (string-append "review dependency changed: " (car pair))))
   pairs))
(def (review-json-equal? a b)
  (cond
   ((hash-table? a)
    (and
     (hash-table? b)
     (= (hash-length a) (hash-length b))
     (every
      (lambda (key) (and (hash-key? b key) (review-json-equal? (hash-ref a key) (hash-ref b key))))
      (hash-keys a))))
   ((pair? a)
    (and (pair? b) (review-json-equal? (car a) (car b)) (review-json-equal? (cdr a) (cdr b))))
   (else (equal? a b))))
(def (oracle-equal actual expected)
  (unless (review-json-equal? actual expected) (error "independent oracle differs")))
(def (artifact record suffix)
  (or
   (find
    (lambda (pair)
      (let (path (car pair))
        (and
         (>= (string-length path) (string-length suffix))
         (equal?
          suffix
          (substring path (- (string-length path) (string-length suffix)) (string-length path))))))
    (hash-ref record "artifacts"))
   (error "required raw artifact absent" suffix)))
(def (audit-backpressure-content-fresh acceptance-path target-selection)
  (unless (memq target-selection '(worker-owned caller-owned))
    (error "unsupported coding-method selection"))
  (def closure (make-hash-table))
  (def (track-files pairs)
    (for-each
     (lambda (pair)
       (def prior (hash-ref closure (car pair) #f))
       (when prior (require-equal prior (cadr pair) "conflicting dependency digests"))
       (hash-put! closure (car pair) (cadr pair)))
     pairs))
  (def (capture-file path) (track-files (list (list path (review-file-digest path)))))
  (when (vector? producer-custody-selection)
    (track-files
     (list
      (list (vector-ref producer-custody-selection 0) (vector-ref producer-custody-selection 1))
      (list (vector-ref producer-custody-selection 3) (vector-ref producer-custody-selection 4)))))
  (capture-file acceptance-path)
  (def acceptance (load-json acceptance-path))
  (require-equal
   (hash-ref acceptance "schema")
   "qualification.domain-owner-slice/v1"
   "wrong acceptance schema")
  (require-equal (hash-ref acceptance "qualified") #t "unqualified evidence")
  (def report-path (hash-ref acceptance "report"))
  (require-equal
   (review-file-digest report-path)
   (hash-ref acceptance "reportSha256")
   "accepted report changed")
  (track-files (list (list report-path (hash-ref acceptance "reportSha256"))))
  (def report (load-json report-path))
  (require-equal (hash-ref report "status") "passed" "investigation incomplete")
  (track-files (hash-ref report "sourceInputs"))
  (track-files (hash-ref report "queries"))
  (track-files (hash-ref report "nativeExchanges"))
  (def snapshot-path (hash-ref acceptance "sourceSnapshotManifest"))
  (require-equal
   (review-file-digest snapshot-path)
   (hash-ref acceptance "sourceSnapshotManifestSha256")
   "Core snapshot manifest changed")
  (track-files (list (list snapshot-path (hash-ref acceptance "sourceSnapshotManifestSha256"))))
  (def snapshot (load-json snapshot-path))
  (track-files
   (map
    (lambda (key)
      (list (path-expand key (hash-ref snapshot "snapshot")) (hash-ref (hash-ref snapshot "files") key)))
    (hash-keys (hash-ref snapshot "files"))))
  (def results (hash-ref report "results"))
  (require-equal (length results) 22 "result closure incomplete")
  (def counts (make-hash-table))
  (def native-paths '())
  (for-each
   (lambda (row)
     (def record (load-json (hash-ref row "recordPath")))
     (require-equal
      (review-json-equal? record (hash-ref row "observation"))
      #t
      "record differs from accepted observation")
     (capture-file (hash-ref row "recordPath"))
     (capture-file (hash-ref row "reviewPath"))
     (def review (load-json (hash-ref row "reviewPath")))
     (require-equal
      (hash-ref review "result")
      (string-append "sha256:" (review-file-digest (hash-ref row "recordPath")))
      "review is bound to different result")
     (track-files (hash-ref record "inputs"))
     (track-files (hash-ref record "artifacts"))
     (for-each
      (lambda (command)
        (track-files (list (list (hash-ref command "log") (hash-ref command "logSha256")))))
      (hash-ref record "commands"))
     (def method (hash-ref record "method"))
     (def observed (hash-ref record "outcome"))
     (def key (string-append method "/" observed))
     (hash-put! counts key (+ 1 (hash-ref counts key 0)))
     (def recorded-oracle (hash-ref review "oracle"))
     (cond
      ((equal? method "native")
       (def raw (car (artifact record "/observations.json")))
       (set! native-paths (cons raw native-paths))
       (def independent (resource-native-oracle (load-json raw)))
       (def gold
         (or
          (find (lambda (g) (equal? (hash-ref g "case") (hash-ref recorded-oracle "case"))) independent)
          (error "unknown native case")))
       (oracle-equal recorded-oracle gold)
       (require-equal observed (hash-ref gold "outcome") "producer outcome contradicts event oracle")
       (for-each
        (lambda (c) (require-equal (hash-ref c "exit") 0 "native process failed"))
        (hash-ref record "commands")))
      ((equal? method "quint")
       (if (equal? observed "pass")
           (begin
             (oracle-equal recorded-oracle (resource-ownership-oracle 1 1))
             (require-equal
              (hash-ref (load-json (car (artifact record "/tlc-result.json"))) "status")
              "ok"
              "TLC did not pass"))
           (oracle-equal recorded-oracle (resource-counter-oracle (car (artifact record ".itf.json"))))))
      ((equal? method "lean")
       (def budget (hash-ref recorded-oracle "budget"))
       (def planned (hash-ref recorded-oracle "planned"))
       (unless (member planned '(128 256)) (error "unsupported selected Lean budget"))
       (oracle-equal recorded-oracle (resource-budget-oracle 1 1 (/ planned 2) 0 0 budget))
       (require-equal budget 256 "budget scope differs")
       (require-equal observed "pass" "arithmetic check failed")
       (for-each
        (lambda (c) (require-equal (hash-ref c "exit") 0 "Lean command failed"))
        (hash-ref record "commands")))
      (else (error "unrecognized verification method" method))))
   results)
  (for-each
   (lambda (pair)
     (require-equal (hash-ref counts (car pair) 0) (cadr pair) "method/outcome inventory differs"))
   '(("native/pass" 15) ("native/fail" 3) ("quint/pass" 1) ("quint/fail" 1) ("lean/pass" 2)))
  (require-equal (length (delete-duplicates/hash native-paths)) 3 "native workload closure differs")
  (def gold '((0 0 0) (2 0 2) (7 1 8) (2 0 8) (7 1 14) (1 0 14) (7 1 21) (7 1 21) (6 2 22)))
  (require-equal (length (hash-ref report "queries")) 9 "ASCENT query closure incomplete")
  (for-each
   (lambda (pair expected)
     (def q (load-json (car pair)))
     (require-equal
      (map (lambda (relation) (length (hash-ref q relation))) '("support" "counter" "witness"))
      expected
      "ASCENT relation gold differs"))
   (hash-ref report "queries")
   gold)
  (def selected-dependencies
    (map (lambda (path) (list path (hash-ref closure path))) (hash-keys closure)))
  (current-files selected-dependencies)
  ;; Raw evidence of M06 is an adherence failure only when caller-owned is selected.
  (.o
    outcome: (if (eq? target-selection 'caller-owned) 'fail 'pass)
    report: report-path
    report-digest: (review-file-digest report-path)
    records: 22
    expected-counters: 4
    target: target-selection
    dependencies: (map (lambda (pair) (map string-copy pair)) selected-dependencies)))
;; One producer-private completed audit, not a receipt or a query-result cache.
;; Every hit streams the complete original dependency closure again. Public
;; presentations own their lists and strings; edits cannot alter this record.
(def completed-content-audit #f)
(def (copy-dependencies pairs)
  (map (lambda (pair) (map string-copy pair)) pairs))
(def (audit-presentation record target reused?)
  (let ((selected-report (string-copy (vector-ref record 2)))
        (selected-report-digest (string-copy (vector-ref record 3)))
        (selected-dependencies (copy-dependencies (vector-ref record 4)))
        (selected-target target)
        (selected-reused reused?))
    (.o
      outcome: (if (eq? selected-target 'caller-owned) 'fail 'pass)
      report: selected-report
      report-digest: selected-report-digest
      dependencies: selected-dependencies
      records: 22
      expected-counters: 4
      target: selected-target
      reused-content?: selected-reused)))
(def (audit-backpressure-content acceptance-path target-selection)
  (unless (memq target-selection '(worker-owned caller-owned))
    (error "unsupported coding-method selection"))
  (select-producer-custody! acceptance-path)
  (def selected-sha (review-file-digest acceptance-path))
  (def prior completed-content-audit)
  (if (and
       prior
       (equal? acceptance-path (vector-ref prior 0))
       (equal? selected-sha (vector-ref prior 1)))
      (begin
        (current-files (vector-ref prior 4))
        (audit-presentation prior target-selection #t))
      (let* ((fresh (audit-backpressure-content-fresh acceptance-path target-selection))
             (record
              (vector
               (string-copy acceptance-path)
               (string-copy selected-sha)
               (string-copy (.ref fresh 'report))
               (string-copy (.ref fresh 'report-digest))
               (copy-dependencies (.ref fresh 'dependencies)))))
        (unless (and
                 (equal? selected-sha (review-file-digest acceptance-path))
                 (equal? selected-sha (cadr (assoc acceptance-path (vector-ref record 4)))))
          (error "acceptance changed during content audit"))
        (set! completed-content-audit record)
        (audit-presentation record target-selection #f))))
(def (make-backpressure-review
      profile
      acceptance-path
      previous:
      (previous #f)
      sources:
      (sources-path (getenv "BACKPRESSURE_REVIEW_SOURCES")))
  (def source-manifest-digest (review-file-digest sources-path))
  (def source-manifest (load-json sources-path))
  (require-equal
   (hash-ref source-manifest "schema")
   "aitia.backpressure-consumer-sources/v1"
   "invalid consumer source manifest")
  (current-files (hash-ref source-manifest "files"))
  (def (profile-snapshot)
    (call-with-output-string
     (lambda (port)
       (write (map (cut .ref profile <>) '(identity subject revision scope software-class target)) port))))
  (def captured-profile (profile-snapshot))
  (unless (eq? (.ref profile 'identity) 'backpressure-coding-method/v1)
    (error "unsupported coding policy"))
  (require-equal (.ref profile 'subject) "rust.backpressure-lifecycle" "unsupported review subject")
  (unless previous
    (require-equal
     (.ref profile 'revision)
     "accepted-owner-slice/r1"
     "new revision requires explicit prior review"))
  (def selected-target (.ref profile 'target))
  (require-equal
   (.ref profile 'scope)
   (if (eq? selected-target 'caller-owned) "bounded-permit-method/M06" "bounded-permit-method/M01-M05")
   "scope does not name the selected coding method")
  (def audit (audit-backpressure-content acceptance-path selected-target))
  (def audited-files (map (lambda (pair) (map string-copy pair)) (.ref audit 'dependencies)))
  (def acceptance-digest (review-file-digest acceptance-path))
  (def project
    (sdlc-project (.ref profile 'subject) (.ref profile 'revision) (.ref profile 'scope) #t))
  (def context (.ref profile 'context))
  (def class-value (.ref profile 'software-class))
  (unless (eq? class-value 'a)
    (error "local applicability Profile requires class a; no NASA authority asserted"))
  (def context-request (nasa-context-request project class-value context))
  (def packet-text
    (json->string
     (hash
      ("schema" "aitia.backpressure-review-packet/v1")
      ("criterion" "SWE-061/p1")
      ("policy" "backpressure-coding-method/v1")
      ("subject" (.ref project 'subject))
      ("revision" (.ref project 'revision))
      ("scope" (.ref project 'scope))
      ("classification" "local-declared-class-a/no-institutional-attestation")
      ("selection" (symbol->string selected-target))
      ("outcome" (symbol->string (.ref audit 'outcome)))
      ("report" (.ref audit 'report))
      ("reportSha256" (.ref audit 'report-digest))
      ("consumerSources" sources-path)
      ("consumerSourcesSha256" source-manifest-digest)
      ("dependencies" audited-files))))
  (def packet-digest (hex-encode (sha256 (string->utf8 packet-text))))
  (def evidence
    (nasa-verifiable-evidence
     (nasa-criterion-evidence
      "BP061-content"
      project
      "SWE-061"
      "SWE-061/p1"
      "backpressure-independent-content-audit/v1"
      (.ref audit 'outcome))
     packet-digest))
  ;; An explicit rebase carries unresolved failures; this consumer implements no disposition authority.
  (def carried
    (if previous
        (begin
          (unless (and
                   (equal? (.ref (.ref previous 'project) 'subject) (.ref project 'subject))
                   (not (equal? (.ref (.ref previous 'project) 'revision) (.ref project 'revision))))
            (error "rebase requires same subject and a new revision"))
          (map
           (lambda (old)
             (nasa-verifiable-evidence
              (nasa-criterion-evidence
               (string-append "carried/" (.ref old 'identity))
               project
               "SWE-061"
               "SWE-061/p1"
               (.ref old 'producer)
               'fail)
              (.ref old 'artifact-digest)))
           (filter (lambda (e) (eq? (.ref e 'outcome) 'fail)) (.ref previous 'evidence))))
        '()))
  (def records (cons evidence carried))
  (def expected-request (nasa-evidence-request evidence))
  (def (check-declaration-current!)
    (require-equal
     (review-file-digest sources-path)
     source-manifest-digest
     "consumer source manifest changed")
    (current-files (hash-ref source-manifest "files"))
    (require-equal (profile-snapshot) captured-profile "review Profile changed"))
  (def (check-current!)
    (check-declaration-current!)
    (require-equal
     (review-file-digest acceptance-path)
     acceptance-digest
     "host-selected acceptance changed")
    (current-files audited-files)
    audit)
  (def (check-content-current!)
    (check-current!)
    (require-equal (.ref audit 'outcome) (.ref evidence 'outcome) "content outcome changed"))
  ;; Identity-bound native requests select existing checks; equal-looking
  ;; submitted data is never a request capability.
  (def request-checks
    (list
     (cons context-request check-declaration-current!)
     (cons expected-request check-content-current!)))
  (def (verify-operation request now until)
    (def selected (assq request request-checks))
    (and selected (begin ((cdr selected)) #t)))
  (def adapter (nasa-verification-adapter "backpressure-content-audit/v1" verify-operation))
  (let ((selected-project project)
        (selected-context context)
        (selected-adapter adapter)
        (selected-audit audit)
        (selected-context-request context-request)
        (selected-packet-digest packet-digest))
    (.o
      project: selected-project
      context: selected-context
      class: class-value
      policy: (nasa-stage-policy "backpressure-coding-method" '("SWE-061"))
      evidence: records
      adapter: selected-adapter
      context-request: selected-context-request
      content-request: expected-request
      current!: check-current!
      audit: selected-audit
      packet: (string-copy packet-text)
      packet-digest: (string-copy selected-packet-digest))))
(def (verify-review-context review now until)
  (yuanxu-verify (.ref review 'adapter) (.ref review 'context-request) now until))
(def (verify-review-content review now until)
  (yuanxu-verify (.ref review 'adapter) (.ref review 'content-request) now until))
(def (backpressure-stage review receipts now)
  ((.ref review 'current!))
  (def result
    (nasa-stage-gate
     (.ref review 'policy)
     (.ref review 'project)
     (.ref review 'class)
     (.ref review 'context)
     (.ref review 'evidence)
     (.ref review 'adapter)
     receipts
     now))
  ((.ref review 'current!))
  result)

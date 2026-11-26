;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Deep, small, reusable pure abstractions for `library/verification-flow` (10.154).
;;; Centralizes Fun-Flow external-step composition, receipt-tree projection,
;;; generic ASCENT program execution, and immutable fact/alist combinators so
;;; `methods.ss`, `syntax.ss`, `rules.ss`, and downstream runners stay concise.
;;; Zero I/O, zero subprocess execution.
(import
  :clan/poo/object
  (only-in :clan/poo/type validate element?)
  :gerbil-ascent/program/session
  (only-in :gerbil-ascent/rules/declaration rule-module-bindings)
  (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
           Fun
           AdapterResult
           adapter-result?
           adapter-result-status
           adapter-result-value
           adapter-result-error
           receipt?
           receipt-task
           receipt-kind
           receipt-output
           receipt-children
           external-flow
           flow-arr
           flow-then)
  "attestation.ss"
  "types.ss")
(export
  sym->str
  copy-fact
  alist-ref
  alist-replace
  filter-governance-sources-for-subject
  canonical-witness-signing-payload
  canonical-report-signing-payload
  canonical-fleet-signing-payload
  compute-expired-steps
  trust-store-key-admitted?
  safe-relative-child-path?
  partition-parallel-frontier-waves
  changed-files->affected-frontier
  flow-of
  run-ascent-program
  adapter-result->raw-receipt
  receipt-tree->evidence-records
  make-step-admitter
  make-external-admit-flow)

;; ── Canonical fact & immutable alist combinators ──

(def (copy-fact value)
  (cond
   ((string? value) (string-copy value))
   ((pair? value) (cons (copy-fact (car value)) (copy-fact (cdr value))))
   ((null? value) '())
   (else (error "unsupported governance fact cell" value))))

(def (alist-ref alist key (default #f))
  (let ((hit (and (list? alist) (assoc key alist))))
    (if hit (cdr hit) default)))

(def (alist-replace alist key new-val)
  (map (lambda (entry) (if (equal? (car entry) key) (cons key new-val) entry))
       alist))

;; Pure multi-subject slicer: restricts a repository-wide SysML v2 governance
;; source alist to a single subject's obligations, steps, DAG edges, and premises.
(def (filter-governance-sources-for-subject gov-sources subject-id)
  (def sid (sym->str subject-id))
  (def steps (filter (lambda (r) (equal? (cadr r) sid)) (alist-ref gov-sources 'flow_step '())))
  (def step-names (map car steps))
  (def (in-steps? s) (and (member s step-names) #t))
  (list
    (cons 'subject_obligation
          (filter (lambda (r) (equal? (car r) sid)) (alist-ref gov-sources 'subject_obligation '())))
    (cons 'subject_factor
          (filter (lambda (r) (equal? (car r) sid)) (alist-ref gov-sources 'subject_factor '())))
    (cons 'method_allows_claim (alist-ref gov-sources 'method_allows_claim '()))
    (cons 'flow_step steps)
    (cons 'flow_dag_edge
          (filter (lambda (r) (and (in-steps? (car r)) (in-steps? (cadr r))))
                  (alist-ref gov-sources 'flow_dag_edge '())))
    (cons 'step_produces
          (filter (lambda (r) (in-steps? (car r))) (alist-ref gov-sources 'step_produces '())))
    (cons 'step_consumes
          (filter (lambda (r) (in-steps? (car r))) (alist-ref gov-sources 'step_consumes '())))
    (cons 'step_requires_premise
          (filter (lambda (r) (in-steps? (car r))) (alist-ref gov-sources 'step_requires_premise '())))
    (cons 'step_supports_premise
          (filter (lambda (r) (in-steps? (car r))) (alist-ref gov-sources 'step_supports_premise '())))
    (cons 'correspondence_bridge (alist-ref gov-sources 'correspondence_bridge '()))
    (cons 'stateful_quint_step
          (filter (lambda (r) (in-steps? (car r))) (alist-ref gov-sources 'stateful_quint_step '())))
    (cons 'step_countermodel
          (filter (lambda (r) (in-steps? (car r))) (alist-ref gov-sources 'step_countermodel '())))
    (cons 'declared_os_containment
          (filter (lambda (r) (equal? (car r) sid)) (alist-ref gov-sources 'declared_os_containment '())))))

;; ── Injection-proof canonical payload framing for Ed25519 cache & report attestation ──

;; Pure TTL evaluator for IR08: given `((step . issued-epoch) ...)` alist, `now-epoch`,
;; and `ttl-seconds` (or #f when TTL disabled), returns list of expired step-name strings
;; (also rejects future-dated timestamps where issued-epoch > now-epoch).
(def (compute-expired-steps issued-alist now-epoch ttl-seconds)
  (if (and (exact-integer? ttl-seconds) (>= ttl-seconds 0) (exact-integer? now-epoch))
    (filter-map
      (lambda (entry)
        (def st (sym->str (car entry)))
        (def issued (cdr entry))
        (and (or (not (exact-integer? issued))
                 (> issued now-epoch)
                 (> (- now-epoch issued) ttl-seconds))
             st))
      issued-alist)
    '()))

;; Pure Multi-Key Trust Store admission predicate (delegates to zero-dependency `attestation.ss`).
(def (trust-store-key-admitted? trust-store key-id)
  (and (object? trust-store)
       (trust-store-alist-key-admitted?
         (.get trust-store trusted-keys)
         (.get trust-store revoked-key-ids)
         key-id)))

;; Pure topological wave partitioner for conflict-free parallel Fun-Flow frontier execution.
;; Respects explicit `dag-edges` AND implicit Cargo/target-dir exclusivity between
;; `de-source-contract` and `de-native-oracle` steps within the same subject.
;; Returns a list of waves, where each wave is a list of step-name strings safe to run concurrently.
(def (partition-parallel-frontier-waves steps dag-edges (pending-names #f))
  (def all-names (map (lambda (st) (symbol->string (.get st identity))) steps))
  (def active-names
    (if pending-names
      (filter (lambda (n) (and (member n pending-names) #t)) all-names)
      all-names))
  (def (in-active? n) (and (member n active-names) #t))
  (def family-by-name
    (map (lambda (st)
           (cons (symbol->string (.get st identity))
                 (.get (.get st family) identity)))
         steps))
  ;; Explicit DAG edges restricted to active pending steps.
  (def explicit-edges
    (filter (lambda (e) (and (in-active? (car e)) (in-active? (cadr e))))
            (map (lambda (e) (list (sym->str (car e)) (sym->str (cadr e)))) dag-edges)))
  ;; Implicit exclusivity edges: de-source-contract -> de-native-oracle (prevents Cargo lock contention).
  (def source-steps
    (filter (lambda (n) (eq? (alist-ref family-by-name n #f) 'de-source-contract)) active-names))
  (def oracle-steps
    (filter (lambda (n) (eq? (alist-ref family-by-name n #f) 'de-native-oracle)) active-names))
  (def implicit-edges
    (apply append
      (map (lambda (s) (map (lambda (o) (list s o)) oracle-steps)) source-steps)))
  (def edges (append explicit-edges implicit-edges))
  (let loop ((remaining active-names) (done '()) (waves '()))
    (if (null? remaining)
      (reverse waves)
      (let ((ready
             (filter
               (lambda (n)
                 (andmap (lambda (e)
                           (or (not (equal? (cadr e) n))
                               (and (member (car e) done) #t)))
                         edges))
               remaining)))
        (unless (pair? ready)
          (error "cycle detected in verification DAG frontier" remaining edges))
        (loop (filter (lambda (n) (not (member n ready))) remaining)
              (append ready done)
              (cons ready waves))))))

;; Pure static change-impact analyzer directly from SysML v2 `projected` specs + `changed-paths`.
;; Computes both direct dirty steps (whose `input-files` intersect `changed-paths`) AND
;; transitive downstream steps along `dag-edges` (matching IR03 closure) with ZERO I/O.
(def (changed-files->affected-frontier projected changed-paths)
  (def norm-changed
    (map (lambda (p) (if (and (>= (string-length p) 2) (equal? (substring p 0 2) "./"))
                       (substring p 2 (string-length p))
                       p))
         changed-paths))
  (def (touches-any? files)
    (ormap (lambda (f) (and (member f norm-changed) #t)) files))
  (map
    (lambda (spec)
      (def skey (string->symbol (.get spec subject-key)))
      (def sid (string->symbol (.get spec identity)))
      (def targets (.get spec targets))
      (def edges (.get spec dag-edges))
      (def direct
        (filter-map
          (lambda (ts) (and (touches-any? (.get ts input-files)) (.get ts name)))
          targets))
      ;; Fixed-point transitive closure along `dag-edges` (producer -> consumer).
      (def affected
        (let loop ((cur direct))
          (def added
            (filter-map
              (lambda (e)
                (and (member (car e) cur)
                     (not (member (cadr e) cur))
                     (cadr e)))
              edges))
          (if (null? added)
            cur
            (loop (append cur added)))))
      (def all-names (map (lambda (ts) (.get ts name)) targets))
      (def unaffected (filter (lambda (n) (not (member n affected))) all-names))
      (.o bind-these: #f
          subject-key: skey
          identity: sid
          direct-steps: direct
          affected-steps: affected
          unaffected-steps: unaffected))
    (.get projected subject-specs)))

;; Polymorphic unwrapper: extracts `.flow` from a VerificationStep or passes a Flow through.
(def (flow-of step-or-flow)
  (if (and (object? step-or-flow) (.slot? step-or-flow 'flow))
    (.get step-or-flow flow)
    step-or-flow))

;; ── Generic stratified ASCENT program runner ──

(def (run-ascent-program prog decl label replacements)
  (def expected (.ref prog 'source-handles))
  (unless (and (list? replacements) (andmap pair? replacements))
    (error (string-append label " replacements must be an alist")))
  (for-each
    (lambda (entry)
      (unless (memq (car entry) expected)
        (error (string-append "unknown " label " input source") (car entry))))
    replacements)
  (for-each
    (lambda (handle)
      (unless (assq handle replacements)
        (error (string-append "missing " label " input source") handle)))
    expected)
  (def prepared (map (lambda (entry) (cons (car entry) (copy-fact (cdr entry)))) replacements))
  (def session (gerbil-ascent-open-session prog))
  (def result
    (gerbil-ascent-session-replace-sources!
      session
      prepared
      (lambda (prospective)
        (and (.ref prospective 'finished)
             (andmap
               (lambda (entry)
                 (let ((actual ((.ref prospective 'rows-of) (car entry))) (wanted (cdr entry)))
                   (and (andmap (cut member <> wanted) actual)
                        (andmap (cut member <> actual) wanted))))
               prepared)))))
  (unless (.ref result 'finished)
    (error (string-append label " evaluation incomplete")))
  (def native-rows (.ref result 'rows-of))
  (def out-bindings
    (filter (lambda (binding) (not (memq (cdr binding) expected)))
            (rule-module-bindings decl)))
  (.o program: prog
      output-bindings: (lambda () (map (lambda (b) (cons (car b) (cdr b))) out-bindings))
      rows-of: (lambda (name) (copy-fact (native-rows name)))))

;; ── Fun-Flow runtime-boundary unwrapper, receipt collector & step combinators ──

(def (adapter-result->raw-receipt res)
  (cond
   ((element? VerificationRawReceiptType res) res)
   ((adapter-result? res)
    (def val (adapter-result-value res))
    (if (element? VerificationRawReceiptType val)
      val
      (validate VerificationRawReceiptType
        (.o step: 'adapter-error
            exit-code: (if (eq? (adapter-result-status res) 'ok) 0 1)
            artifacts: '()
            summary: (let ((err (adapter-result-error res)))
                       (if (string? err)
                         err
                         (string-append "adapter status="
                                        (symbol->string (adapter-result-status res)))))))))
   (else
    (error "expected AdapterResult or VerificationRawReceiptType" res))))

(def (admit-task-symbol? sym)
  (and (symbol? sym)
       (let* ((s (symbol->string sym))
              (n (string-length s)))
         (and (>= n 6) (equal? (substring s (- n 6) n) "-admit")))))

(def (receipt-tree->evidence-records root-receipt)
  (unless (receipt? root-receipt)
    (error "receipt-tree->evidence-records expects a Fun-Flow receipt" root-receipt))
  (def acc '())
  (let walk ((node root-receipt))
    (when (and (eq? (receipt-kind node) 'pure)
               (admit-task-symbol? (receipt-task node))
               (element? VerificationEvidenceRecordType (receipt-output node)))
      (set! acc (cons (receipt-output node) acc)))
    (for-each walk (receipt-children node)))
  (reverse acc))

(def (make-step-admitter obl-id method-id ck-id)
  (lambda (receipt-or-adapter)
    (def raw (adapter-result->raw-receipt receipt-or-adapter))
    (validate VerificationEvidenceRecordType
      (.o step: (.get raw step)
          obligation: obl-id
          method: method-id
          claim-kind: ck-id
          outcome: (if (= (.get raw exit-code) 0) 'pass 'fail)
          detail: (.get raw summary)))))

(def (make-external-admit-flow step-id op payload in-contract out-contract admit-proc)
  (flow-then step-id
    (external-flow step-id op payload (Fun AdapterResult <- in-contract))
    (flow-arr (string->symbol (string-append (symbol->string step-id) "-admit"))
              (Fun out-contract <- AdapterResult)
              (lambda (res) (admit-proc (adapter-result->raw-receipt res))))))

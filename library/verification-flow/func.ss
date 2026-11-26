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
  "types.ss")
(export
  sym->str
  copy-fact
  alist-ref
  alist-replace
  flow-of
  run-ascent-program
  adapter-result->raw-receipt
  receipt-tree->evidence-records
  make-step-admitter
  make-external-admit-flow)

;; ── Canonical fact & immutable alist combinators ──

(def (sym->str x)
  (if (symbol? x) (symbol->string x) x))

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

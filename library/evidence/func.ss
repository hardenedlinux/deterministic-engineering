;;; -*- Gerbil -*-
(import
  :clan/poo/object
  :gerbil-ascent/rules/interface
  (only-in :gerbil-ascent/rules/declaration rule-module-program))
(export
  make-resource-evidence
  resource-review-sources)

;; Finite project rules over native Evidence sources. Host-supplied checked rows
;; record method validation; inferred support never authorizes execution.
(define-program
  (make-resource-evidence)
  (sources application catalog_rule catalog_dependency catalog_factor_rule factor scope witness witness_input checked)
  (outputs
   obligation
   requires
   support
   unopposed_support
   counter
   pending
   mismatch
   missing_input
   extra_input
   applicable
   t_use
   uncovered_factor)
  (relation application ((usage symbol?) (snapshot string?) (entry symbol?)))
  (relation catalog_rule ((entry symbol?) (factor symbol?) (obligation symbol?) (method symbol?)))
  (relation catalog_dependency ((entry symbol?) (obligation symbol?) (key symbol?)))
  (relation catalog_factor_rule ((entry symbol?) (left symbol?) (right symbol?) (derived symbol?)))
  (relation factor ((usage symbol?) (factor symbol?)))
  (relation scope ((usage symbol?) (key symbol?) (digest string?)))
  (relation
   witness
   ((id symbol?)
    (obligation symbol?)
    (method symbol?)
    (validation string?)
    (outcome symbol?)))
  (relation witness_input ((id symbol?) (key symbol?) (digest string?)))
  (relation checked ((id symbol?) (validation string?) (review string?)))
  (relation obligation ((usage symbol?) (obligation symbol?) (method symbol?)))
  (relation requires ((usage symbol?) (obligation symbol?) (key symbol?)))
  (relation covered_factor ((entry symbol?) (factor symbol?)))
  (relation uncovered_factor ((usage symbol?) (factor symbol?)))
  (relation candidate ((usage symbol?) (obligation symbol?) (method symbol?) (witness symbol?)))
  (relation blocked ((usage symbol?) (obligation symbol?) (witness symbol?)))
  (relation
   mismatch
   ((usage symbol?)
    (obligation symbol?)
    (witness symbol?)
    (key symbol?)
    (expected string?)
    (observed string?)))
  (relation missing_input ((usage symbol?) (obligation symbol?) (witness symbol?) (key symbol?)))
  (relation extra_input ((usage symbol?) (obligation symbol?) (witness symbol?) (key symbol?)))
  (relation applicable ((usage symbol?) (obligation symbol?) (witness symbol?)))
  (relation
   support
   ((usage symbol?)
    (obligation symbol?)
    (witness symbol?)
    (validation string?)
    (review string?)))
  (relation
   counter
   ((usage symbol?)
    (obligation symbol?)
    (witness symbol?)
    (validation string?)
    (review string?)))
  (relation supported ((usage symbol?) (obligation symbol?)))
  (relation unopposed_support ((usage symbol?) (obligation symbol?)))
  (relation pending ((usage symbol?) (obligation symbol?) (method symbol?)))
  (relation t_use ((usage symbol?) (snapshot string?) (obligation symbol?) (witness symbol?)))
  ((factor U D)
   <--
   (application U S E)
   (catalog_factor_rule E L R D)
   (factor U L)
   (factor U R))
  ((obligation U O M) <-- (application U S E) (factor U F) (catalog_rule E F O M))
  ((requires U O K) <-- (application U S E) (obligation U O M) (catalog_dependency E O K))
  ((covered_factor E F) <-- (catalog_rule E F O M))
  ((uncovered_factor U F) <-- (application U S E) (factor U F) (not (covered_factor E F)))
  ((candidate U O M W) <-- (obligation U O M) (witness W O M V R))
  ((mismatch U O W K D A)
   <--
   (candidate U O M W)
   (requires U O K)
   (scope U K D)
   (witness_input W K A)
   (if (D A) (not (equal? D A))))
  ((missing_input U O W K)
   <--
   (candidate U O M W)
   (requires U O K)
   (not (witness_input W K _)))
  ((missing_input U O W K)
   <--
   (candidate U O M W)
   (requires U O K)
   (not (scope U K _)))
  ((extra_input U O W K)
   <--
   (candidate U O M W)
   (witness_input W K D)
   (not (requires U O K)))
  ((blocked U O W) <-- (mismatch U O W K D A))
  ((blocked U O W) <-- (missing_input U O W K))
  ((blocked U O W) <-- (extra_input U O W K))
  ((applicable U O W) <-- (candidate U O M W) (not (blocked U O W)))
  ((support U O W V A) <-- (applicable U O W) (witness W O M V (lit 'pass)) (checked W V A))
  ((counter U O W V A) <-- (applicable U O W) (witness W O M V (lit 'fail)) (checked W V A))
  ((supported U O) <-- (support U O W V A))
  ;; Support is a retained observation, not a verdict. An applicable counter
  ;; prevents even this narrow unopposed-support conclusion; it grants no authority.
  ((unopposed_support U O) <-- (supported U O) (not (counter U O _ _ _)))
  ((pending U O M) <-- (obligation U O M) (not (supported U O)))
  ((t_use U S O W)
   <--
   (application U S E)
   (applicable U O W)
   (witness W O M V R)
   (checked W V A))
  (bounds 4096 4096 4096))

;; Pure projection of selected declarations. Source installation below is the
;; explicit native Session effect; the projection grants no method attestation.
(def (resource-review-sources entry profile usage snapshot scopes)
  (list
   (cons 'application (list (list usage snapshot (.get entry identity))))
   (cons 'catalog_rule (map (lambda (row) (cons (.get entry identity) row)) (.get entry rules)))
   (cons 'catalog_dependency
     (map (lambda (row) (cons (.get entry identity) row)) (.get entry dependencies)))
   (cons 'catalog_factor_rule
     (map (lambda (row) (cons (.get entry identity) row)) (.get entry factor-implications)))
   (cons 'factor (map (cut list usage <>) (.get profile factors)))
   (cons 'scope scopes)))

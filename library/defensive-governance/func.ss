;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; G1 Five-Tuple Guard Admission & F1/F2 Live Executable ASCENT Bounded Revalidation Program.
(import :clan/poo/object
        (only-in :clan/poo/type validate)
        :std/list/list
        :gerbil-ascent/rules/func
        (only-in :gerbil-ascent/rules/declaration rule-module-program rule-module-bindings)
        "types.ss")
(export admit-guard-five-tuple
        audit-agent-defensive-submission
        extract-scheme-defensive-facts
        audit-scheme-defensive-datums
        BoundedRevalidationProgram
        make-bounded-revalidation-program
        reason-bounded-revalidation
        AgentTranscriptAuditProgram
        make-agent-transcript-audit-program
        reason-agent-transcript)

;; G1: Refuse any guard missing required 5-tuple evidence or claiming immutable reuse on an M3 mutable root.
(def (admit-guard-five-tuple candidate)
  (def checked (validate GuardAdmissionFiveTupleType candidate))
  (when (and (eq? (.get checked mutability) 'M3-mutable-root)
             (.get checked claims-immutable-reuse?))
    (error "G1 refusal: M3 mutable-root boundary cannot claim M1 immutable check reuse"
           (.get checked guard-id)))
  checked)

;; G2: Pure executable detector for all 4 AI Agent defensive-hallucination classes:
;;   - silent-fallback:         (site defect-kind)
;;   - floor-weakening:         (slot old-val new-val) weakening monotonic Band-5 floors
;;   - redundant-defensive-glue: (guard-id has-witness? has-owner? has-obligation?) missing any required field
;;   - fabricated-evidence:     (claim-id backing-kind) where backing-kind is 'prose-only or 'absent
(def (audit-agent-defensive-submission submission)
  (def silent-items
    (if (.slot? submission 'silent-fallbacks) (.ref submission 'silent-fallbacks) '()))
  (def floor-items
    (if (.slot? submission 'floor-overrides) (.ref submission 'floor-overrides) '()))
  (def guard-items
    (if (.slot? submission 'guard-proposals) (.ref submission 'guard-proposals) '()))
  (def claim-items
    (if (.slot? submission 'evidence-claims) (.ref submission 'evidence-claims) '()))
  (def f1
    (map (lambda (row)
           (list 'silent-fallback (car row) (cadr row)))
         silent-items))
  (def f2
    (filter-map
      (lambda (row)
        (let ((slot (car row)) (old-v (cadr row)) (new-v (caddr row)))
          (cond
           ((and (memq slot '(require-countermodels? require-emergent-invariants?
                              require-use-time-witness? require-dependency-manifest?
                              require-guard-necessity-countermodel? require-admission-five-tuple?))
                 (eq? old-v #t) (eq? new-v #f))
            (list 'floor-weakening slot 'weakened-require-floor))
           ((and (eq? slot 'allow-global-purge?) (eq? old-v #f) (eq? new-v #t))
            (list 'floor-weakening slot 're-enabled-global-purge))
           (else #f))))
      floor-items))
  (def f3
    (filter-map
      (lambda (row)
        (let ((gid (car row)) (has-w? (cadr row)) (has-o? (caddr row)) (has-ob? (cadddr row)))
          (if (and has-w? has-o? has-ob?)
            #f
            (list 'redundant-defensive-glue gid 'incomplete-five-tuple))))
      guard-items))
  (def f4
    (filter-map
      (lambda (row)
        (let ((cid (car row)) (backing (cadr row)))
          (if (memq backing '(prose-only absent))
            (list 'fabricated-evidence cid backing)
            #f)))
      claim-items))
  (def audit-findings (append f1 f2 f3 f4))
  (.o passed?: (null? audit-findings)
      findings: audit-findings))

;; E3.1: Pure Scheme S-expression AST extractor feeding audit-agent-defensive-submission.
;; Zero I/O: operates directly on parsed Scheme datums.
(def (constant-fallback-expr? expr)
  (or (eq? expr #t)
      (eq? expr 0)
      (equal? expr '(quote ()))
      (equal? expr "")
      (and (pair? expr)
           (eq? (car expr) '.o)
           (let loop ((xs (cdr expr)))
             (and (pair? xs) (pair? (cdr xs))
                  (or (and (eq? (car xs) 'ok:) (eq? (cadr xs) #t))
                      (loop (cddr xs))))))))

(def (poo-keyword-value plist key)
  (let loop ((xs plist))
    (cond
     ((or (null? xs) (null? (cdr xs))) 'not-found)
     ((eq? (car xs) key) (cadr xs))
     (else (loop (cdr xs))))))

(def (extract-scheme-defensive-facts datums)
  (def silent '())
  (def floors '())
  (def guards '())
  (def claims '())
  (def (walk form)
    (when (pair? form)
      (let ((head (car form)) (rest (cdr form)))
        (cond
         ;; P1: (with-catch (lambda (_) <constant-ok-or-empty>) ...)
         ((and (eq? head 'with-catch) (>= (length rest) 2))
          (let ((handler (car rest)))
            (when (and (pair? handler)
                       (eq? (car handler) 'lambda)
                       (= (length handler) 3)
                       (constant-fallback-expr? (caddr handler)))
              (set! silent (cons (list 'with-catch 'swallows-exception-into-constant) silent)))))
         ;; P4: vacuous (guard <id> #t ...)
         ((and (eq? head 'guard) (>= (length rest) 2) (symbol? (car rest)) (eq? (cadr rest) #t))
          (set! guards (cons (list (car rest) #f #t #t) guards)))
         ;; G2 floor-weakening & fabricated-evidence inside (.o ...) / (.def ...)
         ((memq head '(.o .def))
          (let ((plist (if (eq? head '.def) (if (pair? rest) (cdr rest) '()) rest)))
            (for-each
              (lambda (row)
                (let ((kw (car row)) (slot (cadr row)) (bad-val (caddr row)))
                  (let ((v (poo-keyword-value plist kw)))
                    (when (eq? v bad-val)
                      (set! floors
                            (cons (list slot (not bad-val) bad-val)
                                  floors))))))
              '((require-countermodels?: require-countermodels? #f)
                (require-emergent-invariants?: require-emergent-invariants? #f)
                (require-use-time-witness?: require-use-time-witness? #f)
                (require-guard-necessity-countermodel?: require-guard-necessity-countermodel? #f)
                (require-admission-five-tuple?: require-admission-five-tuple? #f)
                (allow-global-purge?: allow-global-purge? #t)))
            ;; Fabricated evidence: verified?: #t paired with witness: #f or evidence: '()
            (when (and (eq? (poo-keyword-value plist 'verified?:) #t)
                       (or (eq? (poo-keyword-value plist 'witness:) #f)
                           (equal? (poo-keyword-value plist 'evidence:) '(quote ()))))
              (set! claims (cons (list 'poo-verified-without-witness 'absent) claims)))))
         (else #f))
        (for-each walk rest))))
  (for-each walk datums)
  (.o silent-fallbacks: (reverse silent)
      floor-overrides: (reverse floors)
      guard-proposals: (reverse guards)
      evidence-claims: (reverse claims)))

(def (audit-scheme-defensive-datums datums)
  (audit-agent-defensive-submission (extract-scheme-defensive-facts datums)))

;; F1 + F2 + G1 live pure ASCENT Datalog program:
;; Evaluates 6-state epistemic status, bounded negative-dependency invalidation
;; (preserving frozen history and independent M1 method bytes), and guard admission findings.
(define-program
  (make-bounded-revalidation-program)
  (sources
    subject
    expected_body_present
    method_completed
    scope_established
    authentic_allow
    authentic_deny
    conflict_resolved
    frozen_cut_item
    independent_method_result
    review_depends_on_neg_domain
    neg_domain_member
    replacement_reason_admitted
    guard_proposal
    policy_requires_direct_record
    direct_record_present
    method_admission)
  (outputs
    epistemic_state
    review_stale
    review_reusable
    history_preserved
    method_preserved
    review_reclosable
    guard_admission_finding
    policy_verdict_qualified
    policy_verdict_pending
    policy_binding_refused)
  (relation subject ((id string?)))
  (relation expected_body_present ((id string?)))
  (relation method_completed ((id string?)))
  (relation scope_established ((id string?)))
  (relation authentic_allow ((id string?)))
  (relation authentic_deny ((id string?)))
  (relation conflict_resolved ((id string?)))
  (relation frozen_cut_item ((cut string?) (item string?)))
  (relation independent_method_result ((method_id string?) (artifact string?)))
  (relation review_depends_on_neg_domain ((review_id string?) (domain string?)))
  (relation neg_domain_member ((domain string?) (member_id string?) (relevance string?)))
  (relation replacement_reason_admitted ((review_id string?)))
  (relation guard_proposal ((guard_id string?) (mutability string?) (claims_reuse string?) (has_witness string?)))
  (relation policy_requires_direct_record ((id string?)))
  (relation direct_record_present ((id string?)))
  (relation method_admission ((method_id string?) (status string?)))

  (relation epistemic_state ((id string?) (state string?)))
  (relation review_stale ((review_id string?) (domain string?) (counter_id string?)))
  (relation review_reusable ((review_id string?)))
  (relation history_preserved ((cut string?) (item string?)))
  (relation method_preserved ((method_id string?) (artifact string?)))
  (relation review_reclosable ((review_id string?)))
  (relation guard_admission_finding ((guard_id string?) (reason string?)))
  (relation policy_verdict_qualified ((id string?) (method_id string?)))
  (relation policy_verdict_pending ((id string?) (reason string?)))
  (relation policy_binding_refused ((id string?) (method_id string?) (reason string?)))

  ;; F1 Six-State Epistemic Classification (never collapses unknown/defect/conflict):
  ((epistemic_state S (lit "SetupDefect"))
   <--
   (subject S)
   (not (expected_body_present S)))
  ((epistemic_state S (lit "PendingMethod"))
   <--
   (subject S)
   (expected_body_present S)
   (not (method_completed S)))
  ((epistemic_state S (lit "PendingScope"))
   <--
   (subject S)
   (expected_body_present S)
   (method_completed S)
   (not (scope_established S)))
  ((epistemic_state S (lit "Conflict"))
   <--
   (subject S)
   (expected_body_present S)
   (authentic_allow S)
   (authentic_deny S)
   (not (conflict_resolved S)))
  ((epistemic_state S (lit "Proven"))
   <--
   (subject S)
   (expected_body_present S)
   (method_completed S)
   (scope_established S)
   (authentic_allow S)
   (not (authentic_deny S)))
  ((epistemic_state S (lit "Proven"))
   <--
   (subject S)
   (expected_body_present S)
   (method_completed S)
   (scope_established S)
   (authentic_allow S)
   (authentic_deny S)
   (conflict_resolved S))
  ((epistemic_state S (lit "Refuted"))
   <--
   (subject S)
   (expected_body_present S)
   (method_completed S)
   (scope_established S)
   (authentic_deny S)
   (not (authentic_allow S)))

  ;; F2 Bounded Negative-Dependency Revalidation (DE01 / 20.16-20.18):
  ;; Only a known "relevant" counter invalidates a review depending on that negative domain.
  ((review_stale R D C)
   <--
   (review_depends_on_neg_domain R D)
   (neg_domain_member D C (lit "relevant")))
  ((review_reusable R)
   <--
   (review_depends_on_neg_domain R _)
   (not (review_stale R _ _)))
  ((review_reclosable R)
   <--
   (review_stale R _ _)
   (replacement_reason_admitted R))
  ;; Frozen historical cuts and independent M1 method results are unconditionally preserved (anti-P3 purge):
  ((history_preserved Cut Item)
   <--
   (frozen_cut_item Cut Item))
  ((method_preserved M Art)
   <--
   (independent_method_result M Art))

  ;; G1 Guard Admission findings:
  ((guard_admission_finding G (lit "missing-witness"))
   <--
   (guard_proposal G _ _ (lit "no")))
  ((guard_admission_finding G (lit "immutable-reuse-on-mutable-root"))
   <--
   (guard_proposal G (lit "M3-mutable-root") (lit "yes") _))

  ;; 20.17 / 20.18 Evidence Sufficiency vs. Policy-Required Direct Record & Method Admission (HA/AH/BR/AM):
  ;; When policy does NOT require a direct record, Proven + admitted method suffices (anti-P3/P4 bloat):
  ((policy_verdict_qualified S M)
   <--
   (epistemic_state S (lit "Proven"))
   (method_admission M (lit "admitted"))
   (not (policy_requires_direct_record S)))
  ;; When policy DOES require a direct record, it qualifies only if direct_record_present holds (BR03):
  ((policy_verdict_qualified S M)
   <--
   (epistemic_state S (lit "Proven"))
   (method_admission M (lit "admitted"))
   (policy_requires_direct_record S)
   (direct_record_present S))
  ;; Missing policy-required direct record leaves verdict pending (BR01):
  ((policy_verdict_pending S (lit "missing-direct-record"))
   <--
   (subject S)
   (policy_requires_direct_record S)
   (not (direct_record_present S)))
  ;; Unknown method admission stays pending (AM01), never silently forbidden or admitted:
  ((policy_verdict_pending S (lit "unknown-method-admission"))
   <--
   (subject S)
   (method_admission _ (lit "unknown")))
  ;; Closed policy forbidding method mapping refuses the offered binding (AM02) while method_preserved retains authentic bytes:
  ((policy_binding_refused S M (lit "forbidden-method-mapping"))
   <--
   (subject S)
   (method_admission M (lit "forbidden")))

  (bounds 4096 4096 4096))

(def BoundedRevalidationDeclaration (make-bounded-revalidation-program))
(def BoundedRevalidationProgram (rule-module-program BoundedRevalidationDeclaration))

(def (copy-fact value)
  (cond
   ((string? value) (string-copy value))
   ((pair? value) (cons (copy-fact (car value)) (copy-fact (cdr value))))
   ((null? value) '())
   (else (error "unsupported defensive-governance fact cell" value))))

(def (reason-bounded-revalidation replacements)
  (def prog-val BoundedRevalidationProgram)
  (def expected (.ref prog-val 'source-handles))
  (unless (and (list? replacements) (andmap pair? replacements))
    (error "bounded-revalidation replacements must be an alist"))
  (for-each
    (lambda (entry)
      (unless (memq (car entry) expected)
        (error "unknown bounded-revalidation source" (car entry))))
    replacements)
  (for-each
    (lambda (handle)
      (unless (assq handle replacements)
        (error "missing bounded-revalidation source" handle)))
    expected)
  (def prepared (map (lambda (entry) (cons (car entry) (copy-fact (cdr entry)))) replacements))
  (def session (gerbil-ascent-open-session prog-val))
  (def result
    (gerbil-ascent-session-replace-sources!
      session
      prepared
      (lambda (prospective)
        (and (.ref prospective 'finished)
             (andmap
               (lambda (entry)
                 (let ((actual ((.ref prospective 'rows-of) (car entry)))
                       (wanted (cdr entry)))
                   (and (andmap (cut member <> wanted) actual)
                        (andmap (cut member <> actual) wanted))))
               prepared)))))
  (unless (.ref result 'finished)
    (error "bounded-revalidation evaluation incomplete"))
  (def native-rows (.ref result 'rows-of))
  (def out-bindings
    (filter
      (lambda (binding) (not (memq (cdr binding) expected)))
      (rule-module-bindings BoundedRevalidationDeclaration)))
  (.o program: prog-val
      output-bindings: (lambda () (map (lambda (e) (cons (car e) (cdr e))) out-bindings))
      rows-of: (lambda (name) (copy-fact (native-rows name)))))

;; G5 / 10.155 Live pure ASCENT Datalog program for AI Agent Patch Transcript Auditing:
;; Cross-validates multi-attempt governance transcripts against scope fencing, anti-evasion findings,
;; unwitnessed obligation deletions, independent oracle verdicts, and bounded human escalation.
(define-program
  (make-agent-transcript-audit-program)
  (sources
    patch
    prose_claim
    independent_oracle_passed
    scope_violation
    evasion_finding
    obligation_deleted
    replacement_witness_admitted
    retry_budget_exhausted)
  (outputs
    unwitnessed_deletion
    patch_blocked
    patch_admitted
    escalation_required)
  (relation patch ((id string?)))
  (relation prose_claim ((id string?)))
  (relation independent_oracle_passed ((id string?)))
  (relation scope_violation ((id string?) (path string?)))
  (relation evasion_finding ((id string?) (rule string?)))
  (relation obligation_deleted ((id string?) (kind string?)))
  (relation replacement_witness_admitted ((id string?) (kind string?)))
  (relation retry_budget_exhausted ((id string?)))

  (relation unwitnessed_deletion ((id string?) (kind string?)))
  (relation patch_blocked ((id string?) (reason string?)))
  (relation patch_admitted ((id string?)))
  (relation escalation_required ((id string?)))

  ((unwitnessed_deletion P K)
   <--
   (obligation_deleted P K)
   (not (replacement_witness_admitted P K)))

  ((patch_blocked P (lit "protected-or-out-of-scope-mutation"))
   <--
   (patch P)
   (scope_violation P _))

  ((patch_blocked P (lit "ast-or-evasion-finding"))
   <--
   (patch P)
   (evasion_finding P _))

  ((patch_blocked P (lit "unwitnessed-obligation-deletion"))
   <--
   (patch P)
   (unwitnessed_deletion P _))

  ((patch_blocked P (lit "self-certified-without-oracle"))
   <--
   (patch P)
   (prose_claim P)
   (not (independent_oracle_passed P)))

  ((patch_blocked P (lit "missing-independent-oracle"))
   <--
   (patch P)
   (not (independent_oracle_passed P)))

  ((patch_admitted P)
   <--
   (patch P)
   (independent_oracle_passed P)
   (not (patch_blocked P _)))

  ((escalation_required P)
   <--
   (patch P)
   (retry_budget_exhausted P)
   (not (patch_admitted P)))

  (bounds 4096 4096 4096))

(def AgentTranscriptAuditDeclaration (make-agent-transcript-audit-program))
(def AgentTranscriptAuditProgram (rule-module-program AgentTranscriptAuditDeclaration))

(def (reason-agent-transcript replacements)
  (def tprog-val AgentTranscriptAuditProgram)
  (def expected (.ref tprog-val 'source-handles))
  (unless (and (list? replacements) (andmap pair? replacements))
    (error "agent-transcript replacements must be an alist"))
  (for-each
    (lambda (entry)
      (unless (memq (car entry) expected)
        (error "unknown agent-transcript source" (car entry))))
    replacements)
  (for-each
    (lambda (handle)
      (unless (assq handle replacements)
        (error "missing agent-transcript source" handle)))
    expected)
  (def prepared (map (lambda (entry) (cons (car entry) (copy-fact (cdr entry)))) replacements))
  (def session (gerbil-ascent-open-session tprog-val))
  (def result
    (gerbil-ascent-session-replace-sources!
      session
      prepared
      (lambda (prospective)
        (and (.ref prospective 'finished)
             (andmap
               (lambda (entry)
                 (let ((actual ((.ref prospective 'rows-of) (car entry)))
                       (wanted (cdr entry)))
                   (and (andmap (cut member <> wanted) actual)
                        (andmap (cut member <> actual) wanted))))
               prepared)))))
  (unless (.ref result 'finished)
    (error "agent-transcript evaluation incomplete"))
  (def native-rows (.ref result 'rows-of))
  (def tout-bindings
    (filter
      (lambda (binding) (not (memq (cdr binding) expected)))
      (rule-module-bindings AgentTranscriptAuditDeclaration)))
  (.o program: tprog-val
      output-bindings: (lambda () (map (lambda (e) (cons (car e) (cdr e))) tout-bindings))
      rows-of: (lambda (name) (copy-fact (native-rows name)))))

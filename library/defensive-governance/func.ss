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
        make-m3-transient-capability
        assert-m1-persistable!
        BoundedRevalidationProgram
        make-bounded-revalidation-program
        reason-bounded-revalidation
        AgentTranscriptAuditProgram
        make-agent-transcript-audit-program
        reason-agent-transcript
        HotPolicyCoEvolutionProgram
        make-hot-policy-coevolution-program
        reason-hot-policy-coevolution
        DurableGovernanceMetaAuditProgram
        make-durable-governance-meta-audit-program
        reason-durable-governance-meta-audit)

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

;; R3 (10.156): Mechanical Prevention of Accidental Reachability Leaks into M1 Persistent Blobs.
;; Constructs sealed non-serializable M3 live-authority wrappers and recursively rejects
;; any object graph (pairs, lists, vectors, POO objects, or I/O ports) reaching an M3 token.
(def (make-m3-transient-capability cap-id cap-scope cap-epoch)
  (validate M3TransientCapabilityType
    (.o capability-id: cap-id
        scope: cap-scope
        revocation-epoch: cap-epoch
        mutability: 'M3-mutable-root
        non-serializable?: #t)))

(def (assert-m1-persistable! datum (path 'root))
  (cond
   ((or (null? datum) (boolean? datum) (number? datum) (string? datum) (symbol? datum) (keyword? datum))
    #t)
   ((port? datum)
    (error "R3 refusal: accidental reachability leak of live I/O port into M1 persistent blob" path))
   ((object? datum)
    (when (and (.slot? datum 'non-serializable?) (eq? (.ref datum 'non-serializable?) #t))
      (error "R3 refusal: accidental reachability leak of non-serializable M3 capability into M1 persistent blob"
             path
             (if (.slot? datum 'capability-id) (.ref datum 'capability-id) 'unknown-capability)))
    (when (and (.slot? datum 'mutability) (eq? (.ref datum 'mutability) 'M3-mutable-root)
               (.slot? datum 'capability-id))
      (error "R3 refusal: M3 mutable-root capability cannot enter M1 persistent Merkle store"
             path (.ref datum 'capability-id)))
    (for-each
      (lambda (slot-name)
        (assert-m1-persistable! (.ref datum slot-name) (list path slot-name)))
      (.all-slots datum))
    #t)
   ((pair? datum)
    (assert-m1-persistable! (car datum) (list path 'car))
    (assert-m1-persistable! (cdr datum) (list path 'cdr))
    #t)
   ((vector? datum)
    (let loop ((idx 0))
      (when (< idx (vector-length datum))
        (assert-m1-persistable! (vector-ref datum idx) (list path idx))
        (loop (+ idx 1))))
    #t)
   (else
    (error "R3 refusal: non-persistable runtime object cannot enter M1 persistent blob" path datum))))

;; R1 (10.156): Live pure ASCENT Datalog program for Hot Policy Co-Evolution Across Suspended Agents.
;; Separates M1 immutable evidence reuse from M2 policy-digest invalidation without crashing
;; suspended continuations (PJama) or breaking deterministic replay (Temporal).
(define-program
  (make-hot-policy-coevolution-program)
  (sources
    suspended_verdict
    verdict_depends_on_domain
    verdict_policy_digest
    active_policy_digest
    domain_changed_in_upgrade
    m1_evidence_leaf
    frozen_historical_cut)
  (outputs
    verdict_needs_revalidation
    verdict_still_valid
    m1_evidence_reusable
    historical_cut_preserved)
  (relation suspended_verdict ((vid string?)))
  (relation verdict_depends_on_domain ((vid string?) (domain string?)))
  (relation verdict_policy_digest ((vid string?) (digest string?)))
  (relation active_policy_digest ((digest string?)))
  (relation domain_changed_in_upgrade ((domain string?)))
  (relation m1_evidence_leaf ((leaf_id string?) (sha string?)))
  (relation frozen_historical_cut ((cut_id string?) (root_sha string?)))

  (relation verdict_needs_revalidation ((vid string?) (reason string?)))
  (relation verdict_still_valid ((vid string?)))
  (relation m1_evidence_reusable ((leaf_id string?) (sha string?)))
  (relation historical_cut_preserved ((cut_id string?) (root_sha string?)))

  ;; Any verdict depending on a domain altered by the hot policy upgrade must be revalidated:
  ((verdict_needs_revalidation V (lit "affected-domain-changed"))
   <--
   (suspended_verdict V)
   (verdict_depends_on_domain V D)
   (domain_changed_in_upgrade D))

  ;; Any verdict pinned to an older policy digest whose domain changed (or mismatched active policy on changed domain):
  ((verdict_needs_revalidation V (lit "stale-policy-digest"))
   <--
   (suspended_verdict V)
   (verdict_policy_digest V OldP)
   (active_policy_digest NewP)
   (not (verdict_policy_digest V NewP))
   (verdict_depends_on_domain V D)
   (domain_changed_in_upgrade D))

  ;; Suspended verdicts on unaffected domains remain valid without re-execution or replay crash:
  ((verdict_still_valid V)
   <--
   (suspended_verdict V)
   (not (verdict_needs_revalidation V _)))

  ;; M1 content-addressed evidence leaves & frozen historical cuts are unconditionally preserved:
  ((m1_evidence_reusable L H)
   <--
   (m1_evidence_leaf L H))
  ((historical_cut_preserved C R)
   <--
   (frozen_historical_cut C R))

  (bounds 4096 4096 4096))

(def HotPolicyCoEvolutionDeclaration (make-hot-policy-coevolution-program))
(def HotPolicyCoEvolutionProgram (rule-module-program HotPolicyCoEvolutionDeclaration))

(def (reason-hot-policy-coevolution replacements)
  (def pprog-val HotPolicyCoEvolutionProgram)
  (def expected (.ref pprog-val 'source-handles))
  (unless (and (list? replacements) (andmap pair? replacements))
    (error "hot-policy-coevolution replacements must be an alist"))
  (for-each
    (lambda (entry)
      (unless (memq (car entry) expected)
        (error "unknown hot-policy-coevolution source" (car entry))))
    replacements)
  (for-each
    (lambda (handle)
      (unless (assq handle replacements)
        (error "missing hot-policy-coevolution source" handle)))
    expected)
  (def prepared (map (lambda (entry) (cons (car entry) (copy-fact (cdr entry)))) replacements))
  (def session (gerbil-ascent-open-session pprog-val))
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
    (error "hot-policy-coevolution evaluation incomplete"))
  (def native-rows (.ref result 'rows-of))
  (def pout-bindings
    (filter
      (lambda (binding) (not (memq (cdr binding) expected)))
      (rule-module-bindings HotPolicyCoEvolutionDeclaration)))
  (.o program: pprog-val
      output-bindings: (lambda () (map (lambda (e) (cons (car e) (cdr e))) pout-bindings))
      rows-of: (lambda (name) (copy-fact (native-rows name)))))

;; Phase 19/22 (10.167 / 10.170): Cross-Pillar B1-B10 Declarative ASCENT Datalog Meta-Governance Auditor.
;; Independent heterogeneous verifier in pure stratified Datalog over cold M1 evidence graphs:
;;   - B3: Transitive multi-hop delegation revocation closure
;;   - B3 -> B8: Causal belief poisoning from revoked proposers + sole-support TMS cascade
;;   - B7: Transitive multi-hop DIFC confidentiality taint propagation & exfiltration detection
;;   - B9: Witness gossip split-view equivocation detection (pure relational inequality)
;;   - B10: Proactive threshold witness cosigning (2f+1 >= 3 distinct roster witnesses),
;;          Byzantine witness double-sign detection, unregistered/unverified cosign rejection,
;;          sub-quorum finality detection, split-world finality breach, and cross-log replay refusal
;;   - B1/B5/B6/B8/B9/B10: Cross-pillar release disqualification vs. clean admission
(define-program
  (make-durable-governance-meta-audit-program)
  (sources
    delegation_edge
    revoked_principal
    belief_proposer
    belief_has_oracle
    belief_sole_dep
    retracted_belief
    base_taint
    derived_from
    declassified_tag
    sink_emits
    sink_allows
    witness_sth
    release_proposal
    release_uses_belief
    saga_pivot_crossed
    saga_rollback_attempted
    witness_roster
    witness_cosign
    claimed_finalized
    release_requires_finality)
  (outputs
    effectively_revoked
    belief_poisoned
    tainted_value
    exfiltration_violation
    equivocation_violation
    byzantine_witness_equivocation
    invalid_witness_cosign
    quorum_3_verified
    sub_quorum_finality_violation
    split_world_finality_breach
    release_disqualified
    release_admitted)
  (relation delegation_edge ((parent string?) (child string?)))
  (relation revoked_principal ((principal string?)))
  (relation belief_proposer ((belief_id string?) (principal string?)))
  (relation belief_has_oracle ((belief_id string?)))
  (relation belief_sole_dep ((derived_id string?) (support_id string?)))
  (relation retracted_belief ((belief_id string?)))
  (relation base_taint ((val_id string?) (tag string?)))
  (relation derived_from ((child_val string?) (parent_val string?)))
  (relation declassified_tag ((val_id string?) (tag string?)))
  (relation sink_emits ((sink_id string?) (val_id string?)))
  (relation sink_allows ((sink_id string?) (tag string?)))
  (relation witness_sth ((witness string?) (log_id string?) (size string?) (root string?)))
  (relation release_proposal ((rel_id string?) (author string?) (approver string?) (log_id string?)))
  (relation release_uses_belief ((rel_id string?) (belief_id string?)))
  (relation saga_pivot_crossed ((rel_id string?)))
  (relation saga_rollback_attempted ((rel_id string?)))
  (relation witness_roster ((log_id string?) (witness string?)))
  (relation witness_cosign ((witness string?) (log_id string?) (size string?) (root string?) (consistency_ok string?)))
  (relation claimed_finalized ((ckpt_id string?) (log_id string?) (size string?) (root string?)))
  (relation release_requires_finality ((rel_id string?) (ckpt_id string?)))

  ;; Internal stratified helper relations for pure relational identity & cross-log finality:
  (relation same_root ((r1 string?) (r2 string?)))
  (relation same_witness ((w1 string?) (w2 string?)))
  (relation valid_witness_cosign ((witness string?) (log_id string?) (size string?) (root string?)))
  (relation release_finality_satisfied ((rel_id string?) (ckpt_id string?)))

  (relation effectively_revoked ((principal string?)))
  (relation belief_poisoned ((belief_id string?)))
  (relation tainted_value ((val_id string?) (tag string?)))
  (relation exfiltration_violation ((sink_id string?) (val_id string?) (tag string?)))
  (relation equivocation_violation ((log_id string?) (size string?) (r1 string?) (r2 string?)))
  (relation byzantine_witness_equivocation ((witness string?) (log_id string?) (size string?) (r1 string?) (r2 string?)))
  (relation invalid_witness_cosign ((witness string?) (log_id string?) (size string?) (root string?) (reason string?)))
  (relation quorum_3_verified ((ckpt_id string?) (log_id string?) (size string?) (root string?)))
  (relation sub_quorum_finality_violation ((ckpt_id string?) (log_id string?) (size string?) (root string?)))
  (relation split_world_finality_breach ((log_id string?) (size string?) (r1 string?) (r2 string?)))
  (relation release_disqualified ((rel_id string?) (reason string?)))
  (relation release_admitted ((rel_id string?)))

  ;; 1. B3 Transitive cascading revocation closure over arbitrary hop depth:
  ((effectively_revoked P)
   <--
   (revoked_principal P))
  ((effectively_revoked C)
   <--
   (effectively_revoked P)
   (delegation_edge P C))

  ;; 2. B3 -> B8 Transitive causal belief poisoning closure (preserving cold-oracle facts):
  ((belief_poisoned B)
   <--
   (retracted_belief B))
  ((belief_poisoned B)
   <--
   (belief_proposer B P)
   (effectively_revoked P)
   (not (belief_has_oracle B)))
  ((belief_poisoned D)
   <--
   (belief_sole_dep D S)
   (belief_poisoned S))

  ;; 3. B7 Transitive DIFC confidentiality taint propagation & no-write-down violation:
  ((tainted_value V T)
   <--
   (base_taint V T)
   (not (declassified_tag V T)))
  ((tainted_value C T)
   <--
   (derived_from C P)
   (tainted_value P T)
   (not (declassified_tag C T)))
  ((exfiltration_violation S V T)
   <--
   (sink_emits S V)
   (tainted_value V T)
   (not (sink_allows S T)))

  ;; 4. B9 Witness gossip split-view equivocation (pure relational inequality R1 != R2):
  ((equivocation_violation L Sz R1 R2)
   <--
   (witness_sth W1 L Sz R1)
   (witness_sth W2 L Sz R2)
   (not (witness_sth W1 L Sz R2)))

  ;; 5. B10 Proactive threshold witness cosigning (2f+1 >= 3 distinct roster witnesses) & finality:
  ((same_root R R)
   <--
   (witness_cosign _ _ _ R _))
  ((same_root R R)
   <--
   (claimed_finalized _ _ _ R))
  ((same_witness W W)
   <--
   (witness_roster _ W))
  ((valid_witness_cosign W L Sz R)
   <--
   (witness_roster L W)
   (witness_cosign W L Sz R (lit "yes")))
  ((byzantine_witness_equivocation W L Sz R1 R2)
   <--
   (witness_cosign W L Sz R1 _)
   (witness_cosign W L Sz R2 _)
   (not (same_root R1 R2)))
  ((invalid_witness_cosign W L Sz R (lit "unregistered-witness"))
   <--
   (witness_cosign W L Sz R _)
   (not (witness_roster L W)))
  ((invalid_witness_cosign W L Sz R (lit "missing-consistency-proof"))
   <--
   (witness_cosign W L Sz R (lit "no")))
  ((quorum_3_verified Ckpt L Sz R)
   <--
   (claimed_finalized Ckpt L Sz R)
   (valid_witness_cosign W1 L Sz R)
   (valid_witness_cosign W2 L Sz R)
   (valid_witness_cosign W3 L Sz R)
   (not (same_witness W1 W2))
   (not (same_witness W2 W3))
   (not (same_witness W1 W3)))
  ((sub_quorum_finality_violation Ckpt L Sz R)
   <--
   (claimed_finalized Ckpt L Sz R)
   (not (quorum_3_verified Ckpt L Sz R)))
  ((split_world_finality_breach L Sz R1 R2)
   <--
   (quorum_3_verified _ L Sz R1)
   (quorum_3_verified _ L Sz R2)
   (not (same_root R1 R2)))

  ;; 6. Cross-pillar B1/B3/B5/B6/B8/B9/B10 release disqualification & clean admission:
  ((release_finality_satisfied Rel Ckpt)
   <--
   (release_proposal Rel _ _ Log)
   (release_requires_finality Rel Ckpt)
   (quorum_3_verified Ckpt Log _ _))
  ((release_disqualified Rel (lit "sod-self-approval"))
   <--
   (release_proposal Rel Same Same _))
  ((release_disqualified Rel (lit "revoked-delegation-chain"))
   <--
   (release_proposal Rel Author _ _)
   (effectively_revoked Author))
  ((release_disqualified Rel (lit "poisoned-supporting-belief"))
   <--
   (release_proposal Rel _ _ _)
   (release_uses_belief Rel B)
   (belief_poisoned B))
  ((release_disqualified Rel (lit "coordinator-equivocated"))
   <--
   (release_proposal Rel _ _ Log)
   (equivocation_violation Log _ _ _))
  ((release_disqualified Rel (lit "post-pivot-rollback-violation"))
   <--
   (release_proposal Rel _ _ _)
   (saga_pivot_crossed Rel)
   (saga_rollback_attempted Rel))
  ((release_disqualified Rel (lit "unfinalized-quorum-checkpoint"))
   <--
   (release_proposal Rel _ _ _)
   (release_requires_finality Rel Ckpt)
   (not (release_finality_satisfied Rel Ckpt)))
  ((release_disqualified Rel (lit "split-world-finality-breach"))
   <--
   (release_proposal Rel _ _ Log)
   (split_world_finality_breach Log _ _ _))
  ((release_admitted Rel)
   <--
   (release_proposal Rel _ _ _)
   (not (release_disqualified Rel _)))

  (bounds 4096 4096 4096))

(def DurableGovernanceMetaAuditDeclaration (make-durable-governance-meta-audit-program))
(def DurableGovernanceMetaAuditProgram (rule-module-program DurableGovernanceMetaAuditDeclaration))

(def (reason-durable-governance-meta-audit replacements)
  (def mprog-val DurableGovernanceMetaAuditProgram)
  (def expected (.ref mprog-val 'source-handles))
  (unless (and (list? replacements) (andmap pair? replacements))
    (error "durable-governance-meta-audit replacements must be an alist"))
  (for-each
    (lambda (entry)
      (unless (memq (car entry) expected)
        (error "unknown durable-governance-meta-audit source" (car entry))))
    replacements)
  (for-each
    (lambda (handle)
      (unless (assq handle replacements)
        (error "missing durable-governance-meta-audit source" handle)))
    expected)
  (def prepared (map (lambda (entry) (cons (car entry) (copy-fact (cdr entry)))) replacements))
  (def session (gerbil-ascent-open-session mprog-val))
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
    (error "durable-governance-meta-audit evaluation incomplete"))
  (def native-rows (.ref result 'rows-of))
  (def mout-bindings
    (filter
      (lambda (binding) (not (memq (cdr binding) expected)))
      (rule-module-bindings DurableGovernanceMetaAuditDeclaration)))
  (.o program: mprog-val
      output-bindings: (lambda () (map (lambda (e) (cons (car e) (cdr e))) mout-bindings))
      rows-of: (lambda (name) (copy-fact (native-rows name)))))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure ASCENT session evaluators and fact adapters for Multi-Method Verification (10.154).
;;; Delegates pure Datalog rules to `ascent-rules.ss`, SysML v2 projection to
;;; `sysml-projection.ss`, and generic session/fact combinators to `func.ss`. Zero I/O.
(import
  :clan/poo/object
  :std/list/list
  "func.ss"
  "ascent-rules.ss"
  "sysml-projection.ss")
(export
  MultiMethodGovernanceDeclaration
  MultiMethodGovernanceProgram
  make-multi-method-governance-program
  reason-multi-method-governance
  VerificationEvidenceAdmissionDeclaration
  VerificationEvidenceAdmissionProgram
  make-verification-evidence-admission-program
  reason-verification-evidence-admission
  IncrementalReuseDeclaration
  IncrementalReuseProgram
  make-incremental-reuse-program
  reason-incremental-reuse
  AiSecurityGovernanceDeclaration
  AiSecurityGovernanceProgram
  make-ai-security-governance-program
  reason-ai-security-governance
  evaluate-ai-patch-admission
  build-incremental-reuse-sources
  reuse-result->plan
  governance+evidence->admission-sources
  default-method-allows-claim-rows
  subject->governance-sources
  sysml-api-json->governance-facts)

(def (reason-multi-method-governance replacements)
  (run-ascent-program MultiMethodGovernanceProgram
                      MultiMethodGovernanceDeclaration
                      "multi-method governance"
                      replacements))

(def (reason-verification-evidence-admission replacements)
  (run-ascent-program VerificationEvidenceAdmissionProgram
                      VerificationEvidenceAdmissionDeclaration
                      "evidence admission"
                      replacements))

(def (reason-incremental-reuse replacements)
  (run-ascent-program IncrementalReuseProgram
                      IncrementalReuseDeclaration
                      "incremental cache reuse"
                      replacements))

(def (reason-ai-security-governance replacements)
  (run-ascent-program AiSecurityGovernanceProgram
                      AiSecurityGovernanceDeclaration
                      "ai security governance"
                      replacements))

;; Pure AI-SE Deterministic Change-Admission & Proof-Transport Gate (10.154).
;; Given a live SysML v2 projection, target subject identity, files modified by
;; an AI patch, optional touched semantic dependency keys, step security deps,
;; claimed proof-reuse steps, and optional runtime role bindings, evaluates:
;;  1. Static change-impact frontier (`changed-files->affected-frontier`),
;;  2. Phase 4 ASCENT AI Security & AI-SE Governance (`AR01`-`AR05`) with
;;     `ai-authored-change` factor injected for the target subject,
;;  3. Whether human Step-Up approval is required (`ai-mutates-host-or-governance`
;;     or any affected step / security-dependency touch).
;; Zero I/O, fail-closed: `reusable-steps` is empty whenever `admitted?` is #f.
(def (evaluate-ai-patch-admission
       projected
       subject-id
       changed-files
       touched-dep-rows: (touched-dep-rows '())
       step-security-dep-rows: (step-security-dep-rows '())
       claimed-reuse-steps: (claimed-reuse-steps '())
       extra-role-bindings: (extra-role-bindings '())
       extra-flow-steps: (extra-flow-steps '()))
  (def sid (sym->str subject-id))
  (def impacts (changed-files->affected-frontier projected changed-files))
  (def matching-impacts
    (filter (lambda (imp) (equal? (sym->str (.get imp identity)) sid)) impacts))
  (def affected-steps
    (if (pair? matching-impacts) (.get (car matching-impacts) affected-steps) '()))
  (def unaffected-steps
    (if (pair? matching-impacts) (.get (car matching-impacts) unaffected-steps) '()))
  (def base-ai (filter-ai-governance-sources-for-subject (.get projected ai-governance-sources) sid))
  (def base-factors (alist-ref base-ai 'subject_factor '()))
  (def factors-with-ai
    (if (member (list sid "ai-authored-change") base-factors)
      base-factors
      (cons (list sid "ai-authored-change") base-factors)))
  (def merged-steps (append extra-flow-steps (alist-ref base-ai 'flow_step '())))
  (def merged-roles (append extra-role-bindings (alist-ref base-ai 'declared_role_binding '())))
  (def reuse-rows (map (lambda (st) (list sid (sym->str st))) claimed-reuse-steps))
  (def eval-sources
    (alist-replace
      (alist-replace
        (alist-replace
          (alist-replace
            (alist-replace
              (alist-replace base-ai 'subject_factor factors-with-ai)
              'flow_step merged-steps)
            'declared_role_binding merged-roles)
          'ai_patch_touches_dep touched-dep-rows)
        'step_security_dep step-security-dep-rows)
      'ai_claimed_proof_reuse reuse-rows))
  (def ar-res (reason-ai-security-governance eval-sources))
  (def findings ((.ref ar-res 'rows-of) 'ar_finding))
  (def admitted-rows ((.ref ar-res 'rows-of) 'ai_governance_admitted))
  (def admitted? (and (null? findings) (and (member (list sid) admitted-rows) #t)))
  (def mutates-host?
    (and (member (list sid "ai-mutates-host-or-governance") factors-with-ai) #t))
  (def touches-sec-dep?
    (ormap (lambda (td)
             (let ((st (cadr td)) (dk (caddr td)))
               (and (member (list st dk) step-security-dep-rows) #t)))
           touched-dep-rows))
  (def requires-human-stepup?
    (or mutates-host? touches-sec-dep? (not admitted?)))
  (.o bind-these: #f
      subject-id: sid
      admitted?: admitted?
      ar-findings: findings
      ar-result: ar-res
      affected-steps: affected-steps
      reusable-steps: (if admitted? unaffected-steps '())
      requires-human-stepup?: requires-human-stepup?))

;; Pure projector assembling IR01-IR06 ASCENT sources from governance sources,
;; mutability annotations, policy flags, current input digests, cached witnesses,
;; optional live/cached toolchain fingerprints (IR05), and verified attested steps (IR06).
(def (build-incremental-reuse-sources
       gov-sources
       mutability-rows
       policy-flags
       current-input-rows
       cached-witness-rows
       cached-input-rows
       (current-toolchain-rows '())
       (cached-toolchain-rows '())
       (attested-steps '())
       (expired-steps '()))
  (list
    (cons 'flow_step (alist-ref gov-sources 'flow_step '()))
    (cons 'flow_dag_edge (alist-ref gov-sources 'flow_dag_edge '()))
    (cons 'step_requires_premise (alist-ref gov-sources 'step_requires_premise '()))
    (cons 'step_supports_premise (alist-ref gov-sources 'step_supports_premise '()))
    (cons 'step_mutability
          (map (lambda (r) (list (sym->str (car r)) (sym->str (cadr r)))) mutability-rows))
    (cons 'reuse_policy
          (map (lambda (f) (list (sym->str f))) policy-flags))
    (cons 'step_input_digest
          (map (lambda (r) (list (sym->str (car r)) (sym->str (cadr r)) (caddr r)))
               current-input-rows))
    (cons 'cached_witness
          (map (lambda (r) (map sym->str r)) cached-witness-rows))
    (cons 'cached_witness_input
          (map (lambda (r) (list (sym->str (car r)) (sym->str (cadr r)) (caddr r)))
               cached-input-rows))
    (cons 'step_toolchain_fingerprint
          (map (lambda (r) (list (sym->str (car r)) (sym->str (cadr r))))
               current-toolchain-rows))
    (cons 'cached_witness_toolchain
          (map (lambda (r) (list (sym->str (car r)) (sym->str (cadr r))))
               cached-toolchain-rows))
    (cons 'cached_witness_attested
          (map (lambda (s) (list (sym->str s))) attested-steps))
    (cons 'cached_witness_expired
          (map (lambda (s) (list (sym->str s))) expired-steps))))

;; Pure projection of an IR01-IR04 ASCENT result into a concise planning object.
(def (reuse-result->plan reuse-res)
  (def pending-steps (map car ((.ref reuse-res 'rows-of) 'step_pending)))
  (def reusable-steps (map car ((.ref reuse-res 'rows-of) 'step_reusable)))
  (def inv-rows ((.ref reuse-res 'rows-of) 'step_invalidated))
  (.o bind-these: #f
      pending: pending-steps
      reusable: reusable-steps
      invalidations: inv-rows))

(def (flatmap-step-slot steps slot-fn)
  (apply append
    (map (lambda (st)
           (def stid (symbol->string (.get st identity)))
           (map (lambda (v) (list stid (sym->str v))) (slot-fn st)))
         steps)))

;; Pure conversion from a VerificationSubject POO object to ASCENT MR01-MR06 sources.
(def (subject->governance-sources subject)
  (def sid (symbol->string (.get subject identity)))
  (def steps (.get subject steps))
  (list
    (cons 'subject_obligation
          (map (lambda (row) (list sid (sym->str (car row)) (sym->str (cadr row))))
               (.get subject obligations)))
    (cons 'subject_factor
          (map (lambda (f) (list sid (sym->str f))) (.get subject factors)))
    (cons 'method_allows_claim (default-method-allows-claim-rows))
    (cons 'flow_step
          (map (lambda (st)
                 (list (symbol->string (.get st identity))
                       sid
                       (symbol->string (.get st obligation))
                       (symbol->string (.get (.get st family) identity))
                       (symbol->string (.get st claim-kind))))
               steps))
    (cons 'flow_dag_edge
          (map (lambda (e) (list (sym->str (car e)) (sym->str (cadr e))))
               (.get subject dag-edges)))
    (cons 'step_produces (flatmap-step-slot steps (lambda (st) (.get st produces))))
    (cons 'step_consumes (flatmap-step-slot steps (lambda (st) (.get st consumes))))
    (cons 'step_requires_premise (flatmap-step-slot steps (lambda (st) (.get st requires-premises))))
    (cons 'step_supports_premise (flatmap-step-slot steps (lambda (st) (.get st supports-premises))))
    (cons 'correspondence_bridge
          (map (lambda (b) (list (sym->str (car b)) (sym->str (cadr b)) (sym->str (caddr b))))
               (.get subject correspondence-bridges)))
    (cons 'stateful_quint_step
          (filter-map (lambda (st)
                        (and (.get st stateful-quint?)
                             (list (symbol->string (.get st identity)))))
                      steps))
    (cons 'step_countermodel (flatmap-step-slot steps (lambda (st) (.get st countermodels))))
    (cons 'declared_os_containment
          (map (lambda (c) (list sid (sym->str (car c)) (sym->str (cadr c))))
               (.get subject os-containment)))))

;; Pure projector combining governance sources (from SysML v2 or VerificationSubject)
;; with live VerificationEvidenceRecordType observations from Fun-Flow execution.
(def (governance+evidence->admission-sources gov-sources evidence-records)
  (def ev-rows
    (map (lambda (ev)
           (list (sym->str (.get ev step))
                 (sym->str (.get ev obligation))
                 (sym->str (.get ev method))
                 (sym->str (.get ev claim-kind))
                 (sym->str (.get ev outcome))
                 (.get ev detail)))
         evidence-records))
  (list
    (cons 'subject_obligation (alist-ref gov-sources 'subject_obligation '()))
    (cons 'method_allows_claim (alist-ref gov-sources 'method_allows_claim '()))
    (cons 'flow_step (alist-ref gov-sources 'flow_step '()))
    (cons 'step_requires_premise (alist-ref gov-sources 'step_requires_premise '()))
    (cons 'step_supports_premise (alist-ref gov-sources 'step_supports_premise '()))
    (cons 'step_evidence ev-rows)))

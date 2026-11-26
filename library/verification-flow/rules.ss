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

;; Pure projector assembling IR01-IR04 ASCENT sources from governance sources,
;; mutability annotations, policy flags, current input digests, and cached witnesses.
(def (build-incremental-reuse-sources
       gov-sources
       mutability-rows
       policy-flags
       current-input-rows
       cached-witness-rows
       cached-input-rows)
  (list
    (cons 'flow_step (alist-ref gov-sources 'flow_step '()))
    (cons 'flow_dag_edge (alist-ref gov-sources 'flow_dag_edge '()))
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
               cached-input-rows))))

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

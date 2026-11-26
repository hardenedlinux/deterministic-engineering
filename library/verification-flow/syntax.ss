;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Hygienic Gerbil defrules metaprogramming adapters for Fun-Flow (10.154).
;;; Boundary invariant (upstream 10.07 rule #5): macros expand strictly to
;;; public Fun-Flow combinators and sealed POO objects — never a separate DSL.
(import
  :clan/poo/object
  (only-in :clan/poo/type validate)
  (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
           Fun
           make-task-family-descriptor
           flow-arr
           flow-then
           flow-fanout
           flow-output-contract)
  "types.ss"
  "func.ss")
(export
  defde-method-family
  defde-verification-step
  defde-verification-dag
  defde-verification-subject)

(defrules defde-method-family ()
  ((_ binding family-name capability runtime-owner adapter-op (claim-kinds ...))
   (def binding
     (validate VerificationMethodFamilyType
       (.o identity: 'family-name
           descriptor: (make-task-family-descriptor
                         'family-name 'capability 'adapter 'runtime-owner 'adapter-op)
           claim-kinds: '(claim-kinds ...))))))

(defrules defde-verification-step ()
  ((_ binding step-name family-obj
      obligation: obl-id
      claim-kind: ck-id
      operation: op-id
      payload: payload-expr
      input: in-contract
      output: out-contract
      produces: (prod ...)
      consumes: (cons ...)
      requires-premises: (req-p ...)
      supports-premises: (sup-p ...)
      stateful-quint?: stateful-flag
      countermodels: (cm ...)
      admit: admit-proc)
   (def binding
     (validate VerificationStepType
       (.o identity: 'step-name
           family: family-obj
           obligation: 'obl-id
           claim-kind: 'ck-id
           produces: '(prod ...)
           consumes: '(cons ...)
           requires-premises: '(req-p ...)
           supports-premises: '(sup-p ...)
           stateful-quint?: stateful-flag
           countermodels: '(cm ...)
           flow: (make-external-admit-flow
                   'step-name 'op-id payload-expr in-contract out-contract admit-proc))))))

(defrules defde-verification-dag ()
  ((_ binding dag-name
      then: (left-step right-step))
   (def binding
     (flow-then 'dag-name (flow-of left-step) (flow-of right-step))))
  ((_ binding dag-name
      fanout: (left-flow right-flow)
      converge-output: out-contract join-proc)
   (def binding
     (let ((fan (flow-fanout (string->symbol (string-append (symbol->string 'dag-name) "-fanout"))
                  (flow-of left-flow)
                  (flow-of right-flow))))
       (flow-then 'dag-name
         fan
         (flow-arr (string->symbol (string-append (symbol->string 'dag-name) "-join"))
                   (Fun out-contract <- (flow-output-contract fan))
                   join-proc))))))

(defrules defde-verification-subject ()
  ((_ binding subject-id
      factors: (fac ...)
      obligations: obl-expr
      os-containment: os-expr
      steps: steps-expr
      dag-edges: edges-expr
      correspondence-bridges: bridges-expr
      dag-flow: flow-expr)
   (def binding
     (validate VerificationSubjectType
       (.o identity: 'subject-id
           factors: '(fac ...)
           obligations: obl-expr
           os-containment: os-expr
           steps: steps-expr
           dag-edges: edges-expr
           correspondence-bridges: bridges-expr
           dag-flow: flow-expr)))))

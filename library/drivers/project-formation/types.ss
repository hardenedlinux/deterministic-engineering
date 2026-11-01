;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Complete effective Module shape; Library definitions remain a dependency.
(import
  :clan/poo/object
  (only-in :clan/poo/mop Any Function Type Type. define-type element? raise-type-error)
  (only-in :clan/poo/type String Symbol)
  (only-in :clan/poo/object-contract ObjectContract.)
  (only-in :yuanxu/object-types/contracts YuanxuContract. yuanxu-predicate-type)
  (only-in :gerbil-ascent/program/types GerbilAscentProgramContract)
  "../../project-organization/types.ss")
(export
  OrganizationScopeContract
  FormationConfigContract
  FormationScopeContract
  FormationReasonSignature
  FormationRenderSignature)
(def (selected-value identity-value expected)
  (yuanxu-predicate-type identity-value (lambda (v) (eq? v expected))))
(def FormationReasonSignature OrganizationReasonSignature)
(def FormationRenderSignature OrganizationRenderSignature)
(def FormationConfigShape
  (.cc ObjectContract. 'responsibilities
       (.o
         purpose: (selected-value 'formation/purpose 'declaration-layout)
         authority: (selected-value 'formation/authority 'design-only)
         program-owner: (selected-value 'formation/program-owner 'project-formation)
         reason-operation: (selected-value 'formation/reason-operation 'reason)
         render-operation: (selected-value 'formation/render-operation 'render))))
(def FormationConfigContract
  (.cc YuanxuContract. 'identity 'project-formation/config 'value-contract FormationConfigShape))
(def (binding-shape key signature-value)
  (.cc ObjectContract. 'responsibilities
       (.o
         definition: (.get OrganizationMethodContract value-contract)
         provider: (selected-value 'formation/provider 'project-formation)
         operation-name: (selected-value 'formation/operation key)
         operation: signature-value
         program: GerbilAscentProgramContract)))
(def FormationBindingsShape
  (.cc ObjectContract. 'responsibilities
       (.o
         reason: (binding-shape 'reason FormationReasonSignature)
         render: (binding-shape 'render FormationRenderSignature))))
(def FormationScopeShape
  (.cc ObjectContract. 'responsibilities
       (.o
         library: (.get OrganizationScopeContract value-contract)
         contracts: (.cc ObjectContract. 'responsibilities
                         (.o
                           config: (selected-value 'formation/config-contract FormationConfigContract)
                           scope: (selected-value 'formation/scope-contract FormationScopeContract)))
         semantics: FormationConfigShape
         program: GerbilAscentProgramContract
         method-bindings: FormationBindingsShape
         reason: FormationReasonSignature
         render: FormationRenderSignature)))
(def (associated? value)
  (and
   (element? FormationScopeShape value)
   (andmap
    (lambda (key)
      (def binding (.ref (.get value method-bindings) key))
      (and
       (eq? (.get binding definition) (.ref (.get value library entry methods) key))
       (eq? (.get binding program) (.get value program))
       (eq? (.get binding operation) (.ref value key))))
    '(reason render))))
;; Children come from actual admitted SD/Config and producer-normalized Functions.
;; Validate their full relation and retain them; never normalize away those links.
(define-type
  (FormationScopeType @ Type.)
  .element?:
  associated?
  .validate:
  (lambda (value) (unless (associated? value) (raise-type-error @ value)) value))
(def FormationScopeContract
  (.cc YuanxuContract. 'identity 'project-formation/scope 'value-contract FormationScopeType))

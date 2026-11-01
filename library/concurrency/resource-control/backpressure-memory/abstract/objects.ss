;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Authored generic meaning; no repo capture, tool lookup or execution here.
(import
  :clan/poo/object
  "types.ss")
(export
  BackpressureModel
  BackpressureDeclaration)
(.def BackpressureDeclaration
  identity: 'backpressure-memory.declaration
  family: 'concurrency.resource-control.backpressure-memory
  source-owner: 'backpressure-memory
  applicability: '(bounded-retention)
  role-contracts: (list BackpressureModelContract)
  extension-expectations: '(specialization integration policy))
(.def BackpressureModel
  identity: 'concurrency.resource-control.backpressure-memory
  role: 'generic-model
  family: 'concurrency.resource-control.backpressure-memory
  declaration-contract: BackpressureDeclarationContract
  contract: BackpressureModelContract
  parent: #f
  revision: "ownership-budget/v1"
  lifecycle: '(waiting queued active returned cleanup released)
  factor-implications: '()
  rules: '((bounded-retention BP-O01 review)
           (bounded-retention BP-O02 quint)
           (bounded-retention BP-O03 lean))
  dependencies: '((BP-O01 inventory)
                  (BP-O01 source)
                  (BP-O02 model)
                  (BP-O03 arithmetic))
  input-demands: '(inventory source model arithmetic)
  premises: (list
             (.o
               identity: 'complete-owned-inventory
               inputs: '(inventory source)
               statement: "Every retained ownership position and its release path is included in the selected inventory.")
             (.o
               identity: 'selected-finite-model
               inputs: '(model)
               statement: "The selected finite model and parameters represent only their declared abstract lifecycle and accounting units.")
             (.o
               identity: 'selected-arithmetic
               inputs: '(arithmetic)
               statement: "The budget interpretation uses the selected item, queue, capacity, fixed and cache accounting parameters."))
  claims: (list
           (.o
             identity: 'BP-O01
             meaning: "Ownership inventory and release paths require independent review."
             premises: '(complete-owned-inventory)
             duties: '(BP-O01)
             strength: 'authored-conditional)
           (.o
             identity: 'BP-O02
             meaning: "The selected finite model preserves its declared ownership invariant."
             premises: '(selected-finite-model)
             duties: '(BP-O02)
             strength: 'finite-model)
           (.o
             identity: 'BP-O03
             meaning: "The selected arithmetic budget follows under its explicit accounting assumptions."
             premises: '(selected-arithmetic)
             duties: '(BP-O03)
             strength: 'arithmetic))
  limits: (list
           (.o
             identity: 'abstract-model-bound
             inputs: '(model arithmetic)
             statement: "Finite-state and arithmetic conclusions do not establish runtime scheduling, byte accounting or complete implementation refinement."))
  assets: (list
           (.o
             identity: 'backpressure.model
             revision: "ownership-budget/v1"
             owner: 'backpressure-memory
             kind: 'quint
             relative-path: "../model.qnt")
           (.o
             identity: 'backpressure.budget
             revision: "ownership-budget/v1"
             owner: 'backpressure-memory
             kind: 'lean
             relative-path: "../budget.lean"))
  capabilities: '(quint-model-asset lean-budget-asset)
  method-refs: '()
  qualification: 'conditional-abstract-model)

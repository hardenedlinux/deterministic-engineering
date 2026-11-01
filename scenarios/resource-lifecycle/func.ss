;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

;;; -*- Gerbil -*-
(import
  :clan/poo/object
  (only-in :clan/poo/mop validate))
(export
  resource-lifecycle-scope)
(.def ResourceLifecycleScenario.
  domain: (error "Resource Scenario requires its domain")
  evidence: (error "Resource Scenario requires its evidence Module")
  contracts: (error "Resource Scenario requires its owner Contract")
  entry: (.get domain entry)
  integration-entry: (.get domain integration-entry)
  methods: (.get domain methods)
  capture: (lambda (root profile crate cargo rustc usage (mode 'normal))
             ((.get methods native-context) root entry profile crate cargo rustc usage mode))
  open-review: (lambda (context)
                 (validate (.get domain context-contract) context)
                 (unless (and
                          (eq? entry (.get domain entry))
                          (eq? methods (.get domain methods))
                          (eq? (.get context entry) entry))
                   (error "context or Scenario belongs to another Library entry"))
                 ((.get methods context-current!) context)
                 ((.get evidence open-review)
                  entry
                  (.get context profile)
                  (.get context usage)
                  (.get context snapshot)
                  (.get context scopes))))
(def (resource-lifecycle-scope selected-domain selected-evidence selected-contract)
  (.o (:: @ ResourceLifecycleScenario.)
      domain: selected-domain
      evidence: selected-evidence
      contracts: (.o
                   scope: selected-contract)))

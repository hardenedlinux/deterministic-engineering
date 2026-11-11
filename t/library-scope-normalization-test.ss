;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;; -*- Gerbil -*-
(import :std/test :clan/poo/object
        (only-in :clan/poo/mop validate)
        (only-in :clan/poo/recursive-validation closed-names)
        (only-in "../library/backpressure-memory/types.ss"
          BackpressureScopeContract BackpressureModelContract BackpressureDeclarationContract BackpressureConfigContract)
        (only-in "../library/backpressure-memory/objects.ss"
          BackpressureModel BackpressureDeclaration)
        (only-in "../library/project-organization/types.ss"
          OrganizationScopeContract OrganizationModelContract OrganizationDeclarationContract OrganizationConfigContract)
        (only-in "../library/project-organization/objects.ss"
          ProjectOrganization OrganizationDeclaration))
(export library-scope-normalization-test)

(def (raw-scope model-value declaration-value model-contract declaration-contract config-contract)
  (.o entry: model-value declaration: declaration-value
      config: (.o entry: model-value declaration: declaration-value)
      contracts: (.o model: model-contract declaration: declaration-contract config: config-contract)))

(def (check-scope contract value)
  (def normalized (validate contract value))
  (check-equal? (closed-names (.get normalized validation)) '(entry declaration config))
  (check-equal? (eq? (.get normalized entry) (.get normalized config entry)) #t)
  (check-equal? (eq? (.get normalized declaration) (.get normalized config declaration)) #t)
  (check-equal? (eq? (validate contract normalized) normalized) #t)
  ;; A structurally equal copy is not the same Config association.
  (check-exception
    (validate contract (.cc value 'config (.cc (.get value config) 'entry (.cc (.get value entry) 'revision (.get value entry revision)))))
    (lambda (_) #t))
  (check-exception
    (validate contract (.cc normalized 'entry (.cc (.get normalized entry) 'revision (.get normalized entry revision))))
    (lambda (_) #t))
  normalized)

(def library-scope-normalization-test
  (test-suite "Shared native Scope closure"
    (test-case "backpressure preserves associations and normalized identity"
      (check-scope BackpressureScopeContract
        (raw-scope BackpressureModel BackpressureDeclaration
          BackpressureModelContract BackpressureDeclarationContract BackpressureConfigContract)))
    (test-case "organization uses the same closure without sharing domain authority"
      (def value
        (raw-scope ProjectOrganization OrganizationDeclaration
          OrganizationModelContract OrganizationDeclarationContract OrganizationConfigContract))
      (check-scope OrganizationScopeContract value)
      (check-exception (validate BackpressureScopeContract value) (lambda (_) #t)))))

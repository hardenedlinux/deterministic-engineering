;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :std/test :clan/poo/object
 (only-in :clan/poo/mop validate)
 "../types.ss"
 "../library/project-organization/types.ss"
 "../library/project-organization/objects.ss"
 "../library/drivers/project-formation/types.ss"
 "../library/drivers/project-formation/objects.ss")
(export organization-library-test)
(def organization-library-test
 (test-suite "Organization declarations, independent demand and Module policy"
  (test-case "family inherits the single generation and model has actual catalog closure"
   (check-equal? (.get OrganizationDeclarationContract contract-version) (.get LibraryDeclarationContract contract-version))
   (validate (.get OrganizationDeclarationContract value-contract) OrganizationDeclaration)
   (def model (validate (.get OrganizationModelContract value-contract) ProjectOrganization))
   (check-equal? (.get model role) 'organization)
   (check-equal? (.get model parent) #f)
   (check-equal? (.get model mapping catalog-id) (.get model catalog identity))
   (check-equal? (.get model capabilities) '(organization-demands))
   (check-equal? (length (.get model required-capabilities)) 4))
  (test-case "lost demand, wrong role, duplicate roles and catalog escape refuse"
   (def expected (.get OrganizationModelContract value-contract))
   (for-each (lambda (candidate) (check-exception (validate expected candidate) error?))
    (list (.cc ProjectOrganization 'products '())
          (.cc ProjectOrganization 'method-refs '())
          (.cc ProjectOrganization 'methods (.cc (.get ProjectOrganization methods) 'reason
            (.cc (.get ProjectOrganization methods reason) 'claims '(foreign-obligation))))
          (.cc ProjectOrganization 'methods (.cc (.get ProjectOrganization methods) 'render
            (.cc (.get ProjectOrganization methods render) 'catalog-ref
              (.cc (.get ProjectOrganization methods render catalog-ref) 'identity 'foreign-catalog))))
          (.cc ProjectOrganization 'role 'generic-model)
          (.cc ProjectOrganization 'roles (cons (car (.get ProjectOrganization roles)) (.get ProjectOrganization roles)))
          (.cc ProjectOrganization 'catalog (.cc (.get ProjectOrganization catalog) 'definitions '("Foreign"))))))
  (test-case "Module policy cannot claim runtime authority or change Program owner"
   (def expected (.get FormationConfigContract value-contract))
   (validate expected FormationSemantics)
   (check-exception (validate expected (.cc FormationSemantics 'authority 'runtime-authority)) error?)
   (check-exception (validate expected (.cc FormationSemantics 'program-owner 'foreign)) error?))))

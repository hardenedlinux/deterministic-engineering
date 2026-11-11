;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import
  :clan/poo/object)
(export
  LibraryFormationProfile)
;; Current project proposals; no candidate identifiers appear in engine rules.
(def full-owners
  '(("definitions" "library")
    ("selection" "profile")
    ("capture" "scenario")
    ("reasoning" "ascent")
    ("review" "aitia")
    ("documentation" "documents")
    ("method-contracts" "library")
    ("receipt-issuance" "yuanxu")
    ("project-entry" "project")))
(def all-products '("D01" "D02" "D03" "D04" "D05" "D06" "D07" "D08" "D09" "D10"))
(def all-duties '("DE-O-ARCH" "DE-O-DOC" "DE-O-DEC" "DE-O-TRACE" "DE-O-REVIEW"))
(.def FormationCandidate.
  project: "DE-CASE-01"
  basis: "reusable-library"
  owners: full-owners
  products: all-products
  duties: all-duties
  capabilities: '())
(def LibraryFormationProfile
  (.o
    project: "DE-CASE-01"
    intent: "reusable-library"
    project-inputs: '("gerbil.pkg" "projects/library-formation/init.ss"
                      "library/library-formation-profiles/objects.ss" "project.sysml"
                      "docs/10-19-design/10-architecture/10.107-implementation-progress-and-execution-gates.org")
    input-byte-limit: 1048576
    input-lifetime-seconds: 60
    model-root: "DE-PROJECT"
    model-package: "DeterministicEngineering"
    model-instance: "libraryProject"
    model-library: "RepositoryOrganization"
    organization: 'project-organization
    model-catalog: 'organization.catalog
    model-mapping: 'organization.role-layout
    resource-model: 'rust.resources.backpressure-memory
    integration: 'rust.resources.backpressure-memory.integration
    coding-policy: 'rust.resources.backpressure-memory.review-policy
    design-policy: 'rust.resources.backpressure-memory.design-review-policy
    resource-methods: '(native quint lean integration)
    ;; role, project slot, type label, existing detail-model reference
    layout: '(("definitions" "definitions" "LibraryDefinitions" "LibraryDefinitions")
              ("selection" "selection" "IndependentProfile" "IndependentProfile")
              ("capture" "scenarioUse" "ProjectScenario" "ProjectScenario")
              ("reasoning" "reasoning" "ApplicationReasoning" "ApplicationReasoning")
              ("review" "review" "ReviewBoundary" "ReviewBoundary")
              ("documentation" "documentation" "DocumentOrganization" "DocumentOrganization")
              ("method-contracts" "methodContracts" "MethodContracts" "MethodContracts")
              ("receipt-issuance" "receiptIssuance" "ReceiptBoundary" "ReceiptBoundary")
              ("project-entry" "projectEntry" "ProjectEntry" "ProjectEntry"))
    ;; Authored edge identities survive order changes and round trips.
    dependencies: '(("selection-definitions" "selection" "definitions")
                    ("capture-selection" "capture" "selection")
                    ("capture-definitions" "capture" "definitions")
                    ("reasoning-capture" "reasoning" "capture")
                    ("review-reasoning" "review" "reasoning")
                    ("documentation-definitions" "documentation" "definitions")
                    ("methods-definitions" "method-contracts" "definitions")
                    ("receipts-capture" "receipt-issuance" "capture")
                    ("entry-definitions" "project-entry" "definitions")
                    ("entry-capture" "project-entry" "capture")
                    ("entry-reasoning" "project-entry" "reasoning"))
    candidates:
    (list
     (.o (:: @ FormationCandidate.)
         identity: "LIB-C01")
     (.o (:: @ FormationCandidate.)
         identity: "LIB-C02"
         owners: => (cut
                     map
                     (lambda (row)
                       (if (member (car row) '("capture" "reasoning" "review" "receipt-issuance"))
                           (list (car row) "library")
                           row))
                     <>))
     (.o (:: @ FormationCandidate.)
         identity: "LIB-C03"
         owners: '(("documentation" "documents"))
         products: '("D01" "D04" "D05" "D09")
         duties: '("DE-O-DOC")))))

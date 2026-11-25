;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  (only-in :clan/poo/object .def .o .get)
  "types.ss" "objects.ss" "config.ss" "func.ss")
(export ResourceEvidence)
(.def ResourceEvidence
  identity: 'evidence
  tags: '(engineering driver reasoning source-contract)
  core:
  (.o
    admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-contract)))
    scope-contract: (.get ResourceEvidenceScopeContract value-contract)
    exports: (.o
               sources: resource-review-sources
               make-evidence: make-resource-evidence
               config: Config
               config-contract: ResourceEvidencePolicyType
               policy: Config))
  features: (.o))

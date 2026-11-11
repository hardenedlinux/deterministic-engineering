;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  (only-in :yuanxu/module-system/source/declaration .def))
(.def ResourceEvidence
  identity: 'evidence
  tags: '(engineering driver reasoning source-contract)
  admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-contract)))
  core:
  (.o
    requires: (.o)
    scope-contract: (.get ResourceEvidenceScopeContract value-contract)
    exports: (.o
               sources: resource-review-sources
               make-evidence: make-resource-evidence
               config: Config
               config-contract: ResourceEvidencePolicyType
               policy: Config))
  features: (.o))

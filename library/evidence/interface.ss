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

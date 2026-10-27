;;; -*- Gerbil -*-
(import (only-in :yuanxu/module-system/source/declaration .def))
(.def ResourceEvidence
  identity: 'resource-evidence
  core:
  (.o requires: (.o)
      scope-contract: ResourceEvidenceScopeContract
      exports: (.o open-review: open-resource-review make-evidence: make-resource-evidence policy: Config))
  features: (.o))

;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  (only-in :yuanxu/module-system/source/declaration .def))
(.def ResourceEvidence
  identity: 'evidence
  core:
  (.o
    requires: (.o)
    scope-contract: ResourceEvidenceScopeContract
    exports: (.o
               open-review: open-resource-review
               make-evidence: make-resource-evidence
               policy: Config))
  features: (.o))

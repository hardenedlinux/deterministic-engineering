;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  (only-in :yuanxu/module-system/source/declaration .def))
(.def GatewayReview
  identity: 'gateway-review
  core:
  (.o
    requires: (.o
                Domain: (.o
                          module-id: 'rust-resources
                          contract: RustResourcesScopeContract)
                Evidence: (.o
                            module-id: 'evidence
                            contract: ResourceEvidenceScopeContract))
    scope-contract: ScenarioScopeContract
    exports: (gateway-review-scope Domain Evidence))
  features: (.o))

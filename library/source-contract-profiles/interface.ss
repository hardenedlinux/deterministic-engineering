;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :yuanxu/module-system/source/declaration .def))
(.def ProfileModule
  identity: 'source-contract-profiles
  tags: '(engineering profile source-contract)
  admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
  core:
  (.o
    requires: (.o Driver: (.o module-id: 'source-contracts))
    scope-contract: ScopeType
    exports:
    (.o
      config: Config
      config-type: ConfigType
      plan-library: Driver
      profiles: (source-contract-profiles (.get Driver strategies))))
  features: (.o))

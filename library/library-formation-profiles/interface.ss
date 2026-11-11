;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :yuanxu/module-system/source/declaration .def))
(.def ProfileModule
  identity: 'library-formation-profiles
  tags: '(engineering profile)
  admissions: (.o Config: (.o export-path: '(config) contract-path: '(config-type)))
  core:
  (.o
    requires: (.o)
    scope-contract: ScopeType
    exports:
    (.o
      config: Config
      config-type: ConfigType
      profiles: (.o LibraryFormationProfile)))
  features: (.o))

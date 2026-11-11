;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :yuanxu/module-system/source/declaration .def))
(.def ResourceLifetime
  identity: 'resource-lifetime
  tags: '(engineering domain memory source-contract)
  admissions: (.o Config: (.o export-path: '(config) contract-path: '(contracts config)))
  core: (.o
          requires: (.o)
          scope-contract: (.get CatalogScopeContract value-contract)
          exports: (.o entry: (.get Config entry)
                       config: Config
                       contracts: (.o config: CatalogConfigContract)))
  features: (.o))

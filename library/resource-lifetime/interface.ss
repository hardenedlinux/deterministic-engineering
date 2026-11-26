;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        "types.ss" "config.ss")
(export ResourceLifetime)
(.def ResourceLifetime
  identity: 'resource-lifetime
  tags: '(engineering domain memory source-contract de.layer.domain)
  core: (.o
          admissions: (.o Config: (.o export-path: '(config) contract-path: '(contracts config)))
          scope-contract: (.get CatalogScopeContract value-contract)
          exports: (.o entry: (.get Config entry)
                       config: Config
                       contracts: (.o config: CatalogConfigContract)))
  features: (.o))

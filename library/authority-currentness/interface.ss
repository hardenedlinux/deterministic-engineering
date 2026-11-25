;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        "types.ss" "config.ss")
(export AuthorityCurrentness)
(.def AuthorityCurrentness
  identity: 'authority-currentness
  tags: '(engineering domain threat)
  core: (.o
          admissions: (.o Config: (.o export-path: '(config) contract-path: '(contracts config)))
          scope-contract: (.get CatalogScopeContract value-contract)
          exports: (.o entry: (.get Config entry)
                       config: Config
                       contracts: (.o config: CatalogConfigContract)))
  features: (.o))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :clan/poo/object .def .o .get)
        "types.ss"
        "config.ss"
        "func.ss")
(export SearchEngine)

(.def SearchEngine
  identity: 'search-engine
  tags: '(engineering domain search source-contract de.layer.domain)
  core: (.o
          admissions: (.o Config: (.o export-path: '(config) contract-path: '(contracts config)))
          scope-contract: (.get CatalogScopeContract value-contract)
          exports: (.o entry: (.get Config entry)
                       config: Config
                       contracts: (.o config: CatalogConfigContract)
                       select-niche-diverse: select-niche-diverse-rows
                       select-mmr-diverse: select-mmr-diverse-items
                       diversity-coverage: compute-diversity-coverage-report
                       hybrid-impact-coverage: compute-hybrid-impact-coverage
                       decompose-zero-hit-stems: decompose-zero-hit-stems
                       classify-tier: classify-search-tier-intent))
  features: (.o))

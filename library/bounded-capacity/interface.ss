(import (only-in :yuanxu/module-system/source/declaration .def))
(.def BoundedCapacity
  identity: 'bounded-capacity
  tags: '(engineering domain numeric source-contract)
  admissions: (.o Config: (.o export-path: '(config) contract-path: '(contracts config)))
  core: (.o
          requires: (.o)
          scope-contract: (.get CatalogScopeContract value-contract)
          exports: (.o entry: (.get Config entry)
                       config: Config
                       contracts: (.o config: CatalogConfigContract)))
  features: (.o))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import
  (only-in :yuanxu/module-system/source/declaration .def))
(.def BackpressureLibrary
  identity: 'backpressure-memory
  tags: '(engineering domain concurrency)
  admissions: (.o
                Config: (.o
                          export-path: '(config)
                          contract-path: '(contracts config)))
  core: (.o
          requires: (.o)
          scope-contract: (.get BackpressureScopeContract value-contract)
          exports: (.o (:: scope)
                     self: scope
                     config: Config
                     declaration: (.get scope config declaration)
                     entry: (.get scope config entry)
                     contracts: (.o
                                  model: BackpressureModelContract
                                  declaration: BackpressureDeclarationContract
                                  config: BackpressureConfigContract)))
  features: (.o))

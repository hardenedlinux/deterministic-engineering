;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import
  (only-in :clan/poo/object .def .o .get)
  "types.ss"
  "config.ss")
(export BackpressureLibrary)
(.def BackpressureLibrary
  identity: 'backpressure-memory
  tags: '(engineering domain concurrency)
  core: (.o
          admissions: (.o
                        Config: (.o
                                  export-path: '(config)
                                  contract-path: '(contracts config)))
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

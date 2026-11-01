;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

(import
  (only-in :yuanxu/module-system/source/declaration .def))
(.def BackpressureLibrary
  identity: 'backpressure-memory
  admissions: (.o
                Config: (.o
                          export-path: '(config)
                          contract-path: '(contracts config)))
  core: (.o
          requires: (.o)
          scope-contract: BackpressureScopeContract
          exports: (.o
                     self: scope
                     config: Config
                     declaration: (.get scope config declaration)
                     entry: (.get scope config entry)
                     contracts: (.o
                                  model: BackpressureModelContract
                                  declaration: BackpressureDeclarationContract
                                  config: BackpressureConfigContract)))
  features: (.o))

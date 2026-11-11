;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Authored specialization is an atomic native Module, separate from execution.
(import (only-in :yuanxu/module-system/source/declaration .def))
(.def TokioRayonLibrary
  identity: 'backpressure-tokio-rayon
  tags: '(engineering domain rust concurrency)
  admissions: (.o
    Config: (.o export-path: '(config) contract-path: '(contracts config)))
  core: (.o
    requires: (.o Parent: (.o module-id: 'backpressure-memory contract: (.get BackpressureScopeContract value-contract)))
    scope-contract: (.get TokioRayonScopeContract value-contract)
    exports: (.o
      config: Config
      contracts: (.o config: TokioRayonConfigContract scope: TokioRayonScopeContract)
      parent: Parent
      specialize: (lambda (references)
                    (specialize-backpressure (.get Parent entry) references))
      integrate: make-backpressure-integration))
  features: (.o))

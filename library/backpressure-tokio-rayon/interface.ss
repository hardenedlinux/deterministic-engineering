;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Authored specialization is an atomic native Module, separate from execution.
(import (only-in :clan/poo/object .def .o .get)
        "types.ss" "objects.ss" "config.ss"
        (only-in "../backpressure-memory/interface.ss" BackpressureLibrary))
(export TokioRayonLibrary)
(def Parent (.get BackpressureLibrary core exports))
(.def TokioRayonLibrary
  identity: 'backpressure-tokio-rayon
  tags: '(engineering domain rust concurrency de.layer.domain)
  core: (.o
    admissions: (.o
      Config: (.o export-path: '(config) contract-path: '(contracts config)))
    scope-contract: (.get TokioRayonScopeContract value-contract)
    exports: (.o
      config: Config
      contracts: (.o config: TokioRayonConfigContract scope: TokioRayonScopeContract)
      parent: Parent
      specialize: (lambda (references)
                    (specialize-backpressure (.get Parent entry) references))
      integrate: make-backpressure-integration))
  features: (.o))

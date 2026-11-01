;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import (only-in :yuanxu/module-system/source/declaration .def))
(.def RustResources
  identity: 'rust-resources
  admissions: (.o
                Config: (.o
                          export-path: '(config)
                          contract-path: '(contracts config)))
  core:
  (.o
    requires: (.o
                Parent: (.o
                          module-id: 'backpressure-memory
                          contract: BackpressureScopeContract)
                ModelLibrary: (.o
                  module-id: 'backpressure-tokio-rayon
                  contract: TokioRayonScopeContract))
    scope-contract: RustResourcesScopeContract
    exports: (.o
               self: scope
               parent: Parent
               config: (.o (:: @ Config)
                         coding-policy: (.get ModelLibrary config coding-policy)
                         design-policy: (.get ModelLibrary config design-policy))
               model-library: ModelLibrary
               contracts: (.o
                            scope: RustResourcesScopeContract
                            config: RustResourcesConfigContract
                            model: RustResourceModelContract
                            integration: BackpressureIntegrationContract
                            coding-policy: BackpressureReviewPolicyContract
                            design-policy: BackpressureDesignReviewPolicyContract)
               policies: (.o
                           coding: (.get scope config coding-policy)
                           design: (.get scope config design-policy))
               entry: ((.get ModelLibrary specialize)
                        (map (lambda (key) (method-ref (.ref RustMethodDefinitions key)))
                             '(native quint lean)))
               integration-entry: ((.get ModelLibrary integrate) (.ref scope 'entry)
                                    (method-ref (.get RustMethodDefinitions integration)))
               profile-contract: ResourceProfileContract
               native-profile-contract: ResourceNativeProfileContract
               context-contract: ResourceNativeContextContract
               bound-methods: (bind-resource-methods RustMethodDefinitions)
               methods: (.get scope bound-methods operations)))
  features: (.o))

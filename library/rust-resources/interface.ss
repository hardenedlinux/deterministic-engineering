;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import (only-in :clan/poo/object .def .o .get .ref)
        "types.ss" "objects.ss" "config.ss"
        (only-in "../backpressure-memory/interface.ss" BackpressureLibrary)
        (only-in "../backpressure-tokio-rayon/interface.ss" TokioRayonLibrary))
(export RustResources)
(def Parent (.get BackpressureLibrary core exports))
(def ModelLibrary (.get TokioRayonLibrary core exports))
(.def RustResources
  identity: 'rust-resources
  tags: '(engineering driver rust)
  core:
  (.o
    admissions: (.o
                  Config: (.o
                            export-path: '(config)
                            contract-path: '(contracts config)))
    scope-contract: (.get RustResourcesScopeContract value-contract)
    exports: (.o (:: scope)
               definitions: RustMethodDefinitions
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
))
  features: (.o))

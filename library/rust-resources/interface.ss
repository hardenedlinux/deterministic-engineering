;;; -*- Gerbil -*-
(import (only-in :yuanxu/module-system/source/declaration .def))
(.def RustResources
  identity: 'rust-resources
  tags: '(engineering driver rust)
  admissions: (.o
                Config: (.o
                          export-path: '(config)
                          contract-path: '(contracts config)))
  core:
  (.o
    requires: (.o
                Parent: (.o
                          module-id: 'backpressure-memory
                          contract: (.get BackpressureScopeContract value-contract))
                ModelLibrary: (.o
                  module-id: 'backpressure-tokio-rayon
                  contract: (.get TokioRayonScopeContract value-contract)))
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

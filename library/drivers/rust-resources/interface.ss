;;; -*- Gerbil -*-
(import
  (only-in :yuanxu/module-system/source/declaration .def))
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
                          contract: BackpressureScopeContract))
    scope-contract: RustResourcesScopeContract
    exports: (.o
               self: scope
               parent: Parent
               config: Config
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
               entry: (specialize-backpressure (.ref Parent 'entry))
               integration-entry: (make-backpressure-integration (.ref scope 'entry))
               profile-contract: ResourceProfileContract
               native-profile-contract: ResourceNativeProfileContract
               context-contract: ResourceNativeContextContract
               bound-methods: (bind-resource-methods RustMethodDefinitions)
               methods: (.get scope bound-methods operations)))
  features: (.o))

;;; -*- Gerbil -*-
(import
  (only-in :yuanxu/module-system/source/declaration .def))
(.def ResourceLifecycle
  identity: 'resource-lifecycle
  core:
  (.o
    requires: (.o
                Domain: (.o
                          module-id: 'rust-resources
                          contract: RustResourcesScopeContract)
                Evidence: (.o
                            module-id: 'evidence
                            contract: ResourceEvidenceScopeContract))
    scope-contract: ResourceLifecycleScopeContract
    exports: (resource-lifecycle-scope Domain Evidence ResourceLifecycleScopeContract))
  features: (.o))

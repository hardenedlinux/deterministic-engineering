;;; -*- Gerbil -*-
(.def ResourceLifecycle
  identity: 'resource-lifecycle
  core:
  (.o requires: (.o Domain: (.o module-id: 'rust-resources contract: RustResourcesScopeContract)
                    Evidence: (.o module-id: 'resource-evidence contract: ResourceEvidenceScopeContract))
      scope-contract: ResourceLifecycleScopeContract
      exports: (resource-lifecycle-scope Domain Evidence))
  features: (.o))

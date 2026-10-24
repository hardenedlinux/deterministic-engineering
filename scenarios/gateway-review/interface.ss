;;; -*- Gerbil -*-
(.def GatewayReview
  identity: 'gateway-review
  core:
  (.o requires: (.o Domain: (.o module-id: 'rust-resources
                                contract: RustResourcesScopeContract)
                    Evidence: (.o module-id: 'resource-evidence
                                  contract: ResourceEvidenceScopeContract))
      scope-contract: ScenarioScopeContract
      exports: (gateway-review-scope Domain Evidence))
  features: (.o))

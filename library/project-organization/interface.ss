(import
  (only-in :yuanxu/module-system/source/declaration .def))
(.def ProjectOrganizationLibrary
  identity: 'project-organization
  admissions: (.o
                Config: (.o
                          export-path: '(config)
                          contract-path: '(contracts config)))
  core: (.o
          requires: (.o)
          scope-contract: OrganizationScopeContract
          exports: (.o
                     self: scope
                     config: Config
                     declaration: (.get scope config declaration)
                     entry: (.get scope config entry)
                     contracts: (.o
                                  model: OrganizationModelContract
                                  declaration: OrganizationDeclarationContract
                                  config: OrganizationConfigContract)))
  features: (.o))

(import
  (only-in :yuanxu/module-system/source/declaration .def))
(.def ProjectFormation
  identity: 'project-formation
  tags: '(engineering driver organization)
  admissions: (.o
                Config: (.o
                          export-path: '(config)
                          contract-path: '(contracts config)))
  core: (.o
          requires: (.o
                      Library: (.o
                                 module-id: 'project-organization
                                 contract: (.get OrganizationScopeContract value-contract)))
          scope-contract: (.get FormationScopeContract value-contract)
          exports: (.o (:: module-scope)
                     self: module-scope
                     library: Library
                     config: Config
                     semantics: Config
                     contracts: (.o
                                  config: FormationConfigContract
                                  scope: FormationScopeContract)
                     program: FormationProgram
                     method-bindings: (bind-formation-methods Library)
                     reason: (.get module-scope method-bindings reason operation)
                     render: (.get module-scope method-bindings render operation)))
  features: (.o))

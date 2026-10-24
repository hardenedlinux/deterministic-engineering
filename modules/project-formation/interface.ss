(.def ProjectFormation
 identity: 'project-formation
 admissions: (.o Config: (.o export-path: '(semantics) contract-path: '(contracts config)))
 core: (.o requires: (.o Library: (.o module-id: 'project-organization contract: OrganizationScopeContract))
           scope-contract: FormationScopeContract
           exports: (.o self: module-scope library: Library semantics: Config contracts: (.o config: FormationConfigContract scope: FormationScopeContract)
             program: FormationProgram method-bindings: (bind-formation-methods Library)
             reason: (.get module-scope method-bindings reason operation)
             render: (.get module-scope method-bindings render operation)))
 features: (.o))

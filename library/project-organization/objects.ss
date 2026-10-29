(import
  :clan/poo/object
  "types.ss")
(export
  ProjectOrganization
  OrganizationDeclaration)
;; Reusable authored definitions. No project occurrence or execution claims.
(def organization-family 'project-organization)
(def OrganizationDeclaration
  (.o
    identity: 'organization-library
    family: organization-family
    source-owner: 'project-organization
    applicability: '(repository-architecture documentation decision-review)
    role-contracts: (list OrganizationModelContract OrganizationCatalogContract OrganizationMappingContract)
    extension-expectations: '(policy method)))
(def catalog-asset
  (.o
    identity: 'organization.catalog
    revision: "organization-layout"
    owner: 'project-organization
    kind: 'sysml
    relative-path: "organization.sysml"))
(def catalog-value
  (.o
    identity: 'organization.catalog
    revision: "organization-layout"
    owner: 'project-organization
    role: 'catalog
    family: organization-family
    declaration-contract: OrganizationDeclarationContract
    contract: OrganizationCatalogContract
    asset: catalog-asset
    package: 'RepositoryOrganization
    definitions: '("LibraryDefinitions" "IndependentProfile" "ProjectScenario" "ApplicationReasoning"
                   "ReviewBoundary" "DocumentOrganization" "MethodContracts" "ReceiptBoundary" "ProjectEntry")))
(def mapping-value
  (.o
    identity: 'organization.role-layout
    revision: "role-definition-layout"
    owner: 'project-organization
    role: 'mapping
    family: organization-family
    declaration-contract: OrganizationDeclarationContract
    contract: OrganizationMappingContract
    catalog-id: (.get catalog-value identity)
    roles: '(("definitions" "LibraryDefinitions")
             ("selection" "IndependentProfile")
             ("capture" "ProjectScenario")
             ("reasoning" "ApplicationReasoning")
             ("review" "ReviewBoundary")
             ("documentation" "DocumentOrganization")
             ("method-contracts" "MethodContracts")
             ("receipt-issuance" "ReceiptBoundary")
             ("project-entry" "ProjectEntry"))
    loss: "Architecture responsibility categories; no implementation or authorization conclusion."))
(def (method-ref definition-value)
  (.o
    identity: (.get definition-value identity)
    revision: (.get definition-value revision)
    owner: (.get definition-value owner)))
(.def OrganizationMethod.
  operation: (error "Organization method requires an operation")
  identity: (string->symbol (string-append "organization." (symbol->string operation)))
  revision: "formation-rules"
  owner: 'project-organization
  role: 'method
  family: organization-family
  declaration-contract: OrganizationDeclarationContract
  contract: OrganizationMethodContract
  kind: (.get (.ref OrganizationMethodRequirements operation) kind)
  model-ids: '(project-organization)
  policy-ids: '()
  claims: '(organization.coverage)
  modes: '(design-only)
  strength: 'authored-conditional
  signature: (.get (.ref OrganizationMethodRequirements operation) signature)
  provider: 'project-formation
  result-owner: 'project-formation
  result-kinds: '(declaration-findings candidate-notation)
  input-demands: '(organization-demands profile proposals actual-program source-closure)
  assets: (list catalog-asset)
  premises: (list
             (.o
               identity: 'declaration-only
               inputs: '(proposals)
               statement: "Candidate facts are assertions; genuine capability and origin verification remain separate."))
  limits: (list
           (.o
             identity: 'no-runtime-authority
             inputs: '(actual-program)
             statement: "Design findings and generated notation are not accepted Q, validation, publication or authority."))
  program-ref: (.o
                 identity: 'project-formation.program
                 revision: "formation-rules"
                 owner: 'project-formation)
  catalog-ref: (method-ref catalog-value)
  mapping-ref: (method-ref mapping-value))
(def OrganizationMethods
  (.o
    reason: (.o (:: @ OrganizationMethod.)
                operation: 'reason)
    render: (.o (:: @ OrganizationMethod.)
                operation: 'render)))
(def ProjectOrganization
  (.o
    identity: 'project-organization
    role: 'organization
    family: organization-family
    declaration-contract: OrganizationDeclarationContract
    contract: OrganizationModelContract
    parent: #f
    revision: "organization-demands"
    lifecycle: '()
    rules: '()
    dependencies: '()
    input-demands: '(confirmed-intent proposals repository-inputs role-mandates)
    premises: (list
               (.o
                 identity: 'independent-demand
                 inputs: '(confirmed-intent)
                 statement: "Required responsibilities and products are independent of each proposal."))
    claims: (list
             (.o
               identity: 'organization.coverage
               meaning: "Proposed allocations require complete demand coverage."
               premises: '(independent-demand)
               duties: '(DE-O-ARCH DE-O-DOC DE-O-DEC DE-O-TRACE DE-O-REVIEW)
               strength: 'authored-conditional))
    limits: (list
             (.o
               identity: 'organization.assertion-limit
               inputs: '(proposals)
               statement: "Structural declarations do not establish capability, causal truth or authority."))
    qualification: 'authored-conditional
    assets: (list catalog-asset)
    capabilities: '(organization-demands)
    method-refs: (map (lambda (key) (method-ref (.ref methods key))) '(reason render))
    methods: OrganizationMethods
    catalog: catalog-value
    mapping: mapping-value
    roles: '(("definitions" "library" "definition")
             ("selection" "profile" "selection")
             ("capture" "scenario" "project")
             ("reasoning" "ascent" "framework")
             ("review" "aitia" "framework")
             ("documentation" "documents" "document")
             ("method-contracts" "library" "definition")
             ("receipt-issuance" "yuanxu" "framework")
             ("project-entry" "project" "composition"))
    owner-kinds: '(("library" "definition")
                   ("profile" "selection")
                   ("scenario" "project")
                   ("ascent" "framework")
                   ("aitia" "framework")
                   ("documents" "document")
                   ("yuanxu" "framework")
                   ("project" "composition"))
    protected: '(("reasoning" "ascent") ("review" "aitia") ("receipt-issuance" "yuanxu"))
    products: '("D01" "D02" "D03" "D04" "D05" "D06" "D07" "D08" "D09" "D10")
    duties: '("DE-O-ARCH" "DE-O-DOC" "DE-O-DEC" "DE-O-TRACE" "DE-O-REVIEW")
    required-capabilities: '("source-load" "capture-origin" "method-validation" "authority")
    ))

(import :clan/poo/object
        (only-in :clan/poo/mop define-type Object Type)
        (only-in :clan/poo/type Record Exactly))
(export ConfigType ScopeType)

(define-type ConfigType (Record purpose: [(Exactly 'source-contract-profiles)]))
(define-type ScopeType
  (.cc (Record config: [ConfigType] config-type: [Type] profiles: [Object])
       'identity 'source-contract-profiles/scope))

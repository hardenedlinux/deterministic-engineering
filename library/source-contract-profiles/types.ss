;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        (only-in :clan/poo/mop define-type Object Type Bool Function)
        (only-in :clan/poo/type Record Symbol)
        (only-in "../source-contracts/types.ss" SourceContractPolicyShape))
(export ConfigType ScopeType)

(define-type
  (LanguageSettings @
   (Record profile: [Symbol]
           timeout: [(.get SourceContractPolicyShape slots timeout type)]))
  sealed: #t)
(define-type
  (LanguageConfig @ (Record enable: [Bool] settings: [LanguageSettings]))
  sealed: #t)
(define-type
  (Languages @ (Record c: [LanguageConfig] cpp: [LanguageConfig]))
  sealed: #t)
(define-type
  (EngineeringProgram @ (Record languages: [Languages]))
  sealed: #t)
(define-type
  (Programs @ (Record deterministic-engineering: [EngineeringProgram]))
  sealed: #t)
(define-type
  (ConfigType @ (Record programs: [Programs]))
  sealed: #t)
(define-type ScopeType
  (.cc
    (Record config: [ConfigType]
            config-type: [Type]
            configure: [(Function (list ConfigType) (list Object))]
            plan-library: [Object]
            profiles: [Object]
            languages: [Object])
    'identity 'source-contract-profiles/scope))

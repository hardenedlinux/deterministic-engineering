;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Sealed Record contracts for threat-model-profiles and languages.quint Config.
(import
  :clan/poo/object
  (only-in :clan/poo/type define-type Object Type Bool Function Record Symbol)
  (only-in "../quint-methods/types.ss" QuintTimeout QuintProfileType QuintPlanType))
(export QuintLanguageSettings QuintLanguageConfig QuintConfigType ScopeType)

(define-type
  (QuintLanguageSettings @
   (Record profile: [Symbol]
           timeout: [QuintTimeout]))
  sealed: #t)

(define-type
  (QuintLanguageConfig @
   (Record enable: [Bool]
           settings: [QuintLanguageSettings]))
  sealed: #t)

(define-type
  (QuintLanguages @
   (Record c: [Object optional: #t]
           cpp: [Object optional: #t]
           quint: [QuintLanguageConfig]))
  sealed: #t)

(define-type
  (QuintEngineeringProgram @ (Record languages: [QuintLanguages]))
  sealed: #t)

(define-type
  (QuintPrograms @ (Record deterministic-engineering: [QuintEngineeringProgram]))
  sealed: #t)

(define-type
  (QuintConfigType @ (Record programs: [QuintPrograms]))
  sealed: #t)

(define-type ScopeType
  (.cc
    (Record config: [QuintConfigType]
            config-type: [Type]
            configure: [(Function (list Object) (list QuintConfigType))]
            methods: [Object]
            profiles: [Object]
            plan-for: [(Function (list Symbol) (list QuintPlanType))])
    'identity 'threat-model-profiles/scope))

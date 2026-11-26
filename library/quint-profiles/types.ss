;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Sealed contracts for the orthogonal 3-axis Quint Profile Namespace
;;; (assurance.*, bound.*, governance.*) and languages.quint Config admission.
(import :clan/poo/object
        (only-in :clan/poo/type
                 define-type Object Type Bool Function Record Symbol List Any)
        (only-in :deterministic-engineering/library/quint-methods/types
                 QuintTimeout QuintProfileType))
(export QuintLanguageSettings
        QuintLanguageConfig
        QuintConfigType
        QuintProfilesScopeType)

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
  (QuintEngineeringProgram @
   (Record languages: [QuintLanguages]))
  sealed: #t)

(define-type
  (QuintPrograms @
   (Record deterministic-engineering: [QuintEngineeringProgram]))
  sealed: #t)

(define-type
  (QuintConfigType @
   (Record programs: [QuintPrograms]))
  sealed: #t)

(define-type QuintProfilesScopeType
  (.cc
    (Record config: [QuintConfigType]
            config-type: [Type]
            configure: [(Function (list Object) (list QuintConfigType))]
            slot-specs: [(List Any)]
            default-slots: [Object]
            stateless-default-slots: [Object]
            governance-floor: [Object]
            assurance: [Object]
            bound: [Object]
            governance: [Object]
            registry: [Object]
            converge: [Any]
            model->profile: [(Function (list Object) (list QuintProfileType))])
    'identity 'quint-profiles/scope))

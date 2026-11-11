;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        (only-in :clan/poo/mop define-type Object Type)
        (only-in :clan/poo/type Record)
        (only-in "../source-contracts/types.ss" SourceContractConfig))
(export ConfigType ScopeType)

(define-type
  (ConfigType @ (Record verification: [SourceContractConfig]))
  sealed: #t)
(define-type ScopeType
  (.cc
    (Record config: [ConfigType]
            config-type: [Type]
            plan-library: [Object]
            profiles: [Object])
    'identity 'source-contract-profiles/scope))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        (only-in :clan/poo/type define-type Record)
        "../../types.ss"
        (only-in "../quint-methods/types.ss" EngineeringDomainModelType))
(export RaftLeaderCommitmentConfigType CatalogConfigContract CatalogScopeContract)

(define-type
  (RaftLeaderCommitmentConfigType @
   (Record entry: [EngineeringDomainModelType]))
  sealed: #t)

(def CatalogConfigContract RaftLeaderCommitmentConfigType)
(def CatalogScopeContract (library-catalog-scope-contract 'consensus-raft-commitment/scope))

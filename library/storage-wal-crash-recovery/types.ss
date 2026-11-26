;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        (only-in :clan/poo/type define-type Record)
        "../../types.ss"
        (only-in "../quint-methods/types.ss" EngineeringDomainModelType))
(export WalCrashRecoveryConfigType CatalogConfigContract CatalogScopeContract)

(define-type
  (WalCrashRecoveryConfigType @
   (Record entry: [EngineeringDomainModelType]))
  sealed: #t)

(def CatalogConfigContract WalCrashRecoveryConfigType)
(def CatalogScopeContract (library-catalog-scope-contract 'storage-wal-crash-recovery/scope))

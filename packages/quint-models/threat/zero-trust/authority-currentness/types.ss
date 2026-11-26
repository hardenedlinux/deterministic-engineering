;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        (only-in :clan/poo/type define-type Record)
        (only-in :deterministic-engineering/types library-catalog-scope-contract)
        (only-in :deterministic-engineering/library/quint-methods/types
                 ThreatDomainModelType))
(export AuthorityCurrentnessConfigType
        CatalogConfigContract
        CatalogScopeContract)

(define-type
  (AuthorityCurrentnessConfigType @
   (Record entry: [ThreatDomainModelType]))
  sealed: #t)

(def CatalogConfigContract AuthorityCurrentnessConfigType)
(def CatalogScopeContract (library-catalog-scope-contract 'authority-currentness/scope))

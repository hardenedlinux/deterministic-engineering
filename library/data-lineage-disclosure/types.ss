;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        (only-in :clan/poo/type define-type Record)
        "../../types.ss"
        (only-in "../quint-methods/types.ss" ThreatDomainModelType))
(export DataLineageDisclosureConfigType CatalogConfigContract CatalogScopeContract)

(define-type
  (DataLineageDisclosureConfigType @
   (Record entry: [ThreatDomainModelType]))
  sealed: #t)

(def CatalogConfigContract DataLineageDisclosureConfigType)
(def CatalogScopeContract (library-catalog-scope-contract 'data-lineage-disclosure/scope))

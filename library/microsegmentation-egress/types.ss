;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        (only-in :clan/poo/type define-type Record)
        "../../types.ss"
        (only-in "../quint-methods/types.ss" ThreatDomainModelType))
(export MicrosegmentationEgressConfigType CatalogConfigContract CatalogScopeContract)

(define-type
  (MicrosegmentationEgressConfigType @
   (Record entry: [ThreatDomainModelType]))
  sealed: #t)

(def CatalogConfigContract MicrosegmentationEgressConfigType)
(def CatalogScopeContract (library-catalog-scope-contract 'microsegmentation-egress/scope))

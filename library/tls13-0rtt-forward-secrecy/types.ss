;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        (only-in :clan/poo/type define-type Record)
        "../../types.ss"
        (only-in "../quint-methods/types.ss" ThreatDomainModelType))
(export Tls13ZeroRttForwardSecrecyConfigType CatalogConfigContract CatalogScopeContract)

(define-type
  (Tls13ZeroRttForwardSecrecyConfigType @
   (Record entry: [ThreatDomainModelType]))
  sealed: #t)

(def CatalogConfigContract Tls13ZeroRttForwardSecrecyConfigType)
(def CatalogScopeContract (library-catalog-scope-contract 'tls13-0rtt-forward-secrecy/scope))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        :deterministic-engineering/types)
(export CatalogConfigContract CatalogScopeContract)
(def CatalogConfigContract LibraryCatalogConfigContract)
(def CatalogScopeContract (library-catalog-scope-contract 'search-engine/scope))

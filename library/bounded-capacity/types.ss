(import :clan/poo/object "../../types.ss")
(export CatalogConfigContract CatalogScopeContract)
(def CatalogConfigContract LibraryCatalogConfigContract)
(def CatalogScopeContract (library-catalog-scope-contract 'bounded-capacity/scope))

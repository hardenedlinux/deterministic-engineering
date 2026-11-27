;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Metamorphic search query algebra, qualifier orthogonality, scope-replace
;;; determinism & clipped tab hit-test fidelity model (SM10).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SearchQueryMetamorphicAlgebraModel)

(.def (SearchQueryMetamorphicAlgebraModel @ ThreatModel.)
  identity: 'engineering.concurrency.search-query-metamorphic-algebra
  family: 'engineering.concurrency.search-query-metamorphic-algebra
  title: "Search Query Metamorphic Algebra, Scope Replacement & Viewport Hit-Test Fidelity"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("Z. Q. Zhou, S. Xiang & T. Y. Chen (IEEE TSE 2016)"
     "Metamorphic Testing for Software Quality Assessment: A Study of Search Engines — relational oracles for search queries.")
    ("T. Y. Chen, F.-C. Kuo, H. Liu, P.-L. Poon, D. Towey, T. H. Tse & Z. Q. Zhou (ACM CSUR 2018)"
     "Metamorphic Testing: A Review of Challenges and Opportunities — monotonicity and invariance properties.")
    ("L. Lampropoulos, M. Hicks & B. C. Pierce (ACM OOPSLA 2019)"
     "Coverage Guided, Property Based Testing (FuzzChick) — combining property oracles with fuzzing feedback.")
    ("H. Goldstein, J. W. Cutler, D. Dickstein, B. C. Pierce & A. Head (IEEE/ACM ICSE 2024)"
     "Property-Based Testing in Practice — stateful and metamorphic properties in production software."))
  quint-module: "concurrency_search_query_metamorphic_algebra"
  quint-file: "SearchQueryMetamorphicAlgebra.qnt"
  domain-dir: "engineering/concurrency/search-query-metamorphic-algebra"
  rules:
  '((conc-search-qual-ortho CONC-SEARCH-QUAL-ORTHO quint)
    (conc-search-scope-replace CONC-SEARCH-SCOPE-REPLACE quint)
    (conc-search-tab-clip CONC-SEARCH-TAB-CLIP quint))
  dependencies:
  '((CONC-SEARCH-QUAL-ORTHO source)
    (CONC-SEARCH-QUAL-ORTHO profile)
    (CONC-SEARCH-QUAL-ORTHO method)
    (CONC-SEARCH-SCOPE-REPLACE source)
    (CONC-SEARCH-SCOPE-REPLACE profile)
    (CONC-SEARCH-SCOPE-REPLACE method)
    (CONC-SEARCH-TAB-CLIP source)
    (CONC-SEARCH-TAB-CLIP profile)
    (CONC-SEARCH-TAB-CLIP method))
  invariant: "Axis qualifiers never leak into literal text matching, interactive scoping replaces any conflicting prior axis rather than being shadowed by last-wins parsing, negation shrinks match sets monotonically, and clipped tabs never register phantom hits."
  limits: "Finite metamorphic algebra abstraction over 2-epoch scope replacement, axis qualifiers, negation monotonicity, and clipped viewport hit-tests; concrete UTF-8 case folding and arbitrary query fuzzing are tested via Go testing.F and Rust proptest.")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Diverse Multi-Hypothesis AI Code Search & Bounded Frontier Exploration:
;;; Anti-Mode-Collapse (MAP-Elites / MMR / DPP), Dead-End Backtracking (SWE-Search / LATS),
;;; Grounded Witness Promotion, and Bounded Dusa Choice Frontier.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SearchDiversityExplorationModel)

(.def (SearchDiversityExplorationModel @ ThreatModel.)
  identity: 'engineering.defense.search-diversity-exploration
  family: 'engineering.defense.search-diversity-exploration
  title: "Diverse Multi-Hypothesis Search Exploration: Anti-Mode-Collapse, Backtracking & Bounded Frontier"
  subdomain: 'quint.engineering.defense
  papers:
  '(("J.-B. Mouret & J. Clune (2015) / DeepMind AlphaEvolve (2025)"
     "MAP-Elites quality-diversity archives and evolutionary multi-island program search countering mode collapse.")
    ("A. Antoniades et al. (ICLR 2025) / A. Zhou et al. (ICML 2024)"
     "SWE-Search and LATS: tree-search exploration with self-feedback, dead-end backtracking, and verified witnesses.")
    ("J. Carbonell & J. Goldstein (SIGIR 1998) / C. Martens et al. (POPL 2025)"
     "Maximal Marginal Relevance (MMR) diversity selection and Dusa finite-choice bounded-frontier search."))
  quint-module: "search_diversity_exploration"
  quint-file: "SearchDiversityExploration.qnt"
  domain-dir: "engineering/defense/search-diversity-exploration"
  rules:
  '((search-diversity-safe DE-SDE-SAFE quint)
    (search-diversity-countermodel DE-SDE-COUNTER quint))
  dependencies:
  '((DE-SDE-SAFE source)
    (DE-SDE-SAFE profile)
    (DE-SDE-SAFE method)
    (DE-SDE-COUNTER source)
    (DE-SDE-COUNTER profile)
    (DE-SDE-COUNTER method))
  invariant: "Search expansion preserves multi-niche diversity against mode collapse, dead-end branches backtrack before further expansion, promoted findings carry verified execution witnesses, and active choice frontiers remain within declared state bounds."
  limits: "Finite 2-niche bounded-frontier abstraction of Quality-Diversity (MAP-Elites / MMR), SWE-Search / LATS dead-end backtracking, grounded witness admission, and Dusa bounded choice branching; full multi-file code graphs and continuous DPP/MMR scoring execute in library/search-engine and Marlin's live Search DSL runtime.")

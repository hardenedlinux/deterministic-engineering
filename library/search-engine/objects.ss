;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned meaning for deterministic neuro-symbolic AI code search;
;;; no external language asset or verifier is loaded here.
(import :clan/poo/object)
(export SearchEngineModel)

(.def SearchEngineModel
  identity: 'search.neuro-symbolic-engine
  family: 'search.neuro-symbolic-engine
  parent: #f
  revision: "1"
  factor-implications: '()
  tiers: '((l0-fast-ram        "Pure-Rust resident RAM trigram/BM25/regex, AST outline, and zero-I/O line reader")
           (l1-relational-ascent "Closed zero-eval Datalog (:gerbil-ascent) over Open EDB with path predicates, impact closure, and niche-diverse sampling")
           (l2-dusa-choice     "Finite-choice logic programming (Dusa POPL 2025) with deduction vs branch provenance and bounded frontier"))
  human-vs-ai-countermodels:
  '((CM01-human-topk-mode-collapse
     "Flat top-K pagination (human visual skimming)"
     "Bounded LLM context collapses onto 1 dominant niche (e.g. 40 rows of new()) without paging"
     "engineering.defense.search-diversity-exploration::stepModeCollapse"
     l1-relational-ascent)
    (CM02-human-iterative-grep-loop
     "Serial terminal ls/find/rg/cat probing"
     "Burns 7+ full-context LLM rounds and retries zero-hit dead ends without backtracking"
     "engineering.defense.search-diversity-exploration::stepDeadEndLoop"
     l1-relational-ascent)
    (CM03-monolithic-tool-and-ungrounded-guess
     "Monolithic human handbook + mental synthesis"
     "Fast models collapse onto text grep and promote ungrounded claims without execution witnesses"
     "engineering.defense.search-diversity-exploration::stepUngroundedPromotion"
     l0-fast-ram)
    (CM04-textual-disambiguation-and-frontier-explosion
     "Manual IDE Go-To-Definition / pure vector RAG"
     "Cannot prove global forbidden constraints; unbounded branching exhausts solver frontier"
     "engineering.defense.search-diversity-exploration::stepFrontierExplosion"
     l2-dusa-choice)
    (CM05-static-cache-and-stale-evidence
     "Unfenced static cache / human working memory"
     "Silently reuses stale structural facts after AST drift, ignores DE01 expansion, or serves poisoned/unpinned KV cache"
     "engineering.defense.search-evidence-chain-integrity::{stepStaleStructuralReuse,stepStaleNegDomainReuse,stepKvCacheContamination,stepPoisonedEvidencePromotion,stepZombieEvidenceCascade}"
     l2-dusa-choice))
  grounded-papers:
  '(("Z. Chen et al. (ACL 2025)" "LocAgent: Graph-guided LLM agents for code localization over directed heterogeneous code graphs.")
    ("S. Ouyang et al. (ICLR 2025)" "RepoGraph: Enhancing AI software engineering with repository-level ego-graph context.")
    ("A. Antoniades et al. (ICLR 2025)" "SWE-Search: Enhancing software agents with Monte Carlo Tree Search, iterative self-feedback, and backtracking.")
    ("Y. Zhang et al. (ISSTA 2024)" "AutoCodeRover: Autonomous program improvement via AST-based structured code search APIs.")
    ("J.-B. Mouret & J. Clune (2015) / DeepMind AlphaEvolve (2025)" "MAP-Elites quality-diversity archives and evolutionary multi-island program search preventing mode collapse.")
    ("A. Zhou et al. (ICML 2024)" "LATS: Language Agent Tree Search unifying reasoning, acting, and planning with reflection and backtracking.")
    ("J. Carbonell & J. Goldstein (SIGIR 1998) / DQO (NeurIPS)" "Maximal Marginal Relevance (MMR) and Determinantal Point Process (DPP) diversity-quality optimization.")
    ("C. Martens, R. Simmons, M. Arntzenius (POPL 2025)" "Dusa: Finite-Choice Logic Programming with deduction vs branch provenance.")
    ("M. Budiu et al. (PVLDB 2023)" "DBSP: Automatic incremental view maintenance for stratified recursive Datalog.")
    ("M. Willsey et al. (PLDI 2023)" "egglog: Unifying Datalog and equality saturation for rewrite-driven analysis.")
    ("T. Green, G. Karvounarakis, V. Tannen (PODS 2007)" "Provenance semirings for algebraic why/how justification tracking."))
  rules: '((search-tier-routing SEARCH-TIER-ROUTE scheme)
           (search-niche-diversity SEARCH-NICHE-DIV scheme)
           (search-evidence-chain SEARCH-EVIDENCE quint)
           (search-diversity-exploration SEARCH-DIV-EXPLORE quint))
  dependencies: '((SEARCH-TIER-ROUTE source) (SEARCH-TIER-ROUTE method)
                  (SEARCH-NICHE-DIV source) (SEARCH-NICHE-DIV method)
                  (SEARCH-EVIDENCE source) (SEARCH-EVIDENCE profile) (SEARCH-EVIDENCE method)
                  (SEARCH-DIV-EXPLORE source) (SEARCH-DIV-EXPLORE profile) (SEARCH-DIV-EXPLORE method))
  invariant: "Every search query routes to the narrowest sound tier, bounded result windows preserve multi-niche diversity against mode collapse, dead-end branches backtrack instead of looping, and promoted evidence carries verifiable structural epoch and witness provenance."
  limits: "Pure Scheme domain contract and deterministic diversity/routing operators; concrete workspace indexing, Open EDB extraction, and live LLM orchestration live in downstream consumers (e.g. Marlin), while stateful safety and adversarial countermodels live in Quint defense models.")

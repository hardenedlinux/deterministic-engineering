;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Interactive search query generation fencing, monotonic cancellation,
;;; identity-anchored selection custody & stale batch preemption model (SM8).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SearchQueryGenerationFencingModel)

(.def (SearchQueryGenerationFencingModel @ ThreatModel.)
  identity: 'engineering.concurrency.search-query-generation-fencing
  family: 'engineering.concurrency.search-query-generation-fencing
  title: "Search Query Generation Fencing, Selection Identity & Stale Preemption"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("J. Dean & L. A. Barroso (CACM 2013)"
     "The Tail at Scale — request cancellation and hedging under interactive fan-out latency.")
    ("M. Kleppmann (2016)"
     "How to do distributed locking — monotonic fencing tokens rejecting out-of-order delayed responses.")
    ("Z. Q. Zhou, S. Xiang & T. Y. Chen (IEEE TSE 2016)"
     "Metamorphic Testing for Software Quality Assessment: A Study of Search Engines — deterministic search consistency under streaming updates."))
  quint-module: "concurrency_search_query_generation_fencing"
  quint-file: "SearchQueryGenerationFencing.qnt"
  domain-dir: "engineering/concurrency/search-query-generation-fencing"
  rules:
  '((conc-search-gen-fence CONC-SEARCH-GEN-FENCE quint)
    (conc-search-sel-anchor CONC-SEARCH-SEL-ANCHOR quint)
    (conc-search-stale-drop CONC-SEARCH-STALE-DROP quint))
  dependencies:
  '((CONC-SEARCH-GEN-FENCE source)
    (CONC-SEARCH-GEN-FENCE profile)
    (CONC-SEARCH-GEN-FENCE method)
    (CONC-SEARCH-SEL-ANCHOR source)
    (CONC-SEARCH-SEL-ANCHOR profile)
    (CONC-SEARCH-SEL-ANCHOR method)
    (CONC-SEARCH-STALE-DROP source)
    (CONC-SEARCH-STALE-DROP profile)
    (CONC-SEARCH-STALE-DROP method))
  invariant: "Interactive search generations cancel monotonically without inversion, drop stale out-of-order batches/DSL responses, anchor selection by candidate identity across async batch arrivals, and prune hidden marks on source filtering."
  limits: "Finite 3-generation, 2-candidate interactive search abstraction; verifies monotonic cancellation, stale batch/DSL rejection, selection identity anchoring, and mark pruning, not ranking relevance scoring.")

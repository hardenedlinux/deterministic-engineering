;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Interactive search query generation fencing, monotonic cancellation,
;;; identity-anchored selection custody & stale batch preemption model (SM8).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SearchQueryGenerationFencingModel
        GenerationInversionCountermodel
        SelectionIdentityJumpCountermodel
        StaleBatchOverwriteCountermodel)

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
  quint-imports: '()
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
  parameters: '()
  state:
  '((activeGen "int" "1")
    (displayedGen "int" "0")
    (visibleCount "int" "0")
    (markedCount "int" "0")
    (staleDrops "int" "0")
    (selectedAnchored "bool" "true")
    (generationInversion "bool" "false")
    (staleApplied "bool" "false"))
  guards:
  '((monotonic-gen-fence false)
    (anchor-selection-id true)
    (epoch-response-fence false))
  transitions:
  '((beginQuery
      (action beginQuery ()
        (if (< (. h activeGen) 3)
          (set-h (activeGen (+ (. h activeGen) 1))
                 (visibleCount 0)
                 (markedCount 0)
                 (selectedAnchored true))
          (keep-h))))
    (dispatchDelayedOlderQuery
      (action dispatchDelayedOlderQuery ()
        (if (and (> (. h activeGen) 1) (< (. h staleDrops) 3))
          (set-h (staleDrops (+ (. h staleDrops) 1))
                 (generationInversion (guard monotonic-gen-fence false true)))
          (keep-h))))
    (applyFreshBatch
      (action applyFreshBatch ()
        (if (< (. h visibleCount) 2)
          (set-h (displayedGen (. h activeGen))
                 (visibleCount (+ (. h visibleCount) 1))
                 (selectedAnchored (if (> (. h visibleCount) 0)
                                     (guard anchor-selection-id true false)
                                     true)))
          (keep-h))))
    (applyStaleBatch
      (action applyStaleBatch ()
        (if (and (> (. h activeGen) 1) (< (. h staleDrops) 3))
          (set-h (staleDrops (+ (. h staleDrops) 1))
                 (staleApplied (guard epoch-response-fence false true)))
          (keep-h))))
    (toggleMark
      (action toggleMark ()
        (if (and (> (. h visibleCount) 0) (< (. h markedCount) (. h visibleCount)))
          (set-h (markedCount (+ (. h markedCount) 1)))
          (keep-h))))
    (filterSource
      (action filterSource ()
        (if (> (. h visibleCount) 0)
          (set-h (visibleCount (- (. h visibleCount) 1))
                 (markedCount (if (> (. h markedCount) (- (. h visibleCount) 1))
                                (- (. h visibleCount) 1)
                                (. h markedCount))))
          (keep-h))))
    (step
      (action step ()
        (any beginQuery dispatchDelayedOlderQuery applyFreshBatch applyStaleBatch toggleMark filterSource))))
  safety:
  '(and (<= (. h displayedGen) (. h activeGen))
        (<= (. h markedCount) (. h visibleCount))
        (. h selectedAnchored)
        (not (. h generationInversion))
        (not (. h staleApplied)))
  traces:
  '((checkFencedSearchSafe
      (action checkFencedSearchSafe ()
        (all (assert (<= (. h displayedGen) (. h activeGen)))
             (assert (<= (. h markedCount) (. h visibleCount)))
             (assert (. h selectedAnchored))
             (assert (> (. h staleDrops) 0))
             (assert safety)
             (keep-h))))
    (checkSearchFenceViolation
      (action checkSearchFenceViolation ()
        (all (assert (or (. h generationInversion) (not (. h selectedAnchored)) (. h staleApplied)))
             (assert (not safety))
             (keep-h))))
    (fencedSearchLifecycleTest
      (run fencedSearchLifecycleTest
        (then init applyFreshBatch toggleMark applyFreshBatch beginQuery dispatchDelayedOlderQuery applyStaleBatch applyFreshBatch filterSource checkFencedSearchSafe)))
    (generationInversionRefutedTest
      (run generationInversionRefutedTest
        (then init beginQuery dispatchDelayedOlderQueryInverted checkSearchFenceViolation)))
    (selectionJumpRefutedTest
      (run selectionJumpRefutedTest
        (then init applyFreshBatch applyFreshBatchUnanchored checkSearchFenceViolation)))
    (staleBatchRefutedTest
      (run staleBatchRefutedTest
        (then init beginQuery applyStaleBatchOverwrite checkSearchFenceViolation))))
  countermodels: (list GenerationInversionCountermodel SelectionIdentityJumpCountermodel StaleBatchOverwriteCountermodel)
  limits: "Finite 3-generation, 2-candidate interactive search abstraction; verifies monotonic cancellation, stale batch/DSL rejection, selection identity anchoring, and mark pruning, not ranking relevance scoring.")

(.def (GenerationInversionCountermodel @ SearchQueryGenerationFencingModel)
  identity: 'engineering.concurrency.search-query-generation-fencing.generation-inversion
  dropped-guard: 'monotonic-gen-fence
  step-action: "stepGenerationInversion"
  derive-from-transition: 'dispatchDelayedOlderQuery
  derive-action-name: 'dispatchDelayedOlderQueryInverted
  expected-itf-predicate: "h.generationInversion == true")

(.def (SelectionIdentityJumpCountermodel @ SearchQueryGenerationFencingModel)
  identity: 'engineering.concurrency.search-query-generation-fencing.selection-jump
  dropped-guard: 'anchor-selection-id
  step-action: "stepSelectionIdentityJump"
  derive-from-transition: 'applyFreshBatch
  derive-action-name: 'applyFreshBatchUnanchored
  expected-itf-predicate: "not(h.selectedAnchored)")

(.def (StaleBatchOverwriteCountermodel @ SearchQueryGenerationFencingModel)
  identity: 'engineering.concurrency.search-query-generation-fencing.stale-overwrite
  dropped-guard: 'epoch-response-fence
  step-action: "stepStaleBatchOverwrite"
  derive-from-transition: 'applyStaleBatch
  derive-action-name: 'applyStaleBatchOverwrite
  expected-itf-predicate: "h.staleApplied == true")

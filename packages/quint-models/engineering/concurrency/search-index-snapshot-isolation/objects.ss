;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Search index cold-start serialization, multi-workspace root isolation,
;;; single-flight leader-cancel follower re-election, and snapshot compaction (SM15).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SearchIndexSnapshotIsolationModel
        SplitBrainColdOpenCountermodel
        CrossWorkspaceContaminationCountermodel
        SingleFlightCascadeFailureCountermodel)

(.def (SearchIndexSnapshotIsolationModel @ ThreatModel.)
  identity: 'engineering.concurrency.search-index-snapshot-isolation
  family: 'engineering.concurrency.search-index-snapshot-isolation
  title: "Search Index Snapshot Isolation, Cold-Open Serialization & Follower Re-Election"
  subdomain: 'quint.engineering.concurrency
  papers:
  '(("J. Gray & A. Reuter (1993)"
     "Transaction Processing: Concepts and Techniques — snapshot isolation prevents readers from observing torn or cross-partition state during incremental compaction.")
    ("M. Stonebraker & L. Rowe (SIGMOD 1986)"
     "The Design of Postgres — generational MVCC snapshots bound tombstone retention once readers release old epochs.")
    ("J. Dean & L. Barroso (CACM 2013)"
     "The Tail at Scale — single-flight coalescing must isolate per-caller cancellation so one cancelled leader does not cascade-fail healthy followers."))
  quint-module: "concurrency_search_index_snapshot_isolation"
  quint-file: "SearchIndexSnapshotIsolation.qnt"
  domain-dir: "engineering/concurrency/search-index-snapshot-isolation"
  quint-imports: '()
  rules:
  '((conc-idx-serialize-cold-open CONC-IDX-SERIALIZE-COLD-OPEN quint)
    (conc-idx-workspace-root-iso CONC-IDX-WORKSPACE-ROOT-ISO quint)
    (conc-idx-follower-reelect CONC-IDX-FOLLOWER-REELECT quint))
  dependencies:
  '((CONC-IDX-SERIALIZE-COLD-OPEN source)
    (CONC-IDX-SERIALIZE-COLD-OPEN profile)
    (CONC-IDX-SERIALIZE-COLD-OPEN method)
    (CONC-IDX-WORKSPACE-ROOT-ISO source)
    (CONC-IDX-WORKSPACE-ROOT-ISO profile)
    (CONC-IDX-WORKSPACE-ROOT-ISO method)
    (CONC-IDX-FOLLOWER-REELECT source)
    (CONC-IDX-FOLLOWER-REELECT profile)
    (CONC-IDX-FOLLOWER-REELECT method))
  invariant: "Concurrent cold-start opens serialize into at most one authoritative index per workspace root (zero split-brain builds), queries against a switched workspace root never return another root's cached snapshot, cancelling a single-flight query leader re-elects a surviving follower with zero cascade failures, and releasing readers allows tombstone compaction to keep pinnedSegments <= activeReaders + 1."
  parameters: '()
  state:
  '((cachedRoot "int" "0")
    (activeIndexesForRoot "int" "0")
    (snapshotGen "int" "1")
    (activeReaders "int" "0")
    (pinnedSegments "int" "1")
    (leaderActive "bool" "false")
    (waitingFollowers "int" "0")
    (splitBrainOpens "int" "0")
    (crossWorkspaceHits "int" "0")
    (cascadeFailures "int" "0"))
  guards:
  '((serialize-cold-open true)
    (verify-workspace-root true)
    (reelect-on-leader-cancel true))
  transitions:
  '((coldOpenRoot1
      (action coldOpenRoot1 ()
        (if (= (. h cachedRoot) 0)
          (if (guard serialize-cold-open true false)
            (set-h (cachedRoot 1)
                   (activeIndexesForRoot 1)
                   (pinnedSegments 1))
            (set-h (cachedRoot 1)
                   (activeIndexesForRoot (+ (. h activeIndexesForRoot) 2))
                   (splitBrainOpens (+ (. h splitBrainOpens) 1))))
          (keep-h))))
    (queryRoot2
      (action queryRoot2 ()
        (if (= (. h cachedRoot) 1)
          (if (guard verify-workspace-root true false)
            (set-h (cachedRoot 2)
                   (activeIndexesForRoot 1)
                   (snapshotGen (+ (. h snapshotGen) 1)))
            (set-h (crossWorkspaceHits (+ (. h crossWorkspaceHits) 1))))
          (keep-h))))
    (startSingleFlightQuery
      (action startSingleFlightQuery ()
        (if (and (> (. h cachedRoot) 0) (not (. h leaderActive)))
          (set-h (leaderActive true)
                 (waitingFollowers 1)
                 (activeReaders (+ (. h activeReaders) 1))
                 (pinnedSegments (+ (. h activeReaders) 1)))
          (keep-h))))
    (cancelLeaderReelect
      (action cancelLeaderReelect ()
        (if (and (. h leaderActive) (> (. h waitingFollowers) 0))
          (if (guard reelect-on-leader-cancel true false)
            (set-h (leaderActive true)
                   (waitingFollowers (- (. h waitingFollowers) 1)))
            (set-h (leaderActive false)
                   (waitingFollowers 0)
                   (cascadeFailures (+ (. h cascadeFailures) 1))))
          (keep-h))))
    (finishQueryReleaseReader
      (action finishQueryReleaseReader ()
        (if (. h leaderActive)
          (set-h (leaderActive false)
                 (waitingFollowers 0)
                 (activeReaders (if (> (. h activeReaders) 0) (- (. h activeReaders) 1) 0))
                 (pinnedSegments (if (> (. h activeReaders) 0) (. h activeReaders) 1)))
          (keep-h))))
    (publishAndCompactSnapshot
      (action publishAndCompactSnapshot ()
        (if (> (. h cachedRoot) 0)
          (set-h (snapshotGen (+ (. h snapshotGen) 1))
                 (pinnedSegments (+ (. h activeReaders) 1)))
          (keep-h))))
    (step
      (action step ()
        (any coldOpenRoot1
             queryRoot2
             startSingleFlightQuery
             cancelLeaderReelect
             finishQueryReleaseReader
             publishAndCompactSnapshot))))
  safety:
  '(and (<= (. h activeIndexesForRoot) 1)
        (= (. h splitBrainOpens) 0)
        (= (. h crossWorkspaceHits) 0)
        (= (. h cascadeFailures) 0)
        (<= (. h pinnedSegments) (+ (. h activeReaders) 1))
        (>= (. h snapshotGen) 1))
  traces:
  '((checkSnapshotSafe
      (action checkSnapshotSafe ()
        (all (assert (= (. h cachedRoot) 2))
             (assert (= (. h activeIndexesForRoot) 1))
             (assert (= (. h splitBrainOpens) 0))
             (assert (= (. h crossWorkspaceHits) 0))
             (assert (= (. h cascadeFailures) 0))
             (assert (<= (. h pinnedSegments) (+ (. h activeReaders) 1)))
             (assert safety)
             (keep-h))))
    (checkSnapshotViolated
      (action checkSnapshotViolated ()
        (all (assert (or (> (. h splitBrainOpens) 0)
                         (> (. h crossWorkspaceHits) 0)
                         (> (. h cascadeFailures) 0)
                         (> (. h activeIndexesForRoot) 1)))
             (assert (not safety))
             (keep-h))))
    (snapshotIsolationSafeTest
      (run snapshotIsolationSafeTest
        (then init
              coldOpenRoot1
              startSingleFlightQuery
              cancelLeaderReelect
              finishQueryReleaseReader
              publishAndCompactSnapshot
              queryRoot2
              checkSnapshotSafe)))
    (splitBrainColdOpenRefutedTest
      (run splitBrainColdOpenRefutedTest
        (then init coldOpenRoot1SplitBrain checkSnapshotViolated)))
    (crossWorkspaceContaminationRefutedTest
      (run crossWorkspaceContaminationRefutedTest
        (then init coldOpenRoot1 queryRoot2Contaminated checkSnapshotViolated)))
    (singleFlightCascadeRefutedTest
      (run singleFlightCascadeRefutedTest
        (then init coldOpenRoot1 startSingleFlightQuery cancelLeaderCascade checkSnapshotViolated))))
  countermodels:
  (list SplitBrainColdOpenCountermodel
        CrossWorkspaceContaminationCountermodel
        SingleFlightCascadeFailureCountermodel)
  limits: "Finite two-workspace, single-leader/follower snapshot isolation abstraction; verifies cold-open serialization, workspace root isolation, follower re-election under leader cancellation, and bounded reader-pinned segment compaction, not OS filesystem rename durability or Tantivy inverted-index compression internals.")

(.def (SplitBrainColdOpenCountermodel @ SearchIndexSnapshotIsolationModel)
  identity: 'engineering.concurrency.search-index-snapshot-isolation.split-brain-cold-open
  dropped-guard: 'serialize-cold-open
  step-action: "stepSplitBrainColdOpen"
  derive-from-transition: 'coldOpenRoot1
  derive-action-name: 'coldOpenRoot1SplitBrain
  expected-itf-predicate: "h.splitBrainOpens > 0")

(.def (CrossWorkspaceContaminationCountermodel @ SearchIndexSnapshotIsolationModel)
  identity: 'engineering.concurrency.search-index-snapshot-isolation.cross-workspace-contamination
  dropped-guard: 'verify-workspace-root
  step-action: "stepCrossWorkspaceContamination"
  derive-from-transition: 'queryRoot2
  derive-action-name: 'queryRoot2Contaminated
  expected-itf-predicate: "h.crossWorkspaceHits > 0")

(.def (SingleFlightCascadeFailureCountermodel @ SearchIndexSnapshotIsolationModel)
  identity: 'engineering.concurrency.search-index-snapshot-isolation.single-flight-cascade-failure
  dropped-guard: 'reelect-on-leader-cancel
  step-action: "stepSingleFlightCascadeFailure"
  derive-from-transition: 'cancelLeaderReelect
  derive-action-name: 'cancelLeaderCascade
  expected-itf-predicate: "h.cascadeFailures > 0")

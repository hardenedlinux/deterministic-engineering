;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Search index cold-start serialization, multi-workspace root isolation,
;;; single-flight leader-cancel follower re-election, and snapshot compaction (SM15).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SearchIndexSnapshotIsolationModel)

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
  limits: "Finite two-workspace, single-leader/follower snapshot isolation abstraction; verifies cold-open serialization, workspace root isolation, follower re-election under leader cancellation, and bounded reader-pinned segment compaction, not OS filesystem rename durability or Tantivy inverted-index compression internals.")

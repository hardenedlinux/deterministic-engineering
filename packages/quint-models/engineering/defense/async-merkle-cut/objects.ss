;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; R1 + R2 (10.156): Per-Agent Merkle Branches, Chandy-Lamport Asynchronous Marker Cuts,
;;; Explicit Conflict-Preserving Merge, and Hot Policy Co-Evolution Across Suspended Agents.
;;; Proves straggler freedom for fast agents while blocking dropped in-flight cuts,
;;; silent LWW conflict erasure, and stale-policy admission after hot policy upgrades.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export AsyncMerkleCutModel)

(.def (AsyncMerkleCutModel @ ThreatModel.)
  identity: 'engineering.defense.async-merkle-cut
  family: 'engineering.defense.async-merkle-cut
  title: "Asynchronous Merkle Cut, Straggler-Free Branching & Hot Policy Co-Evolution"
  subdomain: 'quint.engineering.defense
  papers:
  '(("K. M. Chandy & L. Lamport (ACM TOCS 1985)"
     "Distributed Snapshots: Determining Global States of Distributed Systems.")
    ("M. Atkinson & R. Morrison (VLDB J. 1995)"
     "Orthogonally Persistent Object Systems (schema and policy co-evolution).")
    ("Deterministic Engineering (10.156 R1 / R2)"
     "Per-agent Merkle branch roots decoupling fast agents from stragglers, explicit Conflict preservation, and M2 hot policy revalidation."))
  quint-module: "async_merkle_cut"
  quint-file: "AsyncMerkleCut.qnt"
  domain-dir: "engineering/defense/async-merkle-cut"
  rules:
  '((async-cut-safe DE-ACUT-SAFE quint)
    (async-cut-countermodel DE-ACUT-COUNTER quint))
  dependencies:
  '((DE-ACUT-SAFE source)
    (DE-ACUT-SAFE profile)
    (DE-ACUT-SAFE method)
    (DE-ACUT-COUNTER source)
    (DE-ACUT-COUNTER profile)
    (DE-ACUT-COUNTER method))
  invariant: "Asynchronous cuts never drop in-flight cross-agent messages (droppedChannelCuts == 0), concurrent branch conflicts are never erased via last-writer-wins (lwwConflictsErased == 0), and hot policy upgrades never admit verdicts computed under a stale policy digest (stalePolicyAdmits == 0)."
  limits: "Finite two-branch asynchronous cut and two-version hot policy co-evolution abstraction; does not model unbounded multi-party vector clocks, Byzantine message forgery, or arbitrary three-way AST merge semantics.")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; R1 + R2 (10.156): Per-Agent Merkle Branches, Chandy-Lamport Asynchronous Marker Cuts,
;;; Explicit Conflict-Preserving Merge, and Hot Policy Co-Evolution Across Suspended Agents.
;;; Proves straggler freedom for fast agents while blocking dropped in-flight cuts,
;;; silent LWW conflict erasure, and stale-policy admission after hot policy upgrades.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export AsyncMerkleCutModel
        DroppedInFlightCutCountermodel
        SilentLwwConflictMergeCountermodel
        StalePolicyHotUpgradeCountermodel)

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
  verify-depth: 10
  countermodel-depth: 6
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
  parameters: '()
  state:
  '((fastCommits "int" "0")
    (slowBlocked "bool" "false")
    (inFlightMsg "bool" "false")
    (channelDrained "bool" "true")
    (branchConflict "bool" "false")
    (activePolicyVer "int" "1")
    (verdictPolicyVer "int" "1")
    (cutConsistent "bool" "true")
    (droppedChannelCuts "int" "0")
    (lwwConflictsErased "int" "0")
    (stalePolicyAdmits "int" "0"))
  guards:
  '((require-channel-drained-for-cut (. h channelDrained))
    (forbid-lww-conflict-merge (not (. h branchConflict)))
    (require-current-policy-digest (= (. h verdictPolicyVer) (. h activePolicyVer))))
  transitions:
  '((blockSlowAgent
      (action blockSlowAgent ()
        (if (not (. h slowBlocked))
          (set-h (slowBlocked #t))
          (keep-h))))
    (fastAgentLocalCommit
      (action fastAgentLocalCommit ()
        (if (< (. h fastCommits) 3)
          (set-h (fastCommits (+ (. h fastCommits) 1)))
          (keep-h))))
    (sendCrossAgentHandoff
      (action sendCrossAgentHandoff ()
        (if (not (. h inFlightMsg))
          (set-h (inFlightMsg #t)
                 (channelDrained #f))
          (keep-h))))
    (captureChannelMessage
      (action captureChannelMessage ()
        (if (and (. h inFlightMsg) (not (. h channelDrained)))
          (set-h (inFlightMsg #f)
                 (channelDrained #t))
          (keep-h))))
    (introduceBranchConflict
      (action introduceBranchConflict ()
        (if (not (. h branchConflict))
          (set-h (branchConflict #t))
          (keep-h))))
    (resolveConflictExplicitly
      (action resolveConflictExplicitly ()
        (if (. h branchConflict)
          (set-h (branchConflict #f))
          (keep-h))))
    (hotUpgradePolicy
      (action hotUpgradePolicy ()
        (if (= (. h activePolicyVer) 1)
          (set-h (activePolicyVer 2))
          (keep-h))))
    (revalidateUnderActivePolicy
      (action revalidateUnderActivePolicy ()
        (if (< (. h verdictPolicyVer) (. h activePolicyVer))
          (set-h (verdictPolicyVer (. h activePolicyVer)))
          (keep-h))))
    (sealAsyncCut
      (action sealAsyncCut ()
        (if (guard require-channel-drained-for-cut (. h channelDrained))
          (set-h (droppedChannelCuts
                   (if (. h channelDrained)
                     (. h droppedChannelCuts)
                     (+ (. h droppedChannelCuts) 1))))
          (keep-h))))
    (mergeBranches
      (action mergeBranches ()
        (if (guard forbid-lww-conflict-merge (not (. h branchConflict)))
          (set-h (lwwConflictsErased
                   (if (. h branchConflict)
                     (+ (. h lwwConflictsErased) 1)
                     (. h lwwConflictsErased))))
          (keep-h))))
    (admitSuspendedVerdict
      (action admitSuspendedVerdict ()
        (if (guard require-current-policy-digest (= (. h verdictPolicyVer) (. h activePolicyVer)))
          (set-h (stalePolicyAdmits
                   (if (= (. h verdictPolicyVer) (. h activePolicyVer))
                     (. h stalePolicyAdmits)
                     (+ (. h stalePolicyAdmits) 1))))
          (keep-h))))
    (step
      (action step ()
        (any blockSlowAgent fastAgentLocalCommit sendCrossAgentHandoff captureChannelMessage
             introduceBranchConflict resolveConflictExplicitly hotUpgradePolicy
             revalidateUnderActivePolicy sealAsyncCut mergeBranches admitSuspendedVerdict))))
  safety:
  '(and (. h cutConsistent)
        (= (. h droppedChannelCuts) 0)
        (= (. h lwwConflictsErased) 0)
        (= (. h stalePolicyAdmits) 0))
  traces:
  '((stragglerFreeCommitAndSafeCutTest
      (run stragglerFreeCommitAndSafeCutTest
        (then init blockSlowAgent fastAgentLocalCommit fastAgentLocalCommit
              sendCrossAgentHandoff captureChannelMessage sealAsyncCut
              hotUpgradePolicy revalidateUnderActivePolicy admitSuspendedVerdict
              (all (assert safety)
                   (assert (. h slowBlocked))
                   (assert (= (. h fastCommits) 2))
                   (assert (= (. h verdictPolicyVer) 2))
                   (keep-h)))))
    (droppedChannelCutViolatesSafetyTest
      (run droppedChannelCutViolatesSafetyTest
        (then init sendCrossAgentHandoff sealAsyncCutDropChannel
              (all (assert (not safety))
                   (assert (> (. h droppedChannelCuts) 0))
                   (keep-h)))))
    (silentLwwConflictViolatesSafetyTest
      (run silentLwwConflictViolatesSafetyTest
        (then init introduceBranchConflict mergeBranchesLww
              (all (assert (not safety))
                   (assert (> (. h lwwConflictsErased) 0))
                   (keep-h)))))
    (stalePolicyAdmitViolatesSafetyTest
      (run stalePolicyAdmitViolatesSafetyTest
        (then init hotUpgradePolicy admitStalePolicyVerdict
              (all (assert (not safety))
                   (assert (> (. h stalePolicyAdmits) 0))
                   (keep-h))))))
  countermodels:
  (list DroppedInFlightCutCountermodel
        SilentLwwConflictMergeCountermodel
        StalePolicyHotUpgradeCountermodel)
  limits: "Finite two-branch asynchronous cut and two-version hot policy co-evolution abstraction; does not model unbounded multi-party vector clocks, Byzantine message forgery, or arbitrary three-way AST merge semantics.")

(.def (DroppedInFlightCutCountermodel @ AsyncMerkleCutModel)
  identity: 'engineering.defense.async-merkle-cut.dropped-channel
  dropped-guard: 'require-channel-drained-for-cut
  step-action: "stepDropChannel"
  derive-from-transition: 'sealAsyncCut
  derive-action-name: 'sealAsyncCutDropChannel
  expected-itf-predicate: "h.droppedChannelCuts > 0")

(.def (SilentLwwConflictMergeCountermodel @ AsyncMerkleCutModel)
  identity: 'engineering.defense.async-merkle-cut.lww-conflict
  dropped-guard: 'forbid-lww-conflict-merge
  step-action: "stepLwwMerge"
  derive-from-transition: 'mergeBranches
  derive-action-name: 'mergeBranchesLww
  expected-itf-predicate: "h.lwwConflictsErased > 0")

(.def (StalePolicyHotUpgradeCountermodel @ AsyncMerkleCutModel)
  identity: 'engineering.defense.async-merkle-cut.stale-policy
  dropped-guard: 'require-current-policy-digest
  step-action: "stepStalePolicy"
  derive-from-transition: 'admitSuspendedVerdict
  derive-action-name: 'admitStalePolicyVerdict
  expected-itf-predicate: "h.stalePolicyAdmits > 0")

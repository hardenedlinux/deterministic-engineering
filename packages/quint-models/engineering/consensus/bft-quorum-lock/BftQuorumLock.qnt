// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.consensus.bft-quorum-lock
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel bft-quorum-threshold step=stepSubQuorumCommit max-steps=9 itf="h.committed1 == true and h.committed2 == true"
// @countermodel bft-lock-respect step=stepIgnoreLock max-steps=9 itf="h.committed1 == true and h.committed2 == true"
// @countermodel bft-commit-requires-lock step=stepMissingLockOnPreCommit max-steps=9 itf="h.committed1 == true and h.committed2 == true"
// @countermodel bft-monotonic-view step=stepStaleViewPreCommit max-steps=9 itf="h.committed1 == true and h.committed2 == true"
// Limits: Finite 4-replica (3 honest + 1 equivocating Byzantine, n=3f+1) 2-view BFT quorum-intersection, view-monotonicity, and lock-respect abstraction; does not model partial-synchrony liveness, Pacemaker GST timeouts, or BLS threshold signature aggregation.
module consensus_bft_quorum_lock {
  type State = { r1Prep1: int, r1Prep2: int, r1Prep3: int, r1Pc1: int, r1Pc2: int, r1Pc3: int, lock1: int, lock2: int, lock3: int, r2Prep1: int, r2Prep2: int, r2Prep3: int, committed1: bool, committed2: bool }
  var h: State
  action init = h' = { r1Prep1: 0, r1Prep2: 0, r1Prep3: 0, r1Pc1: 0, r1Pc2: 0, r1Pc3: 0, lock1: 0, lock2: 0, lock3: 0, r2Prep1: 0, r2Prep2: 0, r2Prep3: 0, committed1: false, committed2: false }
  val r1PrepCount1 = (((if (h.r1Prep1 == 1) 1 else 0) + (if (h.r1Prep2 == 1) 1 else 0)) + (if (h.r1Prep3 == 1) 1 else 0))
  val r1PrepCount2 = (((if (h.r1Prep1 == 2) 1 else 0) + (if (h.r1Prep2 == 2) 1 else 0)) + (if (h.r1Prep3 == 2) 1 else 0))
  val r1PcCount1 = (((if (h.r1Pc1 == 1) 1 else 0) + (if (h.r1Pc2 == 1) 1 else 0)) + (if (h.r1Pc3 == 1) 1 else 0))
  val r1PcCount2 = (((if (h.r1Pc1 == 2) 1 else 0) + (if (h.r1Pc2 == 2) 1 else 0)) + (if (h.r1Pc3 == 2) 1 else 0))
  val r2PrepCount1 = (((if (h.r2Prep1 == 1) 1 else 0) + (if (h.r2Prep2 == 1) 1 else 0)) + (if (h.r2Prep3 == 1) 1 else 0))
  val r2PrepCount2 = (((if (h.r2Prep1 == 2) 1 else 0) + (if (h.r2Prep2 == 2) 1 else 0)) + (if (h.r2Prep3 == 2) 1 else 0))
  action r1PrepareAs(node: int, v: int): bool = if (((v == 1 or v == 2) and (if (node == 1) h.r1Prep1 else if (node == 2) h.r1Prep2 else h.r1Prep3) == 0)) if (node == 1) h' = h.with("r1Prep1", v) else if (node == 2) h' = h.with("r1Prep2", v) else h' = h.with("r1Prep3", v) else h' = h
  action r1Prepare = { nondet node = Set(1, 2, 3).oneOf()
    nondet v = Set(1, 2).oneOf()
    r1PrepareAs(node, v) }
  action r1PreCommitAs(node: int, v: int): bool = if (((v == 1 or v == 2) and (if (node == 1) h.r1Pc1 else if (node == 2) h.r1Pc2 else h.r1Pc3) == 0 and (if (node == 1) h.r2Prep1 else if (node == 2) h.r2Prep2 else h.r2Prep3) == 0 and ((if (v == 1) r1PrepCount1 else r1PrepCount2) + 1) >= 3)) if (node == 1) h' = h.with("r1Pc1", v).with("lock1", v) else if (node == 2) h' = h.with("r1Pc2", v).with("lock2", v) else h' = h.with("r1Pc3", v).with("lock3", v) else h' = h
  action r1PreCommit = { nondet node = Set(1, 2, 3).oneOf()
    nondet v = Set(1, 2).oneOf()
    r1PreCommitAs(node, v) }
  action r1CommitAs(v: int): bool = if (((v == 1 or v == 2) and ((if (v == 1) r1PcCount1 else r1PcCount2) + 1) >= 3)) if (v == 1) h' = h.with("committed1", true) else h' = h.with("committed2", true) else h' = h
  action r1Commit = { nondet v = Set(1, 2).oneOf()
    r1CommitAs(v) }
  action r2PrepareAs(node: int, v: int): bool = if (((v == 1 or v == 2) and (if (node == 1) h.r2Prep1 else if (node == 2) h.r2Prep2 else h.r2Prep3) == 0 and ((if (node == 1) h.lock1 else if (node == 2) h.lock2 else h.lock3) == 0 or (if (node == 1) h.lock1 else if (node == 2) h.lock2 else h.lock3) == v))) if (node == 1) h' = h.with("r2Prep1", v) else if (node == 2) h' = h.with("r2Prep2", v) else h' = h.with("r2Prep3", v) else h' = h
  action r2Prepare = { nondet node = Set(1, 2, 3).oneOf()
    nondet v = Set(1, 2).oneOf()
    r2PrepareAs(node, v) }
  action r2CommitAs(v: int): bool = if (((v == 1 or v == 2) and ((if (v == 1) r2PrepCount1 else r2PrepCount2) + 1) >= 3)) if (v == 1) h' = h.with("committed1", true) else h' = h.with("committed2", true) else h' = h
  action r2Commit = { nondet v = Set(1, 2).oneOf()
    r2CommitAs(v) }
  action step = any { r1Prepare, r1PreCommit, r1Commit, r2Prepare, r2Commit }
  val safety = not((h.committed1 and h.committed2))
  // Countermodel engineering.consensus.bft-quorum-lock.sub-quorum-commit (dropped guard: bft-quorum-threshold)
  action r2CommitSubQuorum(v: int): bool = if (((v == 1 or v == 2) and ((if (v == 1) r2PrepCount1 else r2PrepCount2) + 1) >= 2)) if (v == 1) h' = h.with("committed1", true) else h' = h.with("committed2", true) else h' = h
  action stepSubQuorumCommit = any { step, { nondet v = Set(1, 2).oneOf()
    r2CommitSubQuorum(v) } }
  // Countermodel engineering.consensus.bft-quorum-lock.ignore-lock (dropped guard: bft-lock-respect)
  action r2PrepareIgnoreLock(node: int, v: int): bool = if (((v == 1 or v == 2) and (if (node == 1) h.r2Prep1 else if (node == 2) h.r2Prep2 else h.r2Prep3) == 0 and true)) if (node == 1) h' = h.with("r2Prep1", v) else if (node == 2) h' = h.with("r2Prep2", v) else h' = h.with("r2Prep3", v) else h' = h
  action stepIgnoreLock = any { step, { nondet node = Set(1, 2, 3).oneOf()
    nondet v = Set(1, 2).oneOf()
    r2PrepareIgnoreLock(node, v) } }
  // Countermodel engineering.consensus.bft-quorum-lock.missing-lock-on-precommit (dropped guard: bft-commit-requires-lock)
  action r1PreCommitNoLock(node: int, v: int): bool = if (((v == 1 or v == 2) and (if (node == 1) h.r1Pc1 else if (node == 2) h.r1Pc2 else h.r1Pc3) == 0 and (if (node == 1) h.r2Prep1 else if (node == 2) h.r2Prep2 else h.r2Prep3) == 0 and ((if (v == 1) r1PrepCount1 else r1PrepCount2) + 1) >= 3)) if (node == 1) h' = h.with("r1Pc1", v).with("lock1", 0) else if (node == 2) h' = h.with("r1Pc2", v).with("lock2", 0) else h' = h.with("r1Pc3", v).with("lock3", 0) else h' = h
  action stepMissingLockOnPreCommit = any { step, { nondet node = Set(1, 2, 3).oneOf()
    nondet v = Set(1, 2).oneOf()
    r1PreCommitNoLock(node, v) } }
  // Countermodel engineering.consensus.bft-quorum-lock.stale-view-precommit (dropped guard: bft-monotonic-view)
  action r1PreCommitStaleView(node: int, v: int): bool = if (((v == 1 or v == 2) and (if (node == 1) h.r1Pc1 else if (node == 2) h.r1Pc2 else h.r1Pc3) == 0 and true and ((if (v == 1) r1PrepCount1 else r1PrepCount2) + 1) >= 3)) if (node == 1) h' = h.with("r1Pc1", v).with("lock1", v) else if (node == 2) h' = h.with("r1Pc2", v).with("lock2", v) else h' = h.with("r1Pc3", v).with("lock3", v) else h' = h
  action stepStaleViewPreCommit = any { step, { nondet node = Set(1, 2, 3).oneOf()
    nondet v = Set(1, 2).oneOf()
    r1PreCommitStaleView(node, v) } }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run lockedBlockSurvivesViewChangeTest = init.then(r1PrepareAs(1, 1)).then(r1PrepareAs(2, 1)).then(r1PreCommitAs(1, 1)).then(r1PreCommitAs(2, 1)).then(r1CommitAs(1)).then(r2PrepareAs(3, 2)).then(r2PrepareAs(2, 2)).then(r2CommitAs(2)).then(all { assert(h.committed1), assert(not(h.committed2)), assert(safety), h' = h })
  run subQuorumForkCountermodelTest = init.then(r1PrepareAs(1, 1)).then(r1PrepareAs(2, 1)).then(r1PreCommitAs(1, 1)).then(r1PreCommitAs(2, 1)).then(r1CommitAs(1)).then(r2PrepareAs(3, 2)).then(r2CommitSubQuorum(2)).then(checkUnsafe)
  run ignoreLockForkCountermodelTest = init.then(r1PrepareAs(1, 1)).then(r1PrepareAs(2, 1)).then(r1PreCommitAs(1, 1)).then(r1PreCommitAs(2, 1)).then(r1CommitAs(1)).then(r2PrepareAs(3, 2)).then(r2PrepareIgnoreLock(2, 2)).then(r2CommitAs(2)).then(checkUnsafe)
  run missingLockForkCountermodelTest = init.then(r1PrepareAs(1, 1)).then(r1PrepareAs(2, 1)).then(r1PreCommitNoLock(1, 1)).then(r1PreCommitNoLock(2, 1)).then(r1CommitAs(1)).then(r2PrepareAs(2, 2)).then(r2PrepareAs(3, 2)).then(r2CommitAs(2)).then(checkUnsafe)
}

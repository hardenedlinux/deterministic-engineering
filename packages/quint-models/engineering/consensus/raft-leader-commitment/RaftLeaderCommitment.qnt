// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.consensus.raft-leader-commitment
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel current-term-commit-rule step=stepFigure8Commit max-steps=9 itf="h.committed == true and h.leaderId > 0 and ((h.leaderId == 1 and h.n1Val != h.committedVal) or (h.leaderId == 2 and h.n2Val != h.committedVal) or (h.leaderId == 3 and h.n3Val != h.committedVal))"
// @countermodel election-log-up-to-date step=stepStaleLogElection max-steps=9 itf="h.committed == true and h.leaderId > 0 and ((h.leaderId == 1 and h.n1Val != h.committedVal) or (h.leaderId == 2 and h.n2Val != h.committedVal) or (h.leaderId == 3 and h.n3Val != h.committedVal))"
// Limits: Finite 3-node single-slot Raft election and Figure 8 commitment abstraction; does not model multi-index prefix matching, log compaction snapshots, or dynamic membership joint consensus.
module consensus_raft_commitment {
  type State = { currentTerm: int, leaderId: int, n1Term: int, n1Val: int, n2Term: int, n2Val: int, n3Term: int, n3Val: int, committed: bool, committedVal: int }
  var h: State
  action init = h' = { currentTerm: 1, leaderId: 0, n1Term: 0, n1Val: 0, n2Term: 0, n2Val: 0, n3Term: 0, n3Val: 0, committed: false, committedVal: 0 }
  val leaderLogTerm = if (h.leaderId == 1) h.n1Term else if (h.leaderId == 2) h.n2Term else if (h.leaderId == 3) h.n3Term else 0
  val leaderLogVal = if (h.leaderId == 1) h.n1Val else if (h.leaderId == 2) h.n2Val else if (h.leaderId == 3) h.n3Val else 0
  val leaderMatchCount = (((if ((leaderLogTerm > 0 and h.n1Term == leaderLogTerm)) 1 else 0) + (if ((leaderLogTerm > 0 and h.n2Term == leaderLogTerm)) 1 else 0)) + (if ((leaderLogTerm > 0 and h.n3Term == leaderLogTerm)) 1 else 0))
  action electLeaderAs(cand: int, voter: int): bool = if ((h.currentTerm < 5 and cand != voter and cand != h.leaderId and (if (cand == 1) h.n1Term else if (cand == 2) h.n2Term else h.n3Term) >= (if (voter == 1) h.n1Term else if (voter == 2) h.n2Term else h.n3Term))) h' = h.with("currentTerm", (h.currentTerm + 1)).with("leaderId", cand) else h' = h
  action electLeader = { nondet cand = Set(1, 2, 3).oneOf()
    nondet voter = Set(1, 2, 3).oneOf()
    electLeaderAs(cand, voter) }
  action leaderPropose = if ((h.leaderId > 0 and leaderLogTerm == 0)) if (h.leaderId == 1) h' = h.with("n1Term", h.currentTerm).with("n1Val", 1) else if (h.leaderId == 2) h' = h.with("n2Term", h.currentTerm).with("n2Val", 2) else h' = h.with("n3Term", h.currentTerm).with("n3Val", 3) else h' = h
  action leaderReplicateTo(target: int): bool = if ((h.leaderId > 0 and leaderLogTerm > 0 and target != h.leaderId and (if (target == 1) h.n1Term else if (target == 2) h.n2Term else h.n3Term) != leaderLogTerm)) if (target == 1) h' = h.with("n1Term", leaderLogTerm).with("n1Val", leaderLogVal) else if (target == 2) h' = h.with("n2Term", leaderLogTerm).with("n2Val", leaderLogVal) else h' = h.with("n3Term", leaderLogTerm).with("n3Val", leaderLogVal) else h' = h
  action leaderReplicate = { nondet target = Set(1, 2, 3).oneOf()
    leaderReplicateTo(target) }
  action leaderCommit = if ((h.leaderId > 0 and not(h.committed) and leaderMatchCount >= 2 and leaderLogTerm == h.currentTerm)) h' = h.with("committed", true).with("committedVal", leaderLogVal) else h' = h
  action step = any { electLeader, leaderPropose, leaderReplicate, leaderCommit }
  val safety = (not(h.committed) or h.leaderId == 0 or leaderLogVal == h.committedVal)
  // Countermodel engineering.consensus.raft-leader-commitment.figure8-old-term-commit (dropped guard: current-term-commit-rule)
  action leaderCommitOldTerm = if ((h.leaderId > 0 and not(h.committed) and leaderMatchCount >= 2 and true)) h' = h.with("committed", true).with("committedVal", leaderLogVal) else h' = h
  action stepFigure8Commit = any { step, leaderCommitOldTerm }
  // Countermodel engineering.consensus.raft-leader-commitment.stale-log-election (dropped guard: election-log-up-to-date)
  action electLeaderNoLogCheck(cand: int, voter: int): bool = if ((h.currentTerm < 5 and cand != voter and cand != h.leaderId and true)) h' = h.with("currentTerm", (h.currentTerm + 1)).with("leaderId", cand) else h' = h
  action stepStaleLogElection = any { step, { nondet cand = Set(1, 2, 3).oneOf()
    nondet voter = Set(1, 2, 3).oneOf()
    electLeaderNoLogCheck(cand, voter) } }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validCurrentTermCommitTest = init.then(electLeaderAs(1, 2)).then(leaderPropose).then(leaderReplicateTo(2)).then(leaderCommit).then(electLeaderAs(3, 2)).then(all { assert(h.committed), assert(h.leaderId == 1), assert(safety), h' = h })
  run figure8GuardBlocksOldTermCommitTest = init.then(electLeaderAs(1, 2)).then(leaderPropose).then(electLeaderAs(3, 2)).then(leaderPropose).then(electLeaderAs(1, 2)).then(leaderReplicateTo(2)).then(leaderCommit).then(all { assert(not(h.committed)), assert(safety), h' = h })
  run figure8OverwriteCountermodelTest = init.then(electLeaderAs(1, 2)).then(leaderPropose).then(electLeaderAs(3, 2)).then(leaderPropose).then(electLeaderAs(1, 2)).then(leaderReplicateTo(2)).then(leaderCommitOldTerm).then(electLeaderAs(3, 2)).then(checkUnsafe)
  run staleElectionCountermodelTest = init.then(electLeaderAs(1, 2)).then(leaderPropose).then(leaderReplicateTo(2)).then(leaderCommit).then(electLeaderNoLogCheck(3, 2)).then(checkUnsafe)
}

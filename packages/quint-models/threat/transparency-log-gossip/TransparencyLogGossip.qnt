// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.transparency-log-gossip
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel log-inclusion-proof step=stepUnloggedArtifact max-steps=6 itf="not(subseteq(h.acceptedArtifacts, h.publicLog))"
// @countermodel sth-consistency-gossip step=stepSplitViewEquivocation max-steps=6 itf="h.logForked == true and contains(h.acceptedArtifacts, 99) and not(contains(h.publicLog, 99))"
// Limits: Finite set-prefix abstraction of Merkle consistency proofs and witness gossip; does not model SHA-256 second-preimage resistance, witness threshold collusion, or network eclipsing.
module transparency_log_gossip {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { publicLog: Set[int], victimViewLog: Set[int], logForked: bool, gossipChecked: bool, acceptedArtifacts: Set[int] }
  var h: State
  action init = h' = { publicLog: Set(1), victimViewLog: Set(1), logForked: false, gossipChecked: true, acceptedArtifacts: Set() }
  action appendHonestRelease = if (not(h.publicLog.contains(2))) h' = h.with("publicLog", h.publicLog.union(Set(2))).with("victimViewLog", if (h.logForked) h.victimViewLog else h.victimViewLog.union(Set(2))) else h' = h
  action logEquivocateSplitView = if (not(h.logForked)) h' = h.with("victimViewLog", h.victimViewLog.union(Set(99))).with("logForked", true).with("gossipChecked", false) else h' = h
  action gossipVerifyConsistency = h' = h.with("gossipChecked", h.victimViewLog.subseteq(h.publicLog))
  action clientAcceptArtifactAs(art: int): bool = if ((h.victimViewLog.contains(art) and (h.gossipChecked and h.victimViewLog.subseteq(h.publicLog)))) h' = h.with("acceptedArtifacts", h.acceptedArtifacts.union(Set(art))) else h' = h
  action clientAcceptArtifact = { nondet art = Set(1, 2, 99).oneOf()
    clientAcceptArtifactAs(art) }
  action step = any { appendHonestRelease, logEquivocateSplitView, gossipVerifyConsistency, clientAcceptArtifact }
  val safety = h.acceptedArtifacts.subseteq(h.publicLog)
  // Countermodel threat.transparency-log-gossip.unlogged-artifact (dropped guard: log-inclusion-proof)
  action clientAcceptNoInclusion(art: int): bool = if ((true and (h.gossipChecked and h.victimViewLog.subseteq(h.publicLog)))) h' = h.with("acceptedArtifacts", h.acceptedArtifacts.union(Set(art))) else h' = h
  action stepUnloggedArtifact = any { step, { nondet art = Set(1, 2, 99).oneOf()
    clientAcceptNoInclusion(art) } }
  // Countermodel threat.transparency-log-gossip.split-view-equivocation (dropped guard: sth-consistency-gossip)
  action clientAcceptNoGossip(art: int): bool = if ((h.victimViewLog.contains(art) and true)) h' = h.with("acceptedArtifacts", h.acceptedArtifacts.union(Set(art))) else h' = h
  action stepSplitViewEquivocation = any { step, { nondet art = Set(1, 2, 99).oneOf()
    clientAcceptNoGossip(art) } }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run honestLoggedArtifactAcceptedTest = init.then(appendHonestRelease).then(gossipVerifyConsistency).then(clientAcceptArtifactAs(2)).then(all { assert(h.acceptedArtifacts.contains(2)), assert(safety), h' = h })
  run splitViewBackdoorRejectedByGossipTest = init.then(logEquivocateSplitView).then(gossipVerifyConsistency).then(clientAcceptArtifactAs(99)).then(all { assert(not(h.acceptedArtifacts.contains(99))), assert(safety), h' = h })
  run unloggedArtifactCountermodelTest = init.then(clientAcceptNoInclusion(99)).then(checkUnsafe)
  run splitViewCountermodelTest = init.then(logEquivocateSplitView).then(clientAcceptNoGossip(99)).then(checkUnsafe)
}

// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.process-tree-reclamation
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel grace-or-exit-barrier step=stepPrematureSigkill max-steps=6 itf="h.prematureKill == true"
// @countermodel waitpid-reaped-before-kill step=stepHttpAckNotQuiescence max-steps=6 itf="h.guardian == 3 and (h.c1 == 1 or h.c2 == 1)"
// @countermodel kernel-tree-containment step=stepSinglePidKillNoContainment max-steps=6 itf="h.c1 == 4 or h.c2 == 4"
// @countermodel atomic-freeze-or-container step=stepPgidSpawnToctou max-steps=6 itf="h.spawnEscaped == true"
// @countermodel not-yet-reaped step=stepPidReuseDoubleKill max-steps=6 itf="h.postReapSignal == true"
// Limits: Finite 2-grandchild 3-tier process tree abstraction; OS kernel scheduling, cgroup v2 / Darwin kqueue implementation fidelity, and arbitrary-depth tree induction are discharged separately by LeanPoo Core.Containment and native SIGKILL Leak Oracles.
module concurrency_process_tree_reclamation {
  type State = { guardian: int, supervisor: int, c1: int, c2: int, graceExpired: bool, containerFrozen: bool, containerKilled: bool, prematureKill: bool, postReapSignal: bool, spawnEscaped: bool }
  var h: State
  action init = h' = { guardian: 0, supervisor: 0, c1: 0, c2: 0, graceExpired: false, containerFrozen: false, containerKilled: false, prematureKill: false, postReapSignal: false, spawnEscaped: false }
  val descendantsQuiescent = ((h.c1 == 0 or h.c1 == 3) and (h.c2 == 0 or h.c2 == 3))
  action spawnC1 = if ((h.supervisor == 0 and h.c1 == 0 and not(h.containerFrozen) and not(h.containerKilled))) h' = h.with("c1", 1) else h' = h
  action spawnC2 = if ((h.c2 == 0 and h.supervisor < 3 and (not(h.containerFrozen) and not(h.containerKilled)))) h' = h.with("c2", 1).with("spawnEscaped", (h.spawnEscaped or h.containerFrozen or h.containerKilled)) else h' = h
  action sendShutdown = if (h.guardian == 0) h' = h.with("guardian", 1) else h' = h
  action supervisorHttpAck = if ((h.guardian == 1 and h.supervisor == 0)) h' = h.with("supervisor", 1) else h' = h
  action supervisorBeginDrain = if ((h.guardian == 1 and (h.supervisor == 0 or h.supervisor == 1))) h' = h.with("supervisor", 2).with("c1", if (h.c1 == 1) 2 else h.c1).with("c2", if (h.c2 == 1) 2 else h.c2) else h' = h
  action childC1Exit = if ((h.c1 == 1 or h.c1 == 2)) h' = h.with("c1", 3) else h' = h
  action childC2Exit = if ((h.c2 == 1 or h.c2 == 2)) h' = h.with("c2", 3) else h' = h
  action supervisorCleanExit = if ((h.supervisor == 2 and descendantsQuiescent)) h' = h.with("supervisor", 3) else h' = h
  action supervisorHang = if ((h.guardian == 1 and h.supervisor < 3)) h' = h.with("supervisor", 5) else h' = h
  action expireGraceTimer = if ((h.guardian == 1 and not(h.graceExpired))) h' = h.with("graceExpired", true) else h' = h
  action freezeContainer = if ((h.guardian == 1 and (h.graceExpired or h.supervisor == 5) and not(h.containerFrozen))) h' = h.with("containerFrozen", true) else h' = h
  action escalateKill = if ((h.guardian == 1 and (h.graceExpired or h.supervisor == 5))) h' = h.with("guardian", 2).with("supervisor", 4).with("containerFrozen", true).with("containerKilled", true).with("c1", if (true) if ((h.c1 == 1 or h.c1 == 2)) 3 else h.c1 else if ((h.c1 == 1 or h.c1 == 2)) 4 else h.c1).with("c2", if (true) if ((h.c2 == 1 or h.c2 == 2)) 3 else h.c2 else if ((h.c2 == 1 or h.c2 == 2)) 4 else h.c2).with("prematureKill", (h.prematureKill or (not(h.graceExpired) and h.supervisor != 5))) else h' = h
  action reapAfterShutdown = if ((h.guardian == 1 and (h.supervisor == 3 and descendantsQuiescent))) h' = h.with("guardian", 3) else h' = h
  action reapAfterKill = if ((h.guardian == 2 and h.containerKilled and descendantsQuiescent)) h' = h.with("guardian", 3) else h' = h
  action signalSupervisor = if (((h.guardian == 1 or h.guardian == 3) and h.guardian < 3)) h' = h.with("postReapSignal", (h.postReapSignal or h.guardian == 3)) else h' = h
  action step = any { spawnC1, spawnC2, sendShutdown, supervisorHttpAck, supervisorBeginDrain, childC1Exit, childC2Exit, supervisorCleanExit, supervisorHang, expireGraceTimer, freezeContainer, escalateKill, reapAfterShutdown, reapAfterKill, signalSupervisor }
  val safety = (not(h.prematureKill) and not(h.postReapSignal) and not(h.spawnEscaped) and h.c1 != 4 and h.c2 != 4 and (h.guardian != 3 or descendantsQuiescent))
  // Countermodel engineering.concurrency.process-tree-reclamation.premature-sigkill (dropped guard: grace-or-exit-barrier)
  action escalateKillPremature = if ((h.guardian == 1 and true)) h' = h.with("guardian", 2).with("supervisor", 4).with("containerFrozen", true).with("containerKilled", true).with("c1", if (true) if ((h.c1 == 1 or h.c1 == 2)) 3 else h.c1 else if ((h.c1 == 1 or h.c1 == 2)) 4 else h.c1).with("c2", if (true) if ((h.c2 == 1 or h.c2 == 2)) 3 else h.c2 else if ((h.c2 == 1 or h.c2 == 2)) 4 else h.c2).with("prematureKill", (h.prematureKill or (not(h.graceExpired) and h.supervisor != 5))) else h' = h
  action stepPrematureSigkill = any { step, escalateKillPremature }
  // Countermodel engineering.concurrency.process-tree-reclamation.http-ack-not-quiescence (dropped guard: waitpid-reaped-before-kill)
  action reapAfterHttpAckUnchecked = if ((h.guardian == 1 and true)) h' = h.with("guardian", 3) else h' = h
  action stepHttpAckNotQuiescence = any { step, reapAfterHttpAckUnchecked }
  // Countermodel engineering.concurrency.process-tree-reclamation.single-pid-kill-no-containment (dropped guard: kernel-tree-containment)
  action escalateKillSinglePid = if ((h.guardian == 1 and (h.graceExpired or h.supervisor == 5))) h' = h.with("guardian", 2).with("supervisor", 4).with("containerFrozen", true).with("containerKilled", false).with("c1", if (false) if ((h.c1 == 1 or h.c1 == 2)) 3 else h.c1 else if ((h.c1 == 1 or h.c1 == 2)) 4 else h.c1).with("c2", if (false) if ((h.c2 == 1 or h.c2 == 2)) 3 else h.c2 else if ((h.c2 == 1 or h.c2 == 2)) 4 else h.c2).with("prematureKill", (h.prematureKill or (not(h.graceExpired) and h.supervisor != 5))) else h' = h
  action stepSinglePidKillNoContainment = any { step, escalateKillSinglePid }
  // Countermodel engineering.concurrency.process-tree-reclamation.pgid-spawn-toctou (dropped guard: atomic-freeze-or-container)
  action spawnC2Unfrozen = if ((h.c2 == 0 and h.supervisor < 3 and true)) h' = h.with("c2", 1).with("spawnEscaped", (h.spawnEscaped or h.containerFrozen or h.containerKilled)) else h' = h
  action stepPgidSpawnToctou = any { step, spawnC2Unfrozen }
  // Countermodel engineering.concurrency.process-tree-reclamation.pid-reuse-double-kill (dropped guard: not-yet-reaped)
  action signalSupervisorPostReap = if (((h.guardian == 1 or h.guardian == 3) and true)) h' = h.with("postReapSignal", (h.postReapSignal or h.guardian == 3)) else h' = h
  action stepPidReuseDoubleKill = any { step, signalSupervisorPostReap }
  run gracefulCleanExitTest = init.then(spawnC1).then(sendShutdown).then(supervisorHttpAck).then(supervisorBeginDrain).then(childC1Exit).then(supervisorCleanExit).then(reapAfterShutdown).then(all { assert(h.guardian == 3), assert(h.c1 == 3), assert(safety), h' = h })
  run hungSupervisorEscalationTest = init.then(spawnC1).then(sendShutdown).then(supervisorHang).then(expireGraceTimer).then(freezeContainer).then(escalateKill).then(reapAfterKill).then(all { assert(h.guardian == 3), assert(h.containerKilled), assert(h.c1 == 3), assert(safety), h' = h })
  run prematureSigkillCounterTest = init.then(spawnC1).then(sendShutdown).then(escalateKillPremature).then(all { assert(h.prematureKill), assert(not(safety)), h' = h })
  run singlePidOrphanCounterTest = init.then(spawnC1).then(sendShutdown).then(expireGraceTimer).then(escalateKillSinglePid).then(all { assert(h.c1 == 4), assert(not(safety)), h' = h })
}

// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.gc.safepoint-handshake
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel mutator-safepoint-ack step=stepSkipHandshake max-steps=6 itf="h.phase == 2 and (not(h.m1Barrier) or not(h.m2Barrier))"
// Limits: Finite 2-mutator safepoint handshake abstraction; does not model OS thread preemption, page-fault polling, or stack scanning.
module gc_safepoint_handshake {
  type State = { phase: int, m1Barrier: bool, m2Barrier: bool, unbarrieredWrite: bool }
  var h: State
  action init = h' = { phase: 0, m1Barrier: false, m2Barrier: false, unbarrieredWrite: false }
  action requestSyncMark = if (h.phase == 0)
    h' = h.with("phase", 1)
    else h' = h
  action m1AckSafepoint = if (h.phase == 1 and not(h.m1Barrier))
    h' = h.with("m1Barrier", true)
    else h' = h
  action m2AckSafepoint = if (h.phase == 1 and not(h.m2Barrier))
    h' = h.with("m2Barrier", true)
    else h' = h
  action enterMark = if (h.phase == 1 and h.m1Barrier and h.m2Barrier)
    h' = h.with("phase", 2)
    else h' = h
  action m1Mutate = h' = h.with("unbarrieredWrite", h.unbarrieredWrite or (h.phase == 2 and not(h.m1Barrier)))
  action m2Mutate = h' = h.with("unbarrieredWrite", h.unbarrieredWrite or (h.phase == 2 and not(h.m2Barrier)))
  action enterSweep = if (h.phase == 2)
    h' = h.with("phase", 3)
    else h' = h
  action finishCycle = if (h.phase == 3)
    h' = h.with("phase", 0).with("m1Barrier", false).with("m2Barrier", false)
    else h' = h
  action step = any { requestSyncMark, m1AckSafepoint, m2AckSafepoint, enterMark, m1Mutate, m2Mutate, enterSweep, finishCycle }
  val safety = not(h.unbarrieredWrite) and (h.phase != 2 or (h.m1Barrier and h.m2Barrier))
  // Countermodel engineering.gc.safepoint-handshake.skip-handshake (dropped guard: mutator-safepoint-ack)
  action enterMarkNoHandshake = if (h.phase == 1)
    h' = h.with("phase", 2)
    else h' = h
  action stepSkipHandshake = any { step, enterMarkNoHandshake }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run fullHandshakeCycleTest = init.then(requestSyncMark).then(m1AckSafepoint).then(m2AckSafepoint).then(enterMark).then(m1Mutate).then(m2Mutate).then(enterSweep).then(finishCycle).then(checkSafe)
  run partialAckBlocksMarkTest = init.then(requestSyncMark).then(m1AckSafepoint).then(enterMark).then(all { assert(h.phase == 1), assert(safety), h' = h })
  run skipHandshakeCountermodelTest = init.then(requestSyncMark).then(m1AckSafepoint).then(enterMarkNoHandshake).then(m2Mutate).then(checkUnsafe)
}

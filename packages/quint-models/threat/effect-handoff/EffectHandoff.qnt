// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.effect-handoff
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12 const="MaxSends=1"
// @countermodel durable-ack step=stepNoDurability max-steps=6 itf="h.sent >= 1 and not(h.durable)"
// Limits: Finite protocol abstraction; trusted bits summarize native interpreters; no cryptography, real CAS, codec correctness or Lean refinement is claimed.
module effect_handoff {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  const MaxSends: int
  type State = { phase: int, epoch: int, planned: int, paused: bool, fresh: bool, credential: bool, bytes: bool, durable: bool, unknown: bool, sent: int }
  var h: State
  action init = h' = { phase: 0, epoch: 0, planned: 0, paused: false, fresh: true, credential: true, bytes: true, durable: false, unknown: false, sent: 0 }
  val current = isCurrent(h.paused, h.fresh, h.credential, h.bytes)
  action prepare = if ((h.phase == 0 and not(h.unknown) and current)) h' = h.with("phase", 1).with("planned", h.epoch) else h' = h
  action commitAs(verified: bool): bool = if ((h.phase == 1 and verified and current and epochCurrent(h.epoch, h.planned))) h' = h.with("phase", 2).with("durable", true).with("unknown", true) else h' = h
  action commit = { nondet verified = Set(false, true).oneOf()
    commitAs(verified) }
  action emit = if (((h.phase == 2 and h.durable) and h.phase != 0 and h.phase != 3 and current and epochCurrent(h.epoch, h.planned) and h.sent < MaxSends)) h' = h.with("phase", 3).with("unknown", true).with("sent", (h.sent + 1)) else h' = h
  action pause = h' = h.with("paused", true)
  action expire = h' = h.with("fresh", false)
  action changeWriter = h' = h.with("epoch", 1)
  action substitute = h' = h.with("bytes", false)
  action revoke = h' = h.with("credential", false)
  action recover = h' = h
  action step = any { prepare, commit, emit, pause, expire, changeWriter, substitute, revoke, recover }
  val safety = (h.sent <= MaxSends and (h.sent == 0 or (h.durable and h.unknown)))
  // Countermodel threat.effect-handoff.no-durability (dropped guard: durable-ack)
  action noDurability = if ((true and h.phase != 0 and h.phase != 3 and current and epochCurrent(h.epoch, h.planned) and h.sent < MaxSends)) h' = h.with("phase", 3).with("unknown", true).with("sent", (h.sent + 1)) else h' = h
  action stepNoDurability = any { step, noDurability }
  action blocked = all { assert(h.sent == 0), assert(safety), h' = h }
  action once = all { assert(h.sent == 1), assert(h.unknown), assert(safety), h' = h }
  action unsafe = all { assert(not(safety)), h' = h }
  run exactHandoffTest = init.then(prepare).then(commitAs(true)).then(emit).then(once)
  run absentAckTest = init.then(prepare).then(commitAs(false)).then(emit).then(blocked)
  run expiredTest = init.then(prepare).then(commitAs(true)).then(expire).then(emit).then(blocked)
  run pausedTest = init.then(prepare).then(pause).then(commitAs(true)).then(emit).then(blocked)
  run writerChangedTest = init.then(prepare).then(commitAs(true)).then(changeWriter).then(emit).then(blocked)
  run substitutedBytesTest = init.then(prepare).then(commitAs(true)).then(substitute).then(emit).then(blocked)
  run revokedCredentialTest = init.then(prepare).then(commitAs(true)).then(revoke).then(emit).then(blocked)
  run lostReplyTest = init.then(prepare).then(commitAs(true)).then(emit).then(recover).then(prepare).then(emit).then(once)
}

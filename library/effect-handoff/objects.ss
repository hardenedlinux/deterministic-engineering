;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned guarded effect handoff model; weakened countermodel is a POO descendant.
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export EffectHandoffModel NoDurabilityCountermodel)

(.def (EffectHandoffModel @ AuthorityCurrentnessModel)
  identity: 'threat.effect-handoff
  family: 'threat.effect-handoff
  quint-module: "effect_handoff"
  quint-file: "EffectHandoff.qnt"
  domain-dir: "threat/effect-handoff"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((effect-handoff-once HAND-ONCE quint)
           (effect-handoff-no-durability HAND-NODUR quint))
  dependencies: '((HAND-ONCE source) (HAND-ONCE profile) (HAND-ONCE method)
                  (HAND-NODUR source) (HAND-NODUR profile) (HAND-NODUR method))
  invariant: "Prepared effects commit durably under current authority and emit at most MaxSends times while retaining unknown outcomes."
  parameters: '((MaxSends "int"))
  state: '((phase "int" "0")
           (epoch "int" "0")
           (planned "int" "0")
           (paused "bool" "false")
           (fresh "bool" "true")
           (credential "bool" "true")
           (bytes "bool" "true")
           (durable "bool" "false")
           (unknown "bool" "false")
           (sent "int" "0")
           (unsafe "bool" "false"))
  guards: '((authority-current "isCurrent(h.paused, h.fresh, h.credential, h.bytes)")
            (epoch-current "epochCurrent(h.epoch, h.planned)")
            (durable-ack "h.durable"))
  transitions:
  '((current "val current = isCurrent(h.paused, h.fresh, h.credential, h.bytes)")
    (prepare "action prepare = if (h.phase == 0 and not(h.unknown) and current)\n    h' = h.with(\"phase\", 1).with(\"planned\", h.epoch) else h' = h")
    (commitAs "action commitAs(verified: bool): bool = if (h.phase == 1 and verified and current and epochCurrent(h.epoch, h.planned))\n    h' = h.with(\"phase\", 2).with(\"durable\", true).with(\"unknown\", true) else h' = h")
    (commit "action commit = { nondet verified = Set(false, true).oneOf()\n    commitAs(verified) }")
    (emit "action emit = if (h.phase == 2 and current and h.durable and epochCurrent(h.epoch, h.planned))\n    h' = h.with(\"phase\", 3).with(\"unknown\", true).with(\"sent\", h.sent + 1)\n      .with(\"unsafe\", h.unsafe or h.sent >= MaxSends)\n    else h' = h")
    (pause "action pause = h' = h.with(\"paused\", true)")
    (expire "action expire = h' = h.with(\"fresh\", false)")
    (changeWriter "action changeWriter = h' = h.with(\"epoch\", 1)")
    (substitute "action substitute = h' = h.with(\"bytes\", false)")
    (revoke "action revoke = h' = h.with(\"credential\", false)")
    (recover "action recover = h' = h")
    (step "action step = any { prepare, commit, emit, pause, expire, changeWriter, substitute, revoke, recover }"))
  safety: "not(h.unsafe) and h.sent <= MaxSends and (h.sent == 0 or h.unknown)"
  traces:
  '((blocked "action blocked = all { assert(h.sent == 0), assert(safety), h' = h }")
    (once "action once = all { assert(h.sent == 1), assert(h.unknown), assert(safety), h' = h }")
    (unsafe "action unsafe = all { assert(not(safety)), h' = h }")
    (exactHandoffTest "run exactHandoffTest = init.then(prepare).then(commitAs(true)).then(emit).then(once)")
    (absentAckTest "run absentAckTest = init.then(prepare).then(commitAs(false)).then(emit).then(blocked)")
    (expiredTest "run expiredTest = init.then(prepare).then(commitAs(true)).then(expire).then(emit).then(blocked)")
    (pausedTest "run pausedTest = init.then(prepare).then(pause).then(commitAs(true)).then(emit).then(blocked)")
    (writerChangedTest "run writerChangedTest = init.then(prepare).then(commitAs(true)).then(changeWriter).then(emit).then(blocked)")
    (substitutedBytesTest "run substitutedBytesTest = init.then(prepare).then(commitAs(true)).then(substitute).then(emit).then(blocked)")
    (revokedCredentialTest "run revokedCredentialTest = init.then(prepare).then(commitAs(true)).then(revoke).then(emit).then(blocked)")
    (lostReplyTest "run lostReplyTest = init.then(prepare).then(commitAs(true)).then(emit).then(recover).then(prepare).then(emit).then(once)"))
  countermodels: (list NoDurabilityCountermodel)
  limits: "Finite protocol abstraction; trusted bits summarize native interpreters; no cryptography, real CAS, codec correctness or Lean refinement is claimed.")

;; Weakened descendant: removes the durable-ack guard; must produce an unsafe witness.
(.def (NoDurabilityCountermodel @ EffectHandoffModel)
  identity: 'threat.effect-handoff.no-durability
  dropped-guard: 'durable-ack
  step-action: "stepNoDurability"
  counter-action: "action noDurability = if (h.phase == 1 and current)\n    h' = h.with(\"sent\", h.sent + 1).with(\"unsafe\", true) else h' = h\n  action stepNoDurability = any { step, noDurability }"
  expected-itf-predicate: "h.unsafe == true and h.sent >= 1")

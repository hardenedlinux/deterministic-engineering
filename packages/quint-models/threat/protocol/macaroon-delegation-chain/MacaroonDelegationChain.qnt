// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.protocol.macaroon-delegation-chain
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel hmac-caveat-chain-verify step=stepCaveatStripping max-steps=6 itf="not(subseteq(h.executedPerms, h.attenuatedPerms))"
// Limits: Finite three-permission delegation chain abstraction; does not model HMAC-SHA256 collision resistance or third-party discharge macaroon distribution.
module macaroon_delegation_chain {
  import authority_currentness.* from "../../zero-trust/authority-currentness/AuthorityCurrentness"
  type State = { rootPerms: Set[int], attenuatedPerms: Set[int], presentedPerms: Set[int], hmacValid: bool, delegationHops: int, executedPerms: Set[int] }
  var h: State
  action init = h' = { rootPerms: Set(1, 2, 3), attenuatedPerms: Set(1, 2, 3), presentedPerms: Set(1, 2, 3), hmacValid: true, delegationHops: 0, executedPerms: Set() }
  action delegateDropAdmin = if ((h.delegationHops < 2 and h.executedPerms == Set() and h.attenuatedPerms.contains(3))) h' = h.with("attenuatedPerms", h.attenuatedPerms.exclude(Set(3))).with("presentedPerms", h.attenuatedPerms.exclude(Set(3))).with("hmacValid", true).with("delegationHops", (h.delegationHops + 1)) else h' = h
  action delegateDropWrite = if ((h.delegationHops < 2 and h.executedPerms == Set() and h.attenuatedPerms.contains(2))) h' = h.with("attenuatedPerms", h.attenuatedPerms.exclude(Set(2))).with("presentedPerms", h.attenuatedPerms.exclude(Set(2))).with("hmacValid", true).with("delegationHops", (h.delegationHops + 1)) else h' = h
  action subagentStripCaveats = if (h.attenuatedPerms != h.rootPerms) h' = h.with("presentedPerms", h.rootPerms).with("hmacValid", false) else h' = h
  action invokeToolAs(p: int): bool = if ((h.hmacValid and h.presentedPerms.contains(p))) h' = h.with("executedPerms", h.executedPerms.union(Set(p))) else h' = h
  action invokeTool = { nondet p = Set(1, 2, 3).oneOf()
    invokeToolAs(p) }
  action step = any { delegateDropAdmin, delegateDropWrite, subagentStripCaveats, invokeTool }
  val safety = h.executedPerms.subseteq(h.attenuatedPerms)
  // Countermodel threat.protocol.macaroon-delegation-chain.caveat-stripping (dropped guard: hmac-caveat-chain-verify)
  action invokeToolNoHmac(p: int): bool = if ((true and h.presentedPerms.contains(p))) h' = h.with("executedPerms", h.executedPerms.union(Set(p))) else h' = h
  action stepCaveatStripping = any { step, { nondet p = Set(1, 2, 3).oneOf()
    invokeToolNoHmac(p) } }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run attenuatedSubagentSafeTest = init.then(delegateDropAdmin).then(invokeToolAs(1)).then(invokeToolAs(3)).then(all { assert(h.executedPerms == Set(1)), assert(safety), h' = h })
  run strippedCaveatRejectedTest = init.then(delegateDropAdmin).then(subagentStripCaveats).then(invokeToolAs(3)).then(all { assert(h.executedPerms == Set()), assert(safety), h' = h })
  run caveatStrippingCountermodelTest = init.then(delegateDropAdmin).then(subagentStripCaveats).then(invokeToolNoHmac(3)).then(checkUnsafe)
}

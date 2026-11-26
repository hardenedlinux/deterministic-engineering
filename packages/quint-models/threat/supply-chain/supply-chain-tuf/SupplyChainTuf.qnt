// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.supply-chain.supply-chain-tuf
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel monotonic-version-check step=stepTufRollback max-steps=6 itf="h.installedVer < h.clientMinVer"
// @countermodel timestamp-expiry-check step=stepTufFreeze max-steps=6 itf="h.installedMetaExp < h.installedAtClock"
// @countermodel snapshot-atomic-binding step=stepTufMixAndMatch max-steps=6 itf="h.installedHash != h.installedSnapTargetVer"
// Limits: Finite TUF 4-role metadata version/expiry/binding abstraction; does not model threshold key rotation ceremonies or Rekor Merkle inclusion proofs.
module supply_chain_tuf {
  import authority_currentness.* from "../../zero-trust/authority-currentness/AuthorityCurrentness"
  type State = { clock: int, repoVer: int, clientMinVer: int, installedVer: int, installedHash: int, installedSnapTargetVer: int, installedMetaExp: int, installedAtClock: int }
  var h: State
  action init = h' = { clock: 1, repoVer: 1, clientMinVer: 1, installedVer: 1, installedHash: 1, installedSnapTargetVer: 1, installedMetaExp: 2, installedAtClock: 1 }
  action publishRelease = if (h.repoVer < 3) h' = h.with("repoVer", (h.repoVer + 1)) else h' = h
  action advanceClock = if (h.clock < 4) h' = h.with("clock", (h.clock + 1)) else h' = h
  action clientUpdateAs(tsVer: int, tsExp: int, snapVer: int, targetVer: int, targetHash: int): bool = if ((tsVer >= 1 and tsVer <= h.repoVer and (tsVer >= h.clientMinVer and targetVer >= h.installedVer) and tsExp >= h.clock and (snapVer == tsVer and targetVer == snapVer and targetHash == targetVer))) h' = h.with("clientMinVer", if (tsVer > h.clientMinVer) tsVer else h.clientMinVer).with("installedVer", targetVer).with("installedHash", targetHash).with("installedSnapTargetVer", snapVer).with("installedMetaExp", tsExp).with("installedAtClock", h.clock) else h' = h
  action clientUpdate = { nondet v = Set(1, 2, 3).oneOf()
    nondet t = Set(1, 2, 3).oneOf()
    clientUpdateAs(v, (v + 1), v, t, t) }
  action step = any { publishRelease, advanceClock, clientUpdate }
  val safety = (h.installedVer >= h.clientMinVer and h.installedMetaExp >= h.installedAtClock and h.installedHash == h.installedSnapTargetVer)
  // Countermodel threat.supply-chain.supply-chain-tuf.rollback (dropped guard: monotonic-version-check)
  action updateNoMonotonic(tsVer: int, tsExp: int, snapVer: int, targetVer: int, targetHash: int): bool = if ((tsVer >= 1 and tsVer <= h.repoVer and true and tsExp >= h.clock and (snapVer == tsVer and targetVer == snapVer and targetHash == targetVer))) h' = h.with("clientMinVer", if (tsVer > h.clientMinVer) tsVer else h.clientMinVer).with("installedVer", targetVer).with("installedHash", targetHash).with("installedSnapTargetVer", snapVer).with("installedMetaExp", tsExp).with("installedAtClock", h.clock) else h' = h
  action stepTufRollback = any { step, { nondet v = Set(1, 2, 3).oneOf()
    updateNoMonotonic(v, (v + 1), v, v, v) } }
  // Countermodel threat.supply-chain.supply-chain-tuf.freeze (dropped guard: timestamp-expiry-check)
  action updateNoExpiry(tsVer: int, tsExp: int, snapVer: int, targetVer: int, targetHash: int): bool = if ((tsVer >= 1 and tsVer <= h.repoVer and (tsVer >= h.clientMinVer and targetVer >= h.installedVer) and true and (snapVer == tsVer and targetVer == snapVer and targetHash == targetVer))) h' = h.with("clientMinVer", if (tsVer > h.clientMinVer) tsVer else h.clientMinVer).with("installedVer", targetVer).with("installedHash", targetHash).with("installedSnapTargetVer", snapVer).with("installedMetaExp", tsExp).with("installedAtClock", h.clock) else h' = h
  action stepTufFreeze = any { step, { nondet v = Set(1, 2, 3).oneOf()
    updateNoExpiry(v, (v + 1), v, v, v) } }
  // Countermodel threat.supply-chain.supply-chain-tuf.mix-and-match (dropped guard: snapshot-atomic-binding)
  action updateMixAndMatch(tsVer: int, tsExp: int, snapVer: int, targetVer: int, targetHash: int): bool = if ((tsVer >= 1 and tsVer <= h.repoVer and (tsVer >= h.clientMinVer and targetVer >= h.installedVer) and tsExp >= h.clock and true)) h' = h.with("clientMinVer", if (tsVer > h.clientMinVer) tsVer else h.clientMinVer).with("installedVer", targetVer).with("installedHash", targetHash).with("installedSnapTargetVer", snapVer).with("installedMetaExp", tsExp).with("installedAtClock", h.clock) else h' = h
  action stepTufMixAndMatch = any { step, { nondet v = Set(1, 2, 3).oneOf()
    nondet hval = Set(1, 2, 3).oneOf()
    updateMixAndMatch(v, (v + 1), v, v, hval) } }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validUpgradeAndRejectRollbackTest = init.then(publishRelease).then(clientUpdateAs(2, 3, 2, 2, 2)).then(clientUpdateAs(1, 2, 1, 1, 1)).then(all { assert(h.installedVer == 2), assert(safety), h' = h })
  run expiredFreezeBlockedTest = init.then(advanceClock).then(advanceClock).then(clientUpdateAs(1, 2, 1, 1, 1)).then(all { assert(h.installedAtClock == 1), assert(safety), h' = h })
  run mixAndMatchBlockedTest = init.then(publishRelease).then(clientUpdateAs(2, 3, 2, 1, 1)).then(all { assert(h.installedVer == 1), assert(h.installedHash == h.installedSnapTargetVer), assert(safety), h' = h })
  run rollbackCountermodelTest = init.then(publishRelease).then(clientUpdateAs(2, 3, 2, 2, 2)).then(updateNoMonotonic(1, 2, 1, 1, 1)).then(checkUnsafe)
}

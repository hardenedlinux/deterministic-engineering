// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.parallel.hazard-pointers-tso
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel tso-store-load-fence step=stepMissingTsoFence max-steps=9 itf="h.readerPc == 5 and h.nodeFreed == true"
// Limits: Finite single-node, single-reader, single-reclaimer x86-TSO store-buffer abstraction; does not model ARM/POWER non-multi-copy-atomic reordering or dynamic HP array resizing.
module hazard_pointers_tso {
  type State = { nodePublished: bool, nodeRetired: bool, nodeFreed: bool, readerPc: int, readerHpBuffered: bool, readerHpVisible: bool, reclaimerScanned: bool, reclaimerSawHp: bool }
  var h: State
  action init = h' = { nodePublished: true, nodeRetired: false, nodeFreed: false, readerPc: 0, readerHpBuffered: false, readerHpVisible: false, reclaimerScanned: false, reclaimerSawHp: false }
  action readerLoadPtr = if ((h.readerPc == 0 and h.nodePublished)) h' = h.with("readerPc", 1) else h' = h
  action readerStoreHp = if (h.readerPc == 1) h' = h.with("readerPc", 2).with("readerHpBuffered", true) else h' = h
  action tsoFlushHp = if ((h.readerHpBuffered and not(h.readerHpVisible))) h' = h.with("readerHpVisible", true) else h' = h
  action readerMfence = if (h.readerPc == 2) h' = h.with("readerPc", 3).with("readerHpVisible", true) else h' = h
  action readerValidate = if (h.readerPc == 3) if (h.nodePublished) h' = h.with("readerPc", 4) else h' = h.with("readerPc", 0).with("readerHpBuffered", false).with("readerHpVisible", false) else h' = h
  action readerDeref = if (h.readerPc == 4) h' = h.with("readerPc", 5) else h' = h
  action reclaimerRetire = if ((h.nodePublished and not(h.nodeRetired))) h' = h.with("nodePublished", false).with("nodeRetired", true) else h' = h
  action reclaimerScan = if ((h.nodeRetired and not(h.reclaimerScanned))) h' = h.with("reclaimerScanned", true).with("reclaimerSawHp", h.readerHpVisible) else h' = h
  action reclaimerFree = if ((h.reclaimerScanned and not(h.reclaimerSawHp) and not(h.nodeFreed))) h' = h.with("nodeFreed", true) else h' = h
  action step = any { readerLoadPtr, readerStoreHp, tsoFlushHp, readerMfence, readerValidate, readerDeref, reclaimerRetire, reclaimerScan, reclaimerFree }
  val safety = not((h.readerPc == 5 and h.nodeFreed))
  // Countermodel engineering.parallel.hazard-pointers-tso.missing-tso-fence-uaf (dropped guard: tso-store-load-fence)
  action readerSkipMfence = if (h.readerPc == 2) h' = h.with("readerPc", 3).with("readerHpVisible", h.readerHpVisible) else h' = h
  action stepMissingTsoFence = any { step, readerSkipMfence }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run fencedHpBlocksFreeTest = init.then(readerLoadPtr).then(readerStoreHp).then(readerMfence).then(reclaimerRetire).then(reclaimerScan).then(reclaimerFree).then(all { assert(not(h.nodeFreed)), assert(safety), h' = h })
  run retireBeforeValidateRetriesSafelyTest = init.then(readerLoadPtr).then(readerStoreHp).then(readerMfence).then(reclaimerRetire).then(readerValidate).then(all { assert(h.readerPc == 0), assert(safety), h' = h })
  run tsoMissingFenceUafCountermodelTest = init.then(readerLoadPtr).then(readerStoreHp).then(readerSkipMfence).then(readerValidate).then(reclaimerRetire).then(reclaimerScan).then(reclaimerFree).then(readerDeref).then(checkUnsafe)
}

// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.ui-mainthread-rcu-snapshot
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel off-thread-io-lock-free step=stepBlockingIOReload max-steps=6 itf="h.mainStalled == true or h.writerHoldsLock == true"
// @countermodel atomic-publish-after-stage step=stepTornPublish max-steps=6 itf="h.renderGen > h.publishedGen or (h.stagingActive == true and h.stagingGen <= h.publishedGen)"
// Limits: Finite 4-generation single-writer RCU UI snapshot abstraction; does not model OS page faults, GPU command-buffer stalls, or multi-writer CAS contention.
module concurrency_ui_rcu_snapshot {
  type State = { publishedGen: int, stagingGen: int, stagingActive: bool, renderGen: int, writerHoldsLock: bool, mainStalled: bool }
  var h: State
  action init = h' = { publishedGen: 0, stagingGen: 0, stagingActive: false, renderGen: 0, writerHoldsLock: false, mainStalled: false }
  action beginStageIO = if ((not(h.stagingActive) and h.publishedGen < 4)) h' = h.with("stagingActive", true).with("stagingGen", (h.publishedGen + 1)).with("writerHoldsLock", false) else h' = h
  action publishSnapshot = if ((h.stagingActive and h.stagingGen > h.publishedGen)) h' = h.with("publishedGen", h.stagingGen).with("stagingGen", 0).with("stagingActive", false).with("writerHoldsLock", false) else h' = h
  action renderFrame = if (h.writerHoldsLock) h' = h.with("mainStalled", true) else h' = h.with("renderGen", h.publishedGen)
  action step = any { beginStageIO, publishSnapshot, renderFrame }
  val safety = (not(h.mainStalled) and not(h.writerHoldsLock) and h.renderGen <= h.publishedGen and (not(h.stagingActive) or h.stagingGen > h.publishedGen))
  // Countermodel engineering.concurrency.ui-mainthread-rcu-snapshot.blocking-io-reload (dropped guard: off-thread-io-lock-free)
  action beginStageIOBlocking = if ((not(h.stagingActive) and h.publishedGen < 4)) h' = h.with("stagingActive", true).with("stagingGen", (h.publishedGen + 1)).with("writerHoldsLock", true) else h' = h
  action stepBlockingIOReload = any { step, beginStageIOBlocking }
  // Countermodel engineering.concurrency.ui-mainthread-rcu-snapshot.torn-publish (dropped guard: atomic-publish-after-stage)
  action publishSnapshotUnchecked = if (true) h' = h.with("publishedGen", h.stagingGen).with("stagingGen", 0).with("stagingActive", false).with("writerHoldsLock", false) else h' = h
  action stepTornPublish = any { step, publishSnapshotUnchecked }
  action checkSafeRender = all { assert(not(h.mainStalled)), assert(h.renderGen == h.publishedGen), assert(safety), h' = h }
  run nonBlockingSwapTest = init.then(beginStageIO).then(renderFrame).then(publishSnapshot).then(renderFrame).then(checkSafeRender)
  run blockingIOReloadViolatesSafetyTest = init.then(beginStageIOBlocking).then(renderFrame).then(all { assert(h.mainStalled), assert(not(safety)), h' = h })
  run tornPublishViolatesSafetyTest = init.then(beginStageIO).then(publishSnapshot).then(renderFrame).then(publishSnapshotUnchecked).then(all { assert(not(safety)), h' = h })
}

// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.concurrency.lease-fencing-token
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel monotonic-fencing-token step=stepZombieWrite max-steps=6 itf="h.lastWriterToken < h.storageMaxToken"
// Limits: Finite two-client lease and storage fencing abstraction; does not model physical clock drift, consensus quorum replication, or storage crash recovery.
module lease_fencing_token {
  type State = { nextToken: int, c1Token: int, c1Paused: bool, c2Token: int, storageMaxToken: int, lastWriterToken: int }
  var h: State
  action init = h' = { nextToken: 1, c1Token: 0, c1Paused: false, c2Token: 0, storageMaxToken: 0, lastWriterToken: 0 }
  action acquireC1 = if ((h.c1Token == 0 and h.nextToken <= 3)) h' = h.with("c1Token", h.nextToken).with("nextToken", (h.nextToken + 1)).with("c1Paused", false) else h' = h
  action pauseC1 = if ((h.c1Token > 0 and not(h.c1Paused))) h' = h.with("c1Paused", true) else h' = h
  action acquireC2 = if ((h.c2Token == 0 and h.nextToken <= 3)) h' = h.with("c2Token", h.nextToken).with("nextToken", (h.nextToken + 1)) else h' = h
  action writeC1 = if (h.c1Token > 0) if (h.c1Token >= h.storageMaxToken) h' = h.with("storageMaxToken", if (h.c1Token > h.storageMaxToken) h.c1Token else h.storageMaxToken).with("lastWriterToken", h.c1Token).with("c1Paused", false) else h' = h.with("c1Paused", false) else h' = h
  action writeC2 = if (h.c2Token > 0) if (h.c2Token >= h.storageMaxToken) h' = h.with("storageMaxToken", h.c2Token).with("lastWriterToken", h.c2Token) else h' = h else h' = h
  action step = any { acquireC1, pauseC1, acquireC2, writeC1, writeC2 }
  val safety = h.lastWriterToken >= h.storageMaxToken
  // Countermodel engineering.concurrency.lease-fencing-token.stale-lease-zombie-write (dropped guard: monotonic-fencing-token)
  action writeC1NoFencing = if (h.c1Token > 0) if (true) h' = h.with("storageMaxToken", if (h.c1Token > h.storageMaxToken) h.c1Token else h.storageMaxToken).with("lastWriterToken", h.c1Token).with("c1Paused", false) else h' = h.with("c1Paused", false) else h' = h
  action stepZombieWrite = any { step, writeC1NoFencing }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run staleC1WriteRejectedAfterC2Test = init.then(acquireC1).then(pauseC1).then(acquireC2).then(writeC2).then(writeC1).then(all { assert(h.storageMaxToken == 2), assert(h.lastWriterToken == 2), assert(safety), h' = h })
  run zombieWriteCountermodelTest = init.then(acquireC1).then(pauseC1).then(acquireC2).then(writeC2).then(writeC1NoFencing).then(checkUnsafe)
}

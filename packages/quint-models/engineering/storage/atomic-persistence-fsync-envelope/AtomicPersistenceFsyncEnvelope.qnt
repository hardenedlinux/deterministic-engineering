// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.storage.atomic-persistence-fsync-envelope
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel use-staged-atomic-rename step=stepInPlaceTruncateWrite max-steps=6 itf="h.tornReads > 0"
// @countermodel use-unique-temp-file step=stepSharedTempCollision max-steps=6 itf="h.tempCollisions > 0"
// @countermodel fsync-temp-before-rename step=stepRenameBeforeFsyncCrash max-steps=6 itf="h.zeroLengthOnCrash > 0"
// Limits: Finite 2-writer staged-file and crash-boundary abstraction; verifies unique temp staging, fsync-before-rename ordering, atomic live replacement, and failure cleanup, not NVMe volatile write-cache lies or ext4 journal commit intervals.
module storage_atomic_persistence_fsync_envelope {
  type State = { committedVer: int, activeUniqueTemps: int, maxWriters: int, tempFsyncReady: bool, tornReads: int, tempCollisions: int, zeroLengthOnCrash: int, orphanTemps: int, cleanCommits: int }
  var h: State
  action init = h' = { committedVer: 1, activeUniqueTemps: 0, maxWriters: 2, tempFsyncReady: false, tornReads: 0, tempCollisions: 0, zeroLengthOnCrash: 0, orphanTemps: 0, cleanCommits: 0 }
  action stageUniqueTemp = if (h.activeUniqueTemps < h.maxWriters) h' = h.with("activeUniqueTemps", (h.activeUniqueTemps + 1)).with("tempFsyncReady", false) else h' = h
  action fsyncStagedTemp = if (h.activeUniqueTemps > 0 and not(h.tempFsyncReady)) h' = h.with("tempFsyncReady", true) else h' = h
  action atomicRenameCommit = if (h.activeUniqueTemps > 0 and h.tempFsyncReady) h' = h.with("activeUniqueTemps", (h.activeUniqueTemps - 1)).with("tempFsyncReady", false).with("committedVer", (h.committedVer + 1)).with("cleanCommits", (h.cleanCommits + 1)) else h' = h
  action cleanupFailedTemp = if (h.activeUniqueTemps > 0) h' = h.with("activeUniqueTemps", (h.activeUniqueTemps - 1)).with("tempFsyncReady", false) else h' = h
  action crashAndRecover = h' = h.with("activeUniqueTemps", 0).with("tempFsyncReady", false)
  action step = any { stageUniqueTemp, fsyncStagedTemp, atomicRenameCommit, cleanupFailedTemp, crashAndRecover }
  val safety = (h.committedVer >= 1 and h.activeUniqueTemps >= 0 and h.activeUniqueTemps <= h.maxWriters and h.tornReads == 0 and h.tempCollisions == 0 and h.zeroLengthOnCrash == 0 and h.orphanTemps == 0)
  // Countermodel engineering.storage.atomic-persistence-fsync-envelope.in-place-truncate-write (dropped guard: use-staged-atomic-rename)
  action writeInPlaceTruncate = h' = h.with("tornReads", (h.tornReads + 1))
  action stepInPlaceTruncateWrite = any { step, writeInPlaceTruncate }
  // Countermodel engineering.storage.atomic-persistence-fsync-envelope.shared-temp-collision (dropped guard: use-unique-temp-file)
  action writeSharedDeterministicTmp = if (h.activeUniqueTemps > 0) h' = h.with("tempCollisions", (h.tempCollisions + 1)).with("tornReads", (h.tornReads + 1)) else h' = h
  action stepSharedTempCollision = any { step, writeSharedDeterministicTmp }
  // Countermodel engineering.storage.atomic-persistence-fsync-envelope.rename-before-fsync-crash (dropped guard: fsync-temp-before-rename)
  action renameUnflushedThenCrash = if (h.activeUniqueTemps > 0 and not(h.tempFsyncReady)) h' = h.with("activeUniqueTemps", 0).with("zeroLengthOnCrash", (h.zeroLengthOnCrash + 1)) else h' = h
  action stepRenameBeforeFsyncCrash = any { step, renameUnflushedThenCrash }
  action checkAtomicPersistenceSafe = all { assert(h.cleanCommits > 0), assert(h.committedVer > 1), assert(h.tornReads == 0), assert(h.tempCollisions == 0), assert(h.zeroLengthOnCrash == 0), assert(h.orphanTemps == 0), assert(safety), h' = h }
  action checkAtomicPersistenceViolated = all { assert((h.tornReads > 0 or h.tempCollisions > 0 or h.zeroLengthOnCrash > 0)), assert(not(safety)), h' = h }
  run atomicPersistenceSafeTest = init.then(stageUniqueTemp).then(fsyncStagedTemp).then(atomicRenameCommit).then(stageUniqueTemp).then(cleanupFailedTemp).then(crashAndRecover).then(checkAtomicPersistenceSafe)
  run inPlaceTruncateRefutedTest = init.then(writeInPlaceTruncate).then(checkAtomicPersistenceViolated)
  run sharedTempCollisionRefutedTest = init.then(stageUniqueTemp).then(writeSharedDeterministicTmp).then(checkAtomicPersistenceViolated)
  run renameBeforeFsyncCrashRefutedTest = init.then(stageUniqueTemp).then(renameUnflushedThenCrash).then(checkAtomicPersistenceViolated)
}

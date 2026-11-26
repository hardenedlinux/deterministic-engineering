// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.storage.wal-crash-recovery
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel wal-fsync-before-data step=stepMissingWalFsync max-steps=6 itf="h.dataDiskVer > h.walDiskVer"
// @countermodel commit-fsync-before-ack step=stepUnflushedCommit max-steps=6 itf="h.crashed == true and h.recoveredVer < h.ackedCommitVer"
// Limits: Finite single-page WAL and OS page-cache writeback abstraction; does not model torn 512B/4KB sectors, ext4/XFS directory-entry fsync, or NVMe volatile write-cache lies.
module storage_wal_crash_recovery {
  type State = { walBufVer: int, walDiskVer: int, dataBufVer: int, dataDiskVer: int, ackedCommitVer: int, crashed: bool, recoveredVer: int }
  var h: State
  action init = h' = { walBufVer: 0, walDiskVer: 0, dataBufVer: 0, dataDiskVer: 0, ackedCommitVer: 0, crashed: false, recoveredVer: 0 }
  action appendWalBuf = if ((not(h.crashed) and h.walBufVer < 2 and h.walBufVer == h.dataBufVer)) h' = h.with("walBufVer", (h.walBufVer + 1)) else h' = h
  action fsyncWal = if ((not(h.crashed) and h.walDiskVer < h.walBufVer)) h' = h.with("walDiskVer", h.walBufVer) else h' = h
  action writeDataPage = if ((not(h.crashed) and h.dataBufVer < h.walBufVer and h.walDiskVer >= h.walBufVer)) h' = h.with("dataBufVer", h.walBufVer) else h' = h
  action osWritebackDataPage = if ((not(h.crashed) and h.dataDiskVer < h.dataBufVer)) h' = h.with("dataDiskVer", h.dataBufVer) else h' = h
  action ackCommitToClient = if ((not(h.crashed) and h.ackedCommitVer < h.walBufVer and h.walDiskVer >= h.walBufVer)) h' = h.with("ackedCommitVer", h.walBufVer) else h' = h
  action powerLossAndRecover = if (not(h.crashed)) h' = h.with("crashed", true).with("walBufVer", h.walDiskVer).with("dataBufVer", if (h.walDiskVer > h.dataDiskVer) h.walDiskVer else h.dataDiskVer).with("dataDiskVer", if (h.walDiskVer > h.dataDiskVer) h.walDiskVer else h.dataDiskVer).with("recoveredVer", h.walDiskVer) else h' = h
  action step = any { appendWalBuf, fsyncWal, writeDataPage, osWritebackDataPage, ackCommitToClient, powerLossAndRecover }
  val safety = (h.dataDiskVer <= h.walDiskVer and (not(h.crashed) or h.recoveredVer >= h.ackedCommitVer))
  // Countermodel engineering.storage.wal-crash-recovery.missing-wal-fsync-reorder (dropped guard: wal-fsync-before-data)
  action writeDataPageNoWalFsync = if ((not(h.crashed) and h.dataBufVer < h.walBufVer and true)) h' = h.with("dataBufVer", h.walBufVer) else h' = h
  action stepMissingWalFsync = any { step, writeDataPageNoWalFsync }
  // Countermodel engineering.storage.wal-crash-recovery.unflushed-commit-loss (dropped guard: commit-fsync-before-ack)
  action ackCommitNoFsync = if ((not(h.crashed) and h.ackedCommitVer < h.walBufVer and true)) h' = h.with("ackedCommitVer", h.walBufVer) else h' = h
  action stepUnflushedCommit = any { step, ackCommitNoFsync }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run crashSafeWalRedoTest = init.then(appendWalBuf).then(fsyncWal).then(ackCommitToClient).then(powerLossAndRecover).then(all { assert(h.crashed), assert(h.recoveredVer == 1), assert(h.dataDiskVer == 1), assert(safety), h' = h })
  run writeDataBlockedBeforeWalFsyncTest = init.then(appendWalBuf).then(writeDataPage).then(osWritebackDataPage).then(all { assert(h.dataDiskVer == 0), assert(safety), h' = h })
  run missingWalFsyncReorderCountermodelTest = init.then(appendWalBuf).then(writeDataPageNoWalFsync).then(osWritebackDataPage).then(checkUnsafe)
  run unflushedCommitLossCountermodelTest = init.then(appendWalBuf).then(ackCommitNoFsync).then(powerLossAndRecover).then(checkUnsafe)
}

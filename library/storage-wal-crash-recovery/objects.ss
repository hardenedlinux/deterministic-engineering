;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Write-Ahead Log (WAL) & Page-Cache fsync Crash-Recovery engineering model.
;;; Grounded in Mohan et al. (ARIES, ACM TODS 1992), Pillai et al. (All File Systems
;;; Are Not Created Equal, OSDI 2014 — BOB/ALICE write-reordering), and Bornholt et al.
;;; (ASPLOS 2016). Models volatile OS page cache vs. durable disk writeback ordering.
;;; Emergent safety (zero synthetic unsafe flag); both countermodels auto-derived via (guard ...).
(import :clan/poo/object
        (only-in "../threat-capabilities/objects.ss" ThreatModel.))
(export WalCrashRecoveryModel
        MissingWalFsyncReorderCountermodel
        UnflushedCommitLossCountermodel)

(.def (WalCrashRecoveryModel @ ThreatModel.)
  identity: 'engineering.storage.wal-crash-recovery
  family: 'engineering.storage.wal-crash-recovery
  quint-module: "storage_wal_crash_recovery"
  quint-file: "WalCrashRecovery.qnt"
  domain-dir: "engineering/storage/wal-crash-recovery"
  quint-imports: '()
  rules: '((wal-fsync-before-data STO-WAL-ORDER quint)
           (commit-fsync-before-ack STO-WAL-DURABLE quint))
  dependencies: '((STO-WAL-ORDER source) (STO-WAL-ORDER profile) (STO-WAL-ORDER method)
                  (STO-WAL-DURABLE source) (STO-WAL-DURABLE profile) (STO-WAL-DURABLE method))
  invariant: "On-disk data pages never overtake the persisted WAL (write-ahead rule), and crash recovery preserves every commit acknowledged to clients."
  parameters: '()
  state: '((walBufVer "int" "0")
           (walDiskVer "int" "0")
           (dataBufVer "int" "0")
           (dataDiskVer "int" "0")
           (ackedCommitVer "int" "0")
           (crashed "bool" "false")
           (recoveredVer "int" "0"))
  guards: '((wal-fsync-before-data (>= (. h walDiskVer) (. h walBufVer)))
            (commit-fsync-before-ack (>= (. h walDiskVer) (. h walBufVer))))
  transitions:
  '((appendWalBuf
      (action appendWalBuf ()
        (if (and (not (. h crashed)) (< (. h walBufVer) 2) (= (. h walBufVer) (. h dataBufVer)))
          (set-h (walBufVer (+ (. h walBufVer) 1)))
          (keep-h))))
    (fsyncWal
      (action fsyncWal ()
        (if (and (not (. h crashed)) (< (. h walDiskVer) (. h walBufVer)))
          (set-h (walDiskVer (. h walBufVer)))
          (keep-h))))
    (writeDataPage
      (action writeDataPage ()
        (if (and (not (. h crashed))
                 (< (. h dataBufVer) (. h walBufVer))
                 (guard wal-fsync-before-data (>= (. h walDiskVer) (. h walBufVer))))
          (set-h (dataBufVer (. h walBufVer)))
          (keep-h))))
    (osWritebackDataPage
      (action osWritebackDataPage ()
        (if (and (not (. h crashed)) (< (. h dataDiskVer) (. h dataBufVer)))
          (set-h (dataDiskVer (. h dataBufVer)))
          (keep-h))))
    (ackCommitToClient
      (action ackCommitToClient ()
        (if (and (not (. h crashed))
                 (< (. h ackedCommitVer) (. h walBufVer))
                 (guard commit-fsync-before-ack (>= (. h walDiskVer) (. h walBufVer))))
          (set-h (ackedCommitVer (. h walBufVer)))
          (keep-h))))
    (powerLossAndRecover
      (action powerLossAndRecover ()
        (if (not (. h crashed))
          (set-h (crashed #t)
                 (walBufVer (. h walDiskVer))
                 (dataBufVer (if (> (. h walDiskVer) (. h dataDiskVer)) (. h walDiskVer) (. h dataDiskVer)))
                 (dataDiskVer (if (> (. h walDiskVer) (. h dataDiskVer)) (. h walDiskVer) (. h dataDiskVer)))
                 (recoveredVer (. h walDiskVer)))
          (keep-h))))
    (step
      (action step ()
        (any appendWalBuf fsyncWal writeDataPage osWritebackDataPage ackCommitToClient powerLossAndRecover))))
  safety:
  '(and (<= (. h dataDiskVer) (. h walDiskVer))
        (or (not (. h crashed)) (>= (. h recoveredVer) (. h ackedCommitVer))))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (crashSafeWalRedoTest
      (run crashSafeWalRedoTest
        (then init appendWalBuf fsyncWal ackCommitToClient powerLossAndRecover
              (all (assert (. h crashed)) (assert (= (. h recoveredVer) 1)) (assert (= (. h dataDiskVer) 1)) (assert safety) (keep-h)))))
    (writeDataBlockedBeforeWalFsyncTest
      (run writeDataBlockedBeforeWalFsyncTest
        (then init appendWalBuf writeDataPage osWritebackDataPage
              (all (assert (= (. h dataDiskVer) 0)) (assert safety) (keep-h)))))
    (missingWalFsyncReorderCountermodelTest
      (run missingWalFsyncReorderCountermodelTest
        (then init appendWalBuf writeDataPageNoWalFsync osWritebackDataPage checkUnsafe)))
    (unflushedCommitLossCountermodelTest
      (run unflushedCommitLossCountermodelTest
        (then init appendWalBuf ackCommitNoFsync powerLossAndRecover checkUnsafe))))
  countermodels: (list MissingWalFsyncReorderCountermodel UnflushedCommitLossCountermodel)
  limits: "Finite single-page WAL and OS page-cache writeback abstraction; does not model torn 512B/4KB sectors, ext4/XFS directory-entry fsync, or NVMe volatile write-cache lies.")

(.def (MissingWalFsyncReorderCountermodel @ WalCrashRecoveryModel)
  identity: 'engineering.storage.wal-crash-recovery.missing-wal-fsync-reorder
  dropped-guard: 'wal-fsync-before-data
  step-action: "stepMissingWalFsync"
  derive-from-transition: 'writeDataPage
  derive-action-name: 'writeDataPageNoWalFsync
  expected-itf-predicate: "h.dataDiskVer > h.walDiskVer")

(.def (UnflushedCommitLossCountermodel @ WalCrashRecoveryModel)
  identity: 'engineering.storage.wal-crash-recovery.unflushed-commit-loss
  dropped-guard: 'commit-fsync-before-ack
  step-action: "stepUnflushedCommit"
  derive-from-transition: 'ackCommitToClient
  derive-action-name: 'ackCommitNoFsync
  expected-itf-predicate: "h.crashed == true and h.recoveredVer < h.ackedCommitVer")

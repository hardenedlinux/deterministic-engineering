;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Write-Ahead Log (WAL) & Page-Cache fsync Crash-Recovery engineering model.
;;; Co-located Yuanxu unit: single source of truth alongside WalCrashRecovery.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export WalCrashRecoveryModel)

(.def (WalCrashRecoveryModel @ ThreatModel.)
  identity: 'engineering.storage.wal-crash-recovery
  family: 'engineering.storage.wal-crash-recovery
  title: "Write-Ahead Log (WAL) & OS Page-Cache Crash Recovery"
  subdomain: 'quint.engineering.storage
  papers:
  '(("C. Mohan et al. (ACM TODS 1992)"
     "ARIES: A Transaction Recovery Method Supporting Fine-Granularity Locking and Partial Rollbacks Using Write-Ahead Logging.")
    ("T. S. Pillai et al. (USENIX OSDI 2014)"
     "All File Systems Are Not Created Equal (BOB/ALICE): out-of-order page-cache writeback and missing-fsync crash anomalies.")
    ("J. Bornholt et al. (ASPLOS 2016)"
     "Specifying and Checking File System Crash-Consistency Models."))
  quint-module: "storage_wal_crash_recovery"
  quint-file: "WalCrashRecovery.qnt"
  domain-dir: "engineering/storage/wal-crash-recovery"
  rules: '((wal-fsync-before-data STO-WAL-ORDER quint)
           (commit-fsync-before-ack STO-WAL-DURABLE quint))
  dependencies: '((STO-WAL-ORDER source) (STO-WAL-ORDER profile) (STO-WAL-ORDER method)
                  (STO-WAL-DURABLE source) (STO-WAL-DURABLE profile) (STO-WAL-DURABLE method))
  invariant: "On-disk data pages never overtake the persisted WAL (write-ahead rule), and crash recovery preserves every commit acknowledged to clients."
  limits: "Finite single-page WAL and OS page-cache writeback abstraction; does not model torn 512B/4KB sectors, ext4/XFS directory-entry fsync, or NVMe volatile write-cache lies.")

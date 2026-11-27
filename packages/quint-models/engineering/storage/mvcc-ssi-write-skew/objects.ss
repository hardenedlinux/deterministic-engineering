;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Distributed MVCC & Serializable Snapshot Isolation (SSI) Write-Skew engineering model.
;;; Co-located Yuanxu unit: single source of truth alongside MvccSsiWriteSkew.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export MvccSsiWriteSkewModel)

(.def (MvccSsiWriteSkewModel @ ThreatModel.)
  identity: 'engineering.storage.mvcc-ssi-write-skew
  family: 'engineering.storage.mvcc-ssi-write-skew
  title: "Distributed MVCC & Serializable Snapshot Isolation (SSI) Write Skew"
  subdomain: 'quint.engineering.storage
  papers:
  '(("H. Berenson et al. (ACM SIGMOD 1995)"
     "A Critique of ANSI SQL Isolation Levels: formalizes Snapshot Isolation and Write Skew anomaly (A5B).")
    ("A. Adya, B. Liskov & P. O'Neil (ICDE 2000)"
     "Generalized Isolation Level Definitions: Direct Serialization Graph (DSG) rw-antidependency cycles.")
    ("M. J. Cahill, U. Rohm & A. D. Fekete (ACM SIGMOD 2008 / TODS 2009)"
     "Serializable Isolation for Snapshot Databases: SIREAD locks and dangerous rw-structures.")
    ("D. R. K. Ports & K. Grittner (PVLDB 2012)"
     "Serializable Snapshot Isolation in PostgreSQL: post-commit SIREAD retention (§2.2) and read-time rw detection (§3.2)."))
  quint-module: "storage_mvcc_ssi"
  quint-file: "MvccSsiWriteSkew.qnt"
  domain-dir: "engineering/storage/mvcc-ssi-write-skew"
  rules: '((ssi-dangerous-structure STOR-MVCC-SSI quint)
           (retain-siread-after-commit STOR-MVCC-SIREAD quint)
           (detect-rw-on-read STOR-MVCC-READRW quint))
  dependencies: '((STOR-MVCC-SSI source) (STOR-MVCC-SSI profile) (STOR-MVCC-SSI method)
                  (STOR-MVCC-SIREAD source) (STOR-MVCC-SIREAD profile) (STOR-MVCC-SIREAD method)
                  (STOR-MVCC-READRW source) (STOR-MVCC-READRW profile) (STOR-MVCC-READRW method))
  invariant: "Serializable Snapshot Isolation preserves the multi-key invariant (balX + balY >= 1) and withdrawal conservation (balX + balY + committedWithdrawals == 2) across all concurrent schedules."
  limits: "Finite 2-transaction, 2-key MVCC/SSI abstraction verifying write skew, lost updates, persistent SIREAD locks, and read-time rw-antidependencies; does not model 3-txn read-only anomalies, predicate index page coarsening, or GC vacuuming of old SIREAD locks.")

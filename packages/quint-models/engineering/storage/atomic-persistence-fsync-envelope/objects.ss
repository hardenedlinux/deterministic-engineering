;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Crash-safe atomic file persistence, unique temp-file staging, and
;;; fsync-before-rename ordering envelope (SM21).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export AtomicPersistenceFsyncEnvelopeModel)

(.def (AtomicPersistenceFsyncEnvelopeModel @ ThreatModel.)
  identity: 'engineering.storage.atomic-persistence-fsync-envelope
  family: 'engineering.storage.atomic-persistence-fsync-envelope
  title: "Crash-Safe Atomic Persistence, Unique Temp Staging & Fsync-Before-Rename Envelope"
  subdomain: 'quint.engineering.storage
  papers:
  '(("T. S. Pillai et al. (USENIX OSDI 2014 Best Paper)"
     "All File Systems Are Not Created Equal: On the Complexity of Crafting Crash-Consistent Applications — renaming an un-fsynced temp file can expose a zero-length live file after crash.")
    ("J. Bornholt et al. (ACM ASPLOS 2016)"
     "Specifying and Checking File System Crash-Consistency Models — atomic write-temp + fsync + rename + parent-dir sync prevents torn state across concurrent readers and crashes.")
    ("IEEE Std 1003.1 POSIX rename(2) Semantics"
     "Atomic directory entry replacement requires disjoint per-writer temp files (PID/counter/nonce) so concurrent writers never collide on a shared .tmp path."))
  quint-module: "storage_atomic_persistence_fsync_envelope"
  quint-file: "AtomicPersistenceFsyncEnvelope.qnt"
  domain-dir: "engineering/storage/atomic-persistence-fsync-envelope"
  rules:
  '((sto-atomic-staged-rename STO-ATOMIC-STAGED-RENAME quint)
    (sto-atomic-unique-temp STO-ATOMIC-UNIQUE-TEMP quint)
    (sto-atomic-fsync-order STO-ATOMIC-FSYNC-ORDER quint))
  dependencies:
  '((STO-ATOMIC-STAGED-RENAME source)
    (STO-ATOMIC-STAGED-RENAME profile)
    (STO-ATOMIC-STAGED-RENAME method)
    (STO-ATOMIC-UNIQUE-TEMP source)
    (STO-ATOMIC-UNIQUE-TEMP profile)
    (STO-ATOMIC-UNIQUE-TEMP method)
    (STO-ATOMIC-FSYNC-ORDER source)
    (STO-ATOMIC-FSYNC-ORDER profile)
    (STO-ATOMIC-FSYNC-ORDER method))
  invariant: "Live persisted state files are never truncated in-place (tornReads == 0), concurrent writers stage into disjoint unique temp files in the target parent directory (tempCollisions == 0), every staged file is fsynced before atomic rename so crashes never leave zero-length live files (zeroLengthOnCrash == 0), and failed writes remove staged temp artifacts (orphanTemps == 0)."
  limits: "Finite 2-writer staged-file and crash-boundary abstraction; verifies unique temp staging, fsync-before-rename ordering, atomic live replacement, and failure cleanup, not NVMe volatile write-cache lies or ext4 journal commit intervals.")

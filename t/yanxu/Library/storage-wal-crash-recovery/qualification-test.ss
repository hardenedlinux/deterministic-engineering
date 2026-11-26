;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/storage-wal-crash-recovery/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export storage-wal-crash-recovery-qualification-test)

(def storage-wal-crash-recovery-qualification-test
  (make-quint-model-qualification-suite
    "storage-wal-crash-recovery"
    WalCrashRecoveryModel
    (.get ThreatModelProfiles storage-wal-crash-recovery)))

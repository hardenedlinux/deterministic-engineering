;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/storage/wal-crash-recovery/objects
                 WalCrashRecoveryModel)
        "../../../support/quint-model-qualification.ss")
(export wal-crash-recovery-qualification-test)

(def wal-crash-recovery-qualification-test
  (make-quint-model-qualification-suite "wal-crash-recovery" WalCrashRecoveryModel))

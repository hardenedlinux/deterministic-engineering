;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/ui-mainthread-rcu-snapshot/objects
                 UiMainThreadRcuSnapshotModel)
        "../../../support/quint-model-qualification.ss")
(export ui-mainthread-rcu-snapshot-qualification-test)

(def ui-mainthread-rcu-snapshot-qualification-test
  (make-quint-model-qualification-suite "ui-mainthread-rcu-snapshot" UiMainThreadRcuSnapshotModel))

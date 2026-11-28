;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/storage-boundary-integrity-and-sync-confinement/objects
                 StorageBoundaryIntegrityAndSyncConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export storage-boundary-integrity-and-sync-confinement-qualification-test)

(def storage-boundary-integrity-and-sync-confinement-qualification-test
  (make-quint-model-qualification-suite
    "storage-boundary-integrity-and-sync-confinement"
    StorageBoundaryIntegrityAndSyncConfinementModel))

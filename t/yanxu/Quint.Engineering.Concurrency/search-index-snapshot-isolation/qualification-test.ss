;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/search-index-snapshot-isolation/objects
                 SearchIndexSnapshotIsolationModel)
        "../../../support/quint-model-qualification.ss")
(export search-index-snapshot-isolation-qualification-test)

(def search-index-snapshot-isolation-qualification-test
  (make-quint-model-qualification-suite "search-index-snapshot-isolation" SearchIndexSnapshotIsolationModel))

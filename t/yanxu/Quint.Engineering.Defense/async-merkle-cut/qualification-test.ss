;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/async-merkle-cut/objects
                 AsyncMerkleCutModel)
        "../../../support/quint-model-qualification.ss")
(export async-merkle-cut-qualification-test)

(def async-merkle-cut-qualification-test
  (make-quint-model-qualification-suite "async-merkle-cut" AsyncMerkleCutModel))

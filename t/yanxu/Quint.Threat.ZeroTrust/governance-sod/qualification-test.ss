;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/governance-sod/objects
                 GovernanceSodModel)
        "../../../support/quint-model-qualification.ss")
(export governance-sod-qualification-test)

(def governance-sod-qualification-test
  (make-quint-model-qualification-suite "governance-sod" GovernanceSodModel))

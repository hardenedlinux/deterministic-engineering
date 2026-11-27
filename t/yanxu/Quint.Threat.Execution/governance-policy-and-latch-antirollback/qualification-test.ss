;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/governance-policy-and-latch-antirollback/objects
                 GovernancePolicyAndLatchAntirollbackModel)
        "../../../support/quint-model-qualification.ss")
(export governance-policy-and-latch-antirollback-qualification-test)

(def governance-policy-and-latch-antirollback-qualification-test
  (make-quint-model-qualification-suite
    "governance-policy-and-latch-antirollback"
    GovernancePolicyAndLatchAntirollbackModel))

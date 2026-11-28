;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/policy-admission-sufficiency/objects
                 PolicyAdmissionSufficiencyModel)
        "../../../support/quint-model-qualification.ss")
(export policy-admission-sufficiency-qualification-test)

(def policy-admission-sufficiency-qualification-test
  (make-quint-model-qualification-suite "policy-admission-sufficiency" PolicyAdmissionSufficiencyModel))

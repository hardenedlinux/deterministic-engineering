;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/policy-gate-blindspot-and-cycle-confinement/objects
                 PolicyGateBlindspotAndCycleConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export policy-gate-blindspot-and-cycle-confinement-qualification-test)

(def policy-gate-blindspot-and-cycle-confinement-qualification-test
  (make-quint-model-qualification-suite
    "policy-gate-blindspot-and-cycle-confinement"
    PolicyGateBlindspotAndCycleConfinementModel))

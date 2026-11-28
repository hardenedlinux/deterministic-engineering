;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/defense-pillar-crypto-state-confinement/objects
                 DefensePillarCryptoStateConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export defense-pillar-crypto-state-confinement-qualification-test)

(def defense-pillar-crypto-state-confinement-qualification-test
  (make-quint-model-qualification-suite
    "defense-pillar-crypto-state-confinement"
    DefensePillarCryptoStateConfinementModel))

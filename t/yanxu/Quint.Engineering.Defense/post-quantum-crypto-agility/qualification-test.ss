;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/post-quantum-crypto-agility/objects
                 PostQuantumCryptoAgilityModel)
        "../../../support/quint-model-qualification.ss")
(export post-quantum-crypto-agility-qualification-test)

(def post-quantum-crypto-agility-qualification-test
  (make-quint-model-qualification-suite
    "post-quantum-crypto-agility"
    PostQuantumCryptoAgilityModel))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/key-rotation-crypto-shredding/objects
                 KeyRotationCryptoShreddingModel)
        "../../../support/quint-model-qualification.ss")
(export key-rotation-crypto-shredding-qualification-test)

(def key-rotation-crypto-shredding-qualification-test
  (make-quint-model-qualification-suite
    "key-rotation-crypto-shredding"
    KeyRotationCryptoShreddingModel))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/byzantine-encrypted-store/objects
                 ByzantineEncryptedStoreModel)
        "../../../support/quint-model-qualification.ss")
(export byzantine-encrypted-store-qualification-test)

(def byzantine-encrypted-store-qualification-test
  (make-quint-model-qualification-suite "byzantine-encrypted-store" ByzantineEncryptedStoreModel))

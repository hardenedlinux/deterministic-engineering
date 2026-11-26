;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/supply-chain/slsa-hermetic-provenance/objects
                 SlsaHermeticProvenanceModel)
        "../../../support/quint-model-qualification.ss")
(export slsa-hermetic-provenance-qualification-test)

(def slsa-hermetic-provenance-qualification-test
  (make-quint-model-qualification-suite "slsa-hermetic-provenance" SlsaHermeticProvenanceModel))

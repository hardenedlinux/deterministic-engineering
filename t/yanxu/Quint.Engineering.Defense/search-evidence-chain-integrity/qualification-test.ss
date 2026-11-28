;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/search-evidence-chain-integrity/objects
                 SearchEvidenceChainIntegrityModel)
        "../../../support/quint-model-qualification.ss")
(export search-evidence-chain-integrity-qualification-test)

(def search-evidence-chain-integrity-qualification-test
  (make-quint-model-qualification-suite
    "search-evidence-chain-integrity"
    SearchEvidenceChainIntegrityModel))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/search-diversity-exploration/objects
                 SearchDiversityExplorationModel)
        "../../../support/quint-model-qualification.ss")
(export search-diversity-exploration-qualification-test)

(def search-diversity-exploration-qualification-test
  (make-quint-model-qualification-suite
    "search-diversity-exploration"
    SearchDiversityExplorationModel))

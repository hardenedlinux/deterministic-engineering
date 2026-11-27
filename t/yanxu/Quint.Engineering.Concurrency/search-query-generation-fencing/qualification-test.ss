;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/search-query-generation-fencing/objects
                 SearchQueryGenerationFencingModel)
        "../../../support/quint-model-qualification.ss")
(export search-query-generation-fencing-qualification-test)

(def search-query-generation-fencing-qualification-test
  (make-quint-model-qualification-suite "search-query-generation-fencing" SearchQueryGenerationFencingModel))

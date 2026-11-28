;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/search-query-metamorphic-algebra/objects
                 SearchQueryMetamorphicAlgebraModel)
        "../../../support/quint-model-qualification.ss")
(export search-query-metamorphic-algebra-qualification-test)

(def search-query-metamorphic-algebra-qualification-test
  (make-quint-model-qualification-suite "search-query-metamorphic-algebra" SearchQueryMetamorphicAlgebraModel))

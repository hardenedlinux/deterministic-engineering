;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/bounded-negative-revalidation/objects
                 BoundedNegativeRevalidationModel)
        "../../../support/quint-model-qualification.ss")
(export bounded-negative-revalidation-qualification-test)

(def bounded-negative-revalidation-qualification-test
  (make-quint-model-qualification-suite "bounded-negative-revalidation" BoundedNegativeRevalidationModel))

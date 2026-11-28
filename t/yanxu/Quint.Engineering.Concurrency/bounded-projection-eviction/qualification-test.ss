;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/bounded-projection-eviction/objects
                 BoundedProjectionEvictionModel)
        "../../../support/quint-model-qualification.ss")
(export bounded-projection-eviction-qualification-test)

(def bounded-projection-eviction-qualification-test
  (make-quint-model-qualification-suite "bounded-projection-eviction" BoundedProjectionEvictionModel))

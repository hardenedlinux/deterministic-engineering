;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/parallel/work-stealing-deque/objects
                 WorkStealingDequeModel)
        "../../../support/quint-model-qualification.ss")
(export work-stealing-deque-qualification-test)

(def work-stealing-deque-qualification-test
  (make-quint-model-qualification-suite "work-stealing-deque" WorkStealingDequeModel))

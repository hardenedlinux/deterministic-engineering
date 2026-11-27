;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/metastable-retry-collapse/objects
                 MetastableRetryCollapseModel)
        "../../../support/quint-model-qualification.ss")
(export metastable-retry-collapse-qualification-test)

(def metastable-retry-collapse-qualification-test
  (make-quint-model-qualification-suite "metastable-retry-collapse" MetastableRetryCollapseModel))

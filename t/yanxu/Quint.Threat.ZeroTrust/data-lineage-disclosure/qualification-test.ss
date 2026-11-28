;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/data-lineage-disclosure/objects
                 DataLineageDisclosureModel)
        "../../../support/quint-model-qualification.ss")
(export data-lineage-disclosure-qualification-test)

(def data-lineage-disclosure-qualification-test
  (make-quint-model-qualification-suite "data-lineage-disclosure" DataLineageDisclosureModel))

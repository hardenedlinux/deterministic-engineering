;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/capabilities/objects
                 CapabilitiesModel)
        "../../../support/quint-model-qualification.ss")
(export capabilities-qualification-test)

(def capabilities-qualification-test
  (make-quint-model-qualification-suite "capabilities" CapabilitiesModel))

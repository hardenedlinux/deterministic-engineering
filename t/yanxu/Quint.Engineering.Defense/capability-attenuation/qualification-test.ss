;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/capability-attenuation/objects
                 CapabilityAttenuationModel)
        "../../../support/quint-model-qualification.ss")
(export capability-attenuation-qualification-test)

(def capability-attenuation-qualification-test
  (make-quint-model-qualification-suite "capability-attenuation" CapabilityAttenuationModel))

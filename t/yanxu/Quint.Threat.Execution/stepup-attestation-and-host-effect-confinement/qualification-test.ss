;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/stepup-attestation-and-host-effect-confinement/objects
                 StepUpAttestationAndHostEffectConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export stepup-attestation-and-host-effect-confinement-qualification-test)

(def stepup-attestation-and-host-effect-confinement-qualification-test
  (make-quint-model-qualification-suite
    "stepup-attestation-and-host-effect-confinement"
    StepUpAttestationAndHostEffectConfinementModel))

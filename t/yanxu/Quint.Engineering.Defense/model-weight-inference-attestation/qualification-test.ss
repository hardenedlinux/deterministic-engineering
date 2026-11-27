;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/model-weight-inference-attestation/objects
                 ModelWeightInferenceAttestationModel)
        "../../../support/quint-model-qualification.ss")
(export model-weight-inference-attestation-qualification-test)

(def model-weight-inference-attestation-qualification-test
  (make-quint-model-qualification-suite
    "model-weight-inference-attestation"
    ModelWeightInferenceAttestationModel))

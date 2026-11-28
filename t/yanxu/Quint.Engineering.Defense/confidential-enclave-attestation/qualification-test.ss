;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/confidential-enclave-attestation/objects
                 ConfidentialEnclaveAttestationModel)
        "../../../support/quint-model-qualification.ss")
(export confidential-enclave-attestation-qualification-test)

(def confidential-enclave-attestation-qualification-test
  (make-quint-model-qualification-suite
    "confidential-enclave-attestation"
    ConfidentialEnclaveAttestationModel))

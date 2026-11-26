;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/workload-identity-rotation/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export workload-identity-rotation-qualification-test)

(def workload-identity-rotation-qualification-test
  (make-quint-model-qualification-suite
    "workload-identity-rotation"
    WorkloadIdentityRotationModel
    (.get ThreatModelProfiles workload-identity-rotation)))

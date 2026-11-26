;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/concurrency-saga-compensation/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export concurrency-saga-compensation-qualification-test)

(def concurrency-saga-compensation-qualification-test
  (make-quint-model-qualification-suite
    "concurrency-saga-compensation"
    SagaCompensationModel
    (.get ThreatModelProfiles concurrency-saga-compensation)))

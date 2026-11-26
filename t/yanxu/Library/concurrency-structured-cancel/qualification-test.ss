;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/concurrency-structured-cancel/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export concurrency-structured-cancel-qualification-test)

(def concurrency-structured-cancel-qualification-test
  (make-quint-model-qualification-suite
    "concurrency-structured-cancel"
    StructuredCancelModel
    (.get ThreatModelProfiles concurrency-structured-cancel)))

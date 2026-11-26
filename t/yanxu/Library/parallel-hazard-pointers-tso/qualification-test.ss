;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/parallel-hazard-pointers-tso/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export parallel-hazard-pointers-tso-qualification-test)

(def parallel-hazard-pointers-tso-qualification-test
  (make-quint-model-qualification-suite
    "parallel-hazard-pointers-tso"
    HazardPointersTsoModel
    (.get ThreatModelProfiles parallel-hazard-pointers-tso)))

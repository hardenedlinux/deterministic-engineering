;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/governance-sod/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export governance-sod-qualification-test)

(def governance-sod-qualification-test
  (make-quint-model-qualification-suite
    "governance-sod"
    GovernanceSodModel
    (.get ThreatModelProfiles governance-sod)))

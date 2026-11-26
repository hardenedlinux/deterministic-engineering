;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/data-lineage-disclosure/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export data-lineage-disclosure-qualification-test)

(def data-lineage-disclosure-qualification-test
  (make-quint-model-qualification-suite
    "data-lineage-disclosure"
    DataLineageDisclosureModel
    (.get ThreatModelProfiles data-lineage-disclosure)))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/parallel-epoch-reclamation/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export parallel-epoch-reclamation-qualification-test)

(def parallel-epoch-reclamation-qualification-test
  (make-quint-model-qualification-suite
    "parallel-epoch-reclamation"
    EpochReclamationModel
    (.get ThreatModelProfiles parallel-epoch-reclamation)))

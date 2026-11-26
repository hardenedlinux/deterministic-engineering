;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/parallel-work-stealing/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export parallel-work-stealing-qualification-test)

(def parallel-work-stealing-qualification-test
  (make-quint-model-qualification-suite
    "parallel-work-stealing"
    WorkStealingDequeModel
    (.get ThreatModelProfiles parallel-work-stealing)))

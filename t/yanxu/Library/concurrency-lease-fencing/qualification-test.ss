;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/concurrency-lease-fencing/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export concurrency-lease-fencing-qualification-test)

(def concurrency-lease-fencing-qualification-test
  (make-quint-model-qualification-suite
    "concurrency-lease-fencing"
    LeaseFencingModel
    (.get ThreatModelProfiles concurrency-lease-fencing)))

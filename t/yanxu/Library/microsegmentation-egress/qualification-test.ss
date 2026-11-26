;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/microsegmentation-egress/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export microsegmentation-egress-qualification-test)

(def microsegmentation-egress-qualification-test
  (make-quint-model-qualification-suite
    "microsegmentation-egress"
    MicrosegmentationEgressModel
    (.get ThreatModelProfiles microsegmentation-egress)))

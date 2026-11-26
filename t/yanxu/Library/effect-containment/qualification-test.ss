;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/effect-containment/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export effect-containment-qualification-test)

(def effect-containment-qualification-test
  (make-quint-model-qualification-suite
    "effect-containment"
    EffectContainmentModel
    (.get ThreatModelProfiles effect-containment)))

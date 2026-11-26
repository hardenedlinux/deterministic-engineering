;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/effect-handoff/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export effect-handoff-qualification-test)

(def effect-handoff-qualification-test
  (make-quint-model-qualification-suite
    "effect-handoff"
    EffectHandoffModel
    (.get ThreatModelProfiles effect-handoff)))

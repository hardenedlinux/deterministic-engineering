;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/gc-tricolor-barrier/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export gc-tricolor-barrier-qualification-test)

(def gc-tricolor-barrier-qualification-test
  (make-quint-model-qualification-suite
    "gc-tricolor-barrier"
    TricolorWriteBarrierModel
    (.get ThreatModelProfiles gc-tricolor-barrier)))

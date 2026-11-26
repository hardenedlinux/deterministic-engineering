;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/state-rollback/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export state-rollback-qualification-test)

(def state-rollback-qualification-test
  (make-quint-model-qualification-suite
    "state-rollback"
    StateRollbackModel
    (.get ThreatModelProfiles exact-effect-host)))

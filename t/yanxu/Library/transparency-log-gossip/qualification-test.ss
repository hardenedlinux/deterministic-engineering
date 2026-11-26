;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/transparency-log-gossip/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export transparency-log-gossip-qualification-test)

(def transparency-log-gossip-qualification-test
  (make-quint-model-qualification-suite
    "transparency-log-gossip"
    TransparencyLogGossipModel
    (.get ThreatModelProfiles transparency-log-gossip)))

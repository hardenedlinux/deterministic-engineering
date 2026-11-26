;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        "../../../../library/oauth-token-lifecycle/objects.ss"
        "../../../../library/threat-model-profiles/objects.ss"
        "../../../support/quint-model-qualification.ss")
(export oauth-token-lifecycle-qualification-test)

(def oauth-token-lifecycle-qualification-test
  (make-quint-model-qualification-suite
    "oauth-token-lifecycle"
    OAuthTokenLifecycleModel
    (.get ThreatModelProfiles oauth-token-lifecycle)))

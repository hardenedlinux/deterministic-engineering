;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/identity/oauth-token-lifecycle/objects
                 OAuthTokenLifecycleModel)
        "../../../support/quint-model-qualification.ss")
(export oauth-token-lifecycle-qualification-test)

(def oauth-token-lifecycle-qualification-test
  (make-quint-model-qualification-suite "oauth-token-lifecycle" OAuthTokenLifecycleModel))

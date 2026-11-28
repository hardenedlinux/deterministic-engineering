;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/identity/oauth-revocation-recovery/objects
                 OAuthRevocationRecoveryModel)
        "../../../support/quint-model-qualification.ss")
(export oauth-revocation-recovery-qualification-test)

(def oauth-revocation-recovery-qualification-test
  (make-quint-model-qualification-suite "oauth-revocation-recovery" OAuthRevocationRecoveryModel))

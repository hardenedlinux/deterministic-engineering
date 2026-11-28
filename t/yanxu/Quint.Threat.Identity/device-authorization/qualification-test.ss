;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/identity/device-authorization/objects
                 DeviceAuthorizationModel)
        "../../../support/quint-model-qualification.ss")
(export device-authorization-qualification-test)

(def device-authorization-qualification-test
  (make-quint-model-qualification-suite "device-authorization" DeviceAuthorizationModel))

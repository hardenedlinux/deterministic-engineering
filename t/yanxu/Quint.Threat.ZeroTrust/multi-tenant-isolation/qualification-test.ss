;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/multi-tenant-isolation/objects
                 MultiTenantIsolationModel)
        "../../../support/quint-model-qualification.ss")
(export multi-tenant-isolation-qualification-test)

(def multi-tenant-isolation-qualification-test
  (make-quint-model-qualification-suite "multi-tenant-isolation" MultiTenantIsolationModel))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/plugin-grant-rollback-and-lease-confinement/objects
                 PluginGrantRollbackAndLeaseConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export plugin-grant-rollback-and-lease-confinement-qualification-test)

(def plugin-grant-rollback-and-lease-confinement-qualification-test
  (make-quint-model-qualification-suite
    "plugin-grant-rollback-and-lease-confinement"
    PluginGrantRollbackAndLeaseConfinementModel))

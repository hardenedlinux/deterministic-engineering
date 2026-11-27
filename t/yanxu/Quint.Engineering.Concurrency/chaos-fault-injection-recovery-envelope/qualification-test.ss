;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/chaos-fault-injection-recovery-envelope/objects
                 ChaosFaultInjectionRecoveryEnvelopeModel)
        "../../../support/quint-model-qualification.ss")
(export chaos-fault-injection-recovery-envelope-qualification-test)

(def chaos-fault-injection-recovery-envelope-qualification-test
  (make-quint-model-qualification-suite "chaos-fault-injection-recovery-envelope" ChaosFaultInjectionRecoveryEnvelopeModel))

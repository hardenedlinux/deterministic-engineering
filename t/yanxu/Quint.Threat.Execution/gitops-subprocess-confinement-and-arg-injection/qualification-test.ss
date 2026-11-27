;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/gitops-subprocess-confinement-and-arg-injection/objects
                 GitopsSubprocessConfinementAndArgInjectionModel)
        "../../../support/quint-model-qualification.ss")
(export gitops-subprocess-confinement-and-arg-injection-qualification-test)

(def gitops-subprocess-confinement-and-arg-injection-qualification-test
  (make-quint-model-qualification-suite
    "gitops-subprocess-confinement-and-arg-injection"
    GitopsSubprocessConfinementAndArgInjectionModel))

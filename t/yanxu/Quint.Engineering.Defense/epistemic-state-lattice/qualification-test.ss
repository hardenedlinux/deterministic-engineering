;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/epistemic-state-lattice/objects
                 EpistemicStateLatticeModel)
        "../../../support/quint-model-qualification.ss")
(export epistemic-state-lattice-qualification-test)

(def epistemic-state-lattice-qualification-test
  (make-quint-model-qualification-suite "epistemic-state-lattice" EpistemicStateLatticeModel))

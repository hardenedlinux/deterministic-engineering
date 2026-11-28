;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/defense/difc-exfiltration-fence/objects
                 DifcExfiltrationFenceModel)
        "../../../support/quint-model-qualification.ss")
(export difc-exfiltration-fence-qualification-test)

(def difc-exfiltration-fence-qualification-test
  (make-quint-model-qualification-suite "difc-exfiltration-fence" DifcExfiltrationFenceModel))

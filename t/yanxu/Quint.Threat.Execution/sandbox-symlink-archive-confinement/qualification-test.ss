;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/threat/execution/sandbox-symlink-archive-confinement/objects
                 SandboxSymlinkArchiveConfinementModel)
        "../../../support/quint-model-qualification.ss")
(export sandbox-symlink-archive-confinement-qualification-test)

(def sandbox-symlink-archive-confinement-qualification-test
  (make-quint-model-qualification-suite "sandbox-symlink-archive-confinement" SandboxSymlinkArchiveConfinementModel))

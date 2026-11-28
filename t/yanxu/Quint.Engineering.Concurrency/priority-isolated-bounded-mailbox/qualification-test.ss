;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/priority-isolated-bounded-mailbox/objects
                 PriorityIsolatedBoundedMailboxModel)
        "../../../support/quint-model-qualification.ss")
(export priority-isolated-bounded-mailbox-qualification-test)

(def priority-isolated-bounded-mailbox-qualification-test
  (make-quint-model-qualification-suite "priority-isolated-bounded-mailbox" PriorityIsolatedBoundedMailboxModel))

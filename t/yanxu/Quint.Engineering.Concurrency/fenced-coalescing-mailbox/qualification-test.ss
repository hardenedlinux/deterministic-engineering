;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/fenced-coalescing-mailbox/objects
                 FencedCoalescingMailboxModel)
        "../../../support/quint-model-qualification.ss")
(export fenced-coalescing-mailbox-qualification-test)

(def fenced-coalescing-mailbox-qualification-test
  (make-quint-model-qualification-suite "fenced-coalescing-mailbox" FencedCoalescingMailboxModel))

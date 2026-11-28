;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/hybrid-webview-focus-lifecycle/objects
                 HybridWebViewFocusLifecycleModel)
        "../../../support/quint-model-qualification.ss")
(export hybrid-webview-focus-lifecycle-qualification-test)

(def hybrid-webview-focus-lifecycle-qualification-test
  (make-quint-model-qualification-suite "hybrid-webview-focus-lifecycle" HybridWebViewFocusLifecycleModel))

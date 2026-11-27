;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import (only-in :deterministic-engineering/packages/quint-models/engineering/concurrency/ci-cache-soundness-and-sharding/objects
                 CiCacheSoundnessAndShardingModel)
        "../../../support/quint-model-qualification.ss")
(export ci-cache-soundness-and-sharding-qualification-test)

(def ci-cache-soundness-and-sharding-qualification-test
  (make-quint-model-qualification-suite "ci-cache-soundness-and-sharding" CiCacheSoundnessAndShardingModel))

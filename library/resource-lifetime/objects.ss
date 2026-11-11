;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Ownership is generic; concrete holders and language semantics are Profile inputs.
(import :clan/poo/object)
(export LifetimeModel)

(.def LifetimeModel
  identity: 'memory.resource-lifetime
  family: 'memory.resource-lifetime
  parent: #f
  revision: "1"
  factor-implications: '()
  rules: '((resource-transfer LIFE-BODY cbmc)
           (native-lifetime LIFE-NATIVE native))
  dependencies: '((LIFE-BODY source) (LIFE-BODY profile) (LIFE-BODY method)
                  (LIFE-NATIVE source) (LIFE-NATIVE profile) (LIFE-NATIVE method))
  invariant: "Transfer preserves unique ownership; refusal preserves both owners; release is idempotent."
  limits: "The initial Profile starts live counters at zero and checks bounded explicit transfer and normal destruction. External callers must keep counters live, preserve outstanding-token accounting and reserve increment headroom. Arbitrary caller admission, exceptions and concurrency are not proved.")

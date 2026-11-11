;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned meaning; no language asset or verifier is loaded here.
(import :clan/poo/object)
(export CapacityModel)

(.def CapacityModel
  identity: 'numeric.bounded-capacity
  family: 'numeric.bounded-capacity
  parent: #f
  revision: "1"
  factor-implications: '()
  rules: '((checked-capacity CAP-BODY cbmc)
           (capacity-client CAP-CALLER cbmc)
           (native-capacity CAP-NATIVE native))
  dependencies: '((CAP-BODY source) (CAP-BODY profile) (CAP-BODY method)
                  (CAP-CALLER source) (CAP-CALLER profile) (CAP-CALLER method)
                  (CAP-NATIVE source) (CAP-NATIVE profile) (CAP-NATIVE method))
  invariant: "Quantities share units; overflow refuses admission and preserves output."
  limits: "Representation, callers and native artifact require their own selected evidence.")

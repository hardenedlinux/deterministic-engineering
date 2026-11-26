;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :std/test
        :clan/poo/object
        (only-in :clan/poo/type validate)
        "../../../../library/bounded-capacity/types.ss"
        "../../../../library/bounded-capacity/config.ss")
(export bounded-capacity-contract-test)

(def bounded-capacity-contract-test
  (test-suite "bounded-capacity Loader owner contract"
    (test-case "Config validates sealed CatalogConfigContract and exposes numeric.bounded-capacity"
      (validate (.get CatalogConfigContract value-contract) Config)
      (check-equal? (.get Config entry identity) 'numeric.bounded-capacity)
      (check-equal? (.get Config entry family) 'numeric.bounded-capacity))))

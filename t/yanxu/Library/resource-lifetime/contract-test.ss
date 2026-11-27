;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :std/test
        (only-in :tao3k/yuanxu/testing yuanxu-test-case)
        :clan/poo/object
        (only-in :clan/poo/type validate)
        "../../../../library/resource-lifetime/types.ss"
        "../../../../library/resource-lifetime/config.ss")
(export resource-lifetime-contract-test)

(def resource-lifetime-contract-test
  (test-suite "resource-lifetime Loader owner contract"
    (yuanxu-test-case "Config validates sealed CatalogConfigContract and exposes memory.resource-lifetime"
      (validate (.get CatalogConfigContract value-contract) Config)
      (check-equal? (.get Config entry identity) 'memory.resource-lifetime)
      (check-equal? (.get Config entry family) 'memory.resource-lifetime))))

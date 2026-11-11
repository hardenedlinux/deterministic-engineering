;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :yuanxu/module-system/selection/init-syntax)

(yuanxu!
  :load-modules "../library" mode: auto profile: source-contract rename: Library
  (source-contract-profiles disable: #f)
  (bounded-capacity disable: #f)
  (resource-lifetime disable: #f)
  (evidence disable: #f)
  (backpressure-tokio-rayon disable: #t)
  (gateway-profiles disable: #t))

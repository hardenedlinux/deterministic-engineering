;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :yuanxu/module-system/selection/init-syntax)

(yuanxu!
  :load-modules "../library" mode: auto profile: rust rename: Library
  (backpressure-tokio-rayon disable: #f)
  (evidence disable: #f)
  (source-contract-profiles disable: #t)
  (gateway-profiles disable: #t))

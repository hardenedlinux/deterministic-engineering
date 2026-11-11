;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; The maintained functional configuration; consumers assign Config values.
(import :clan/poo/object)
(export Config)

(.def Config
  enable: #t
  settings:
  (.o
    timeout: 45
    safety-flags:
    '("--bounds-check" "--pointer-check"
      "--signed-overflow-check" "--unsigned-overflow-check"
      "--unwinding-assertions" "--unwind" "8")))

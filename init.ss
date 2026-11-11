;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;; Scheme ownership is flat; native Tags and Profile select the required roles.
(import :yuanxu/module-system/selection/init-syntax)

(yuanxu!
  :load-modules "./library" mode: auto profile: engineering rename: Library)

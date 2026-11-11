;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; The Profile owns the assigned configuration of its verification dependency.
(import :clan/poo/object
        (prefix-in "../source-contracts/config.ss" verification-))
(export Config)

(.def Config
  verification: verification-Config)

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object
        (prefix-in :deterministic-engineering/library/source-contracts/config defaults-))
(export Config)

(def Config
  (.o
    enable: #f
    settings: (.get defaults-Config settings)))

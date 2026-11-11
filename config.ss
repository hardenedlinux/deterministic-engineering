;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object)
(export Config)

(.def Config
  programs:
  (.o
    deterministic-engineering:
    (.o
      languages:
      (.o
        c:
        (.o
          enable: #f
          settings: (.o profile: 'capacity-body timeout: 45))
        cpp:
        (.o
          enable: #f
          settings: (.o profile: 'lifetime-body timeout: 45))))))

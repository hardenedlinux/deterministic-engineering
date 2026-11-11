;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :clan/poo/object)
(export Config)

(def Config
  (.o
    programs:
    (.o
      deterministic-engineering:
      (.o
        languages:
        (.o
          c:
          (.o
            enable: #t
            settings:
            (.o
              ;; Real C capacity/overflow and failure-state checks.
              profile: 'capacity-native
              ;; Wall-clock seconds per command; default/maximum is 45.
              timeout: 30))
          cpp:
          (.o
            enable: #t
            settings:
            (.o
              ;; Real C++ ownership transfer, refusal and destruction checks.
              profile: 'lifetime-native
              timeout: 20)))))))

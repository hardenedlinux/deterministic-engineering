;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; The maintained functional configuration; consumers assign Config values.
(import :clan/poo/object
        (only-in :clan/poo/mop validate)
        (only-in :yuanxu/configuration/json config-defaults)
        "types.ss")
(export Config resolve-config)

(.def Config
  enable: #t
  settings:
  (.o
    timeout: 45
    safety-flags:
    '("--bounds-check" "--pointer-check"
      "--signed-overflow-check" "--unsigned-overflow-check"
      "--unwinding-assertions" "--unwind" "8")))

;; Native composition supplies defaults; Examples contain only assigned values.
(def (resolve-config defaults overrides)
  (def base (validate SourceContractConfig defaults))
  (def assigned (validate SourceContractConfigOverrides overrides))
  (validate SourceContractConfig (config-defaults base assigned)))

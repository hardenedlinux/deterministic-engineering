;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
#!/usr/bin/env gxi
;;; Product construction comes entirely from the native init projection.
(import (only-in :clan/poo/object .get)
        (only-in :yuanxu/module-system/building/script defbuild-script)
        (only-in "./init.ss" deterministic-engineering.init.exports))

(defbuild-script
  ((.get deterministic-engineering.init.exports std-make-spec) '("init")))

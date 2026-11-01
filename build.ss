;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

#!/usr/bin/env gxi
;;; Native package build: use the same Core/SDK boundary as agentic-ai-lab.
(import (for-syntax
          (only-in :std/source this-source-file)
          (only-in :yuanxu/module-system/building/source-package register-module-build-source!)))
(begin-syntax
  (register-module-build-source! (path-directory (this-source-file)) 'deterministic-engineering))

(import (only-in :std/source this-source-file)
        (only-in :yuanxu/module-system/building/script defbuild-script)
        (only-in :clan/poo/object .get)
        (only-in :yuanxu/module-system/building/source-closure package-library-spec)
        (only-in "./init.ss" deterministic-engineering.init.exports))

;; Public roots are declaration data; Core walks their native import closure.
(def public-roots '("init.ss" "examples/gateway-evidence.ss" "profiles/resource-lifecycle.ss"
                    "examples/resource-lifecycle-evidence.ss" "projects/library-formation/init.ss"
                    "profiles/library-formation.ss" "examples/library-formation.ss"
                    "projects/library-formation/test.ss"
                    "scenarios/resource-lifecycle/review/interface.ss"
                    "scenarios/resource-lifecycle/review/archive.ss"
                    "examples/backpressure-reassessment-evidence.ss"))
(def retained-spec
  (package-library-spec (path-directory (this-source-file)) 'deterministic-engineering public-roots))
(def modules-spec (.get deterministic-engineering.init.exports std-make-spec))
(defbuild-script (modules-spec retained-spec))

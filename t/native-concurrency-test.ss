;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;; SPDX-License-Identifier: Apache-2.0 AND LGPL-2.1-or-later
(import :std/test
        (only-in :std/source this-source-file)
        (only-in :std/misc/process run-process))
(export native-concurrency-test)

(def (native-worker-configuration environment)
  (run-process
    (append (list "env") environment
      (list "just" "--justfile"
            (path-expand "../Justfile" (path-directory (this-source-file)))
            "--command" "gxi" "-:max-heap=2G" "-e"
            "(import :gerbil/compiler/base) (write (list (getenv \"GERBIL_BUILD_CORES\" #f) (available-build-cores)))"))
    coprocess: read))

(def native-concurrency-test
  (test-suite "Native build concurrency propagation"
    (test-case "host detection configures both frontend and backend"
      (check (native-worker-configuration '("-u" "GERBIL_BUILD_CORES"))
             => (list (number->string (##core-count)) (##core-count))))
    (test-case "an explicit caller limit reaches the native compiler"
      (check (native-worker-configuration '("GERBIL_BUILD_CORES=3"))
             => '("3" 3)))))

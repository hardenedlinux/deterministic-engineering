#!/usr/bin/env gxi
;;; -*- Gerbil -*-
(import (only-in :std/build-script defbuild-script)
        (only-in :clan/poo/object .get)
        (only-in "./init.ss" deterministic-engineering.init.exports)
        (only-in :yuanxu/module-system/building/artifacts current-build-output-directory))

;; Ordinary roots are explicit. Core projects the declared Module closure.
(def package-roots '("init" "examples/gateway-evidence" "profiles/resource-lifecycle"
                     "examples/resource-lifecycle-evidence" "projects/library-formation/init"
                     "profiles/library-formation" "examples/library-formation"))
(def (package-main spec args)
  (let ()
    (defbuild-script spec libdir: (current-build-output-directory))
    (apply main args)))
(def (main . args)
  ((.get deterministic-engineering.init.exports std-make-run) package-roots package-main args))

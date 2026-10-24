#!/usr/bin/env gxi
;;; The selected declarative Project uses Core's build projection and std/make.
(import (only-in :clan/poo/object .get)
        (only-in :std/build-script defbuild-script)
        (only-in :std/source this-source-file)
        (only-in :yuanxu/module-system/building/artifacts current-build-output-directory)
        (only-in "./projects/library-formation/init.ss"
          deterministic-engineering/projects/library-formation.init.exports))
(def roots '("projects/library-formation/init" "profiles/library-formation"
             "examples/library-formation" "dev/formation-test"))
(def (package-main spec args)
  (let ()
    (defbuild-script spec libdir: (current-build-output-directory))
    (apply main args)))
(def (main . args)
  ((.get deterministic-engineering/projects/library-formation.init.exports std-make-run)
    roots package-main args build-source: (path-expand (this-source-file))))

;;; Actual Project init build projection, with an explicit non-adjacent build owner.
(import :std/test :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in "../projects/library-formation/init.ss"
          deterministic-engineering/projects/library-formation.init.exports))
(export project-formation-build-test)
(def root (path-expand ".." (path-directory (this-source-file))))
(def selected-roots '("profiles/library-formation"))
(def project-formation-build-test
  (test-suite "Declared Project build owner"
    (test-case "native package root retains a same-package Profile target"
      (def spec ((.get deterministic-engineering/projects/library-formation.init.exports std-make-spec)
                  selected-roots build-source: (path-expand "formation-build.ss" root)))
      (check-equal? (and (member '(gxc: "profiles/library-formation") spec) #t) #t)
      (check-equal? (eq? spec
        ((.get deterministic-engineering/projects/library-formation.init.exports std-make-spec)
          selected-roots build-source: (path-expand "formation-build.ss" root))) #t))
    (test-case "the same init epoch cannot switch its build source"
      (check-exception
        ((.get deterministic-engineering/projects/library-formation.init.exports std-make-spec)
          selected-roots build-source: (path-expand "build.ss" root)) error?))
    (test-case "the same init epoch cannot switch retained ordinary roots"
      (check-exception
        ((.get deterministic-engineering/projects/library-formation.init.exports std-make-spec)
          '("profiles/library-formation" "profiles/gateway")
          build-source: (path-expand "formation-build.ss" root)) error?))))

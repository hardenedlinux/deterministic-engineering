;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Build through the package-root init using the inherited Core public API.
(import :std/test :clan/poo/object
        (only-in "../init.ss" deterministic-engineering.init.exports))
(export project-formation-build-test)
(def selected-roots '("profiles/library-formation"))
(def project-formation-build-test
  (test-suite "Package-root build projection"
    (test-case "package build retains the declared Profile and specification"
      (def spec ((.get deterministic-engineering.init.exports std-make-spec) selected-roots))
      (check-equal? (and (member '(gxc: "profiles/library-formation") spec) #t) #t)
      (check-equal? (eq? spec
        ((.get deterministic-engineering.init.exports std-make-spec) selected-roots)) #t))
    (test-case "the same init epoch cannot switch retained ordinary roots"
      (check-exception
        ((.get deterministic-engineering.init.exports std-make-spec)
          '("profiles/library-formation" "profiles/gateway")) error?))))

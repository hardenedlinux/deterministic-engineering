;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Consume the compiled package entry; the native root build checks its source.
(import :std/test
        :clan/poo/object
        (only-in :deterministic-engineering/init
                 deterministic-engineering.init.exports))
(export project-formation-build-test)
(def selected-roots '("config"))
(def project-formation-build-test
  (test-suite "Package-root build projection"
    (test-case "package build retains the declared Profile and specification"
      (def project (.get deterministic-engineering.init.exports std-make-spec))
      (def spec (project selected-roots))
      (check-equal?
        (and (member '(gxc: "library/library-formation-profiles/objects") spec) #t)
        #t)
      ;; Config is also selected by the Profile dependency graph; retain one
      ;; canonical native target rather than a second ordinary source row.
      (check-equal?
        (length (filter (lambda (target) (equal? target '(gxc: "config"))) spec))
        1)
      (check-equal? (eq? spec (project selected-roots)) #t))
    (test-case "the same init epoch cannot switch retained ordinary roots"
      (check-exception
        ((.get deterministic-engineering.init.exports std-make-spec)
          '("config" "library/library-formation-profiles/objects")) error?))))

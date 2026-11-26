;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Yuanxu Loader ownership and t/yanxu/Library/<owner>/ layout gate for deterministic-engineering.
(import :std/test
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in "../../harness/run-de-tests.ss" admit-de-test-layout!)
        (only-in "../../../init.ss" deterministic-engineering.init.exports))
(export de-loader-ownership-test)

(def tests-root (path-normalize (path-expand "../.." (path-directory (this-source-file)))))

(def de-loader-ownership-test
  (test-suite "DE init-owned Yuanxu Loader test publication and layout admission"
    (test-case "declared Loader owners discover exact t/yanxu/Library qualification files cold"
      (def root tests-root)
      (def qualification (.get deterministic-engineering.init.exports tests qualification))
      (def owners '(deterministic-engineering/library/quint-methods/interface
                    deterministic-engineering/library/storage-mvcc-ssi/interface
                    deterministic-engineering/library/tls13-0rtt-forward-secrecy/interface
                    deterministic-engineering/library/consensus-raft-commitment/interface))
      (def selected (.call qualification .select owners))
      (def graph-before (.ref/cached selected 'selected-graph))
      (check-equal? (eq? (.call selected .select owners) selected) #t)
      (def (test-files directory)
        (def path (path-expand directory root))
        (map (cut path-expand <> path) (directory-files path)))
      (check-equal? (list-sort string<? (.get selected spec))
        (list-sort string<?
          (append (test-files "yanxu/Library/quint-methods")
                  (test-files "yanxu/Library/storage-mvcc-ssi")
                  (test-files "yanxu/Library/tls13-0rtt-forward-secrecy")
                  (test-files "yanxu/Library/consensus-raft-commitment"))))
      (check (member (path-expand "yanxu/Library/quint-methods/projection-contracts-test.ss" root)
                     (.get selected spec)) ? pair?)
      (check-equal? (eq? (.get selected admit-current) (.get selected source admit-current)) #t)
      (for-each (lambda (name) (check-equal? (.slot? selected name) #f))
                '(.run .compile execution))
      ((.get selected admit-current))
      (check-equal? (eq? (.ref/cached selected 'selected-graph) graph-before) #t))

    (test-case "full admit-module-test-layout! enforces every Loader owner and rejects flat t/ suites"
      (def published (admit-de-test-layout!))
      (check (pair? published) => #t)
      (check (>= (length published) 43) => #t)
      ;; Zero stray *-test.ss files directly under t/.
      (check-equal?
        (filter (cut string-suffix? "-test.ss" <>) (directory-files tests-root))
        '()))))

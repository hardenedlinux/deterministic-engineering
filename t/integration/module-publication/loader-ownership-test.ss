;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Yuanxu Loader ownership and multi-window t/yanxu/<Mount>/<owner>/ layout gate
;;; for deterministic-engineering (Library + 5 Quint.Engineering.* + 5 Quint.Threat.*).
(import :std/test
        :clan/poo/object
        (only-in :std/source this-source-file)
        (only-in "../../harness/run-de-tests.ss" admit-de-test-layout!)
        (only-in "../../../init.ss" deterministic-engineering.init.exports))
(export de-loader-ownership-test)

(def tests-root
  (path-normalize (path-expand "../.." (path-directory (this-source-file)))))

(def de-loader-ownership-test
  (test-suite "DE init-owned Yuanxu Loader test publication and multi-window layout admission"
    (test-case "declared Loader owners across Library, Engineering, and Threat mounts discover exact qualification files cold"
      (def root tests-root)
      (def qualification (.get deterministic-engineering.init.exports tests qualification))
      (def owners
        '(deterministic-engineering/library/quint-methods/interface
          deterministic-engineering/library/quint-profiles/interface
          deterministic-engineering/packages/quint-models/engineering/storage/wal-crash-recovery/interface
          deterministic-engineering/packages/quint-models/engineering/consensus/raft-leader-commitment/interface
          deterministic-engineering/packages/quint-models/threat/identity/oauth-token-lifecycle/interface
          deterministic-engineering/packages/quint-models/threat/protocol/tls13-0rtt-forward-secrecy/interface
          deterministic-engineering/packages/quint-models/threat/execution/state-rollback/interface))
      (def selected (.call qualification .select owners))
      (def graph-before (.ref/cached selected 'selected-graph))
      (check-equal? (eq? (.call selected .select owners) selected) #t)
      (def (test-files directory)
        (def path (path-expand directory root))
        (map (cut path-expand <> path) (directory-files path)))
      (check-equal?
        (list-sort string<? (.get selected spec))
        (list-sort string<?
          (append (test-files "yanxu/Library/quint-methods")
                  (test-files "yanxu/Library/quint-profiles")
                  (test-files "yanxu/Quint.Engineering.Storage/wal-crash-recovery")
                  (test-files "yanxu/Quint.Engineering.Consensus/raft-leader-commitment")
                  (test-files "yanxu/Quint.Threat.Identity/oauth-token-lifecycle")
                  (test-files "yanxu/Quint.Threat.Protocol/tls13-0rtt-forward-secrecy")
                  (test-files "yanxu/Quint.Threat.Execution/state-rollback"))))
      (check (member (path-expand "yanxu/Library/quint-methods/projection-contracts-test.ss" root)
                     (.get selected spec))
             ? pair?)
      (check-equal? (eq? (.get selected admit-current) (.get selected source admit-current)) #t)
      (for-each (lambda (name) (check-equal? (.slot? selected name) #f))
                '(.run .compile execution))
      ((.get selected admit-current))
      (check-equal? (eq? (.ref/cached selected 'selected-graph) graph-before) #t))

    (test-case "full admit-module-test-layout! enforces every Loader owner across all 11 mounts and rejects flat t/ suites"
      (def published (admit-de-test-layout!))
      (check (pair? published) => #t)
      ;; 10 core Library modules + 37 co-located Quint models = 47 owners (52+ suites).
      (check (>= (length published) 47) => #t)
      ;; Zero stray *-test.ss files directly under t/.
      (check-equal?
        (filter (cut string-suffix? "-test.ss" <>) (directory-files tests-root))
        '()))))

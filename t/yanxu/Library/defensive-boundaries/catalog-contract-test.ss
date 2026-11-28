;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Loader-owned qualification tests for library/defensive-boundaries (C1-C4 / 10.153).
(import :std/test
        (only-in "../../../support/repo-paths.ss" resolve-repo-root)
        (only-in :tao3k/yuanxu/testing yuanxu-test-case)
        :std/source
        :clan/poo/object
        (only-in :clan/poo/type validate TypeError?)
        :deterministic-engineering/library/defensive-boundaries/types
        :deterministic-engineering/library/defensive-boundaries/objects
        :deterministic-engineering/library/defensive-boundaries/interface)
(export defensive-boundaries-catalog-contract-test)

(def repo-root
  (resolve-repo-root))

(def defensive-boundaries-catalog-contract-test
  (test-suite "defensive-boundaries C1-C4 catalog, contracts, and contrast directory closure"
    (yuanxu-test-case "catalog validates all 8 entries across P1-P4 and M1-M3 and resolves contrast dirs on disk"
      (validate DefensiveBoundariesScopeType (.get DefensiveBoundaries core exports))
      (check-equal? (length DefensiveAntiPatternCatalog) 8)
      (check-equal? (>= (length (anti-patterns-by-pathology 'P1-masking)) 2) #t)
      (check-equal? (>= (length (anti-patterns-by-pathology 'P2-misplaced)) 3) #t)
      (check-equal? (>= (length (anti-patterns-by-pathology 'P3-over-blocking)) 2) #t)
      (check-equal? (>= (length (anti-patterns-by-pathology 'P4-bloat)) 1) #t)
      (check-equal? (length DefensiveContrastSubjects) 4)
      (for-each
        (lambda (sub)
          (def dir (path-expand (.get sub relative-dir) repo-root))
          (check-equal? (file-exists? dir) #t))
        DefensiveContrastSubjects))

    (yuanxu-test-case "sealed contracts reject unknown pathology or mutability values"
      (check-exception
        (validate AntiPatternEntryType
          (.o identity: 'bad.entry
              pathology: 'P9-invented
              mutability: 'M1-immutable
              anti-pattern: "bad"
              deterministic-replacement: "good"
              enforcement-kinds: '(mechanical-type)))
        TypeError?)
      (check-exception
        (validate ContrastSubjectType
          (.o identity: 'bad.lang
              language: 'cobol
              relative-dir: "languages-engineering/cobol"
              pathologies-covered: '(P1-masking)
              verification-tool: "none"))
        TypeError?))))

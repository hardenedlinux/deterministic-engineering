;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Repository-level Yuanxu Loader test layout admission harness for deterministic-engineering.
;;; Enforces Core's admit-module-test-layout! contract: every Loader owner publishes
;;; *-test.ss suites under t/yanxu/Library/<owner>/, fixtures and cross-module integration
;;; suites stay outside the Loader test tree, and zero stray *-test.ss live directly under t/.
(import (only-in :clan/poo/object .get .call)
        (only-in :std/source this-source-file)
        (only-in :tao3k/yuanxu/module-system/source/directory module-directory-context)
        (only-in :tao3k/yuanxu/module-system/building/test-projection admit-module-test-layout!)
        (only-in "../../init.ss" deterministic-engineering.init.exports))
(export admit-de-test-layout!)

(def (admit-de-test-layout!)
  (def init (path-normalize (path-expand "../../init.ss" (path-directory (this-source-file)))))
  (def context
    (module-directory-context init
      (lambda (_) (error "test roster must leave publications cold"))
      publication-prepares-source?: #t))
  (def tests
    (.call (.get deterministic-engineering.init.exports tests qualification)
      .select (.get context loader-roots)))
  (def files (.get tests spec))
  ((.get tests admit-current))
  (admit-module-test-layout! context files
    require-owner-tests?: #t
    independent-directories:
    '("fixtures" "harness" "integration" "support")))

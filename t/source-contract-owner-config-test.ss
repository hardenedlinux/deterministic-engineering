;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :std/test
        :clan/poo/object
        :gerbil-ascent/program/session
        "support/source-contracts.ss"
        (only-in :std/error Error? Error-message)
        (only-in :std/source this-source-file)
        (only-in :std/io/tempfile call-with-temporary-directory)
        (only-in :std/misc/ports read-all-as-string)
        (only-in :yuanxu/module-system/interface yuanxu-load-modules))
(export source-contract-owner-config-test)

(def root (path-expand ".." (path-directory (this-source-file))))
(def (read-text path) (call-with-input-file path read-all-as-string))
(def (write-text path text)
  (call-with-output-file (list path: path truncate: #t) (cut display text <>)))

;; Copy the actual maintained roles, not replacement publications or relation rows.
(def (copy-directory-source source destination)
  (create-directory destination)
  (for-each
    (lambda (name)
      (when (equal? (path-extension name) ".ss")
        (copy-file (path-expand name source) (path-expand name destination))))
    (directory-files source)))

(def source-contract-owner-config-test
  (test-suite "Actual native Profile Config dependency admission"
    (test-case "source Config change refuses old owner and disables a newly admitted dependency"
      (call-with-temporary-directory "source-contract-owner-config"
        (lambda (directory)
          (copy-file (path-expand "types.ss" root) (path-expand "types.ss" directory))
          (copy-file (path-expand "gerbil.pkg" root) (path-expand "gerbil.pkg" directory))
          (def library (path-expand "library" directory))
          (create-directory library)
          (for-each
            (lambda (name)
              (copy-directory-source
                (path-expand (string-append "library/" name) root)
                (path-expand name library)))
            '("source-contracts" "source-contract-profiles" "bounded-capacity" "evidence"))
          (def examples (path-expand "examples" directory))
          (create-directory examples)
          (for-each
            (lambda (name)
              (copy-file (path-expand (string-append "examples/" name) root)
                         (path-expand name examples)))
            '("source-contracts.ss" "source-contracts-disabled.ss"))
          (def configuration (path-expand "source-contract-profiles/config.ss" library))
          (def (select-example name)
            (write-text configuration
              (string-append
                "(import :clan/poo/object (prefix-in \"../../examples/" name "\" user-))\n"
                "(export Config)\n(.def Config verification: user-Config)\n")))
          (select-example "source-contracts.ss")
          (def entry (path-expand "init.ss" directory))
          (write-text entry
            "(import :yuanxu/module-system/selection/init-syntax)\n(yuanxu! :load-modules \"./library\" mode: auto rename: Library (source-contract-profiles))\n")
          (def owner (yuanxu-load-modules entry))
          (def profile-module (.get owner modules Library source-contract-profiles))
          (def method (.get profile-module plan-library))
          ;; Native Type admission may normalize values; check their meaning.
          (check-equal? (.get method config enable)
                        (.get profile-module config verification enable))
          (check-equal? (.get method config settings safety-flags)
                        (.get profile-module config verification settings safety-flags))
          (def profile (.get profile-module profiles capacity-body))
          (def frozen-plan (.call method plan (.get method strategies cbmc) profile))
          (.call owner admit-current)
          (def selected (.get owner modules Library))
          (def catalog (.get selected bounded-capacity entry))
          (def native-profile (.get profile-module profiles capacity-native))
          (def runner (source-contract-test-support method (.get selected evidence)))
          (def implementation-root root)
          (def compiler-tools
            (.o cbmc: (getenv "SOURCE_CONTRACT_CBMC")
                goto-cc: (getenv "SOURCE_CONTRACT_GOTO_CC")
                goto-instrument: (getenv "SOURCE_CONTRACT_GOTO_INSTRUMENT")
                cc: (getenv "SOURCE_CONTRACT_CC")
                cxx: (getenv "SOURCE_CONTRACT_CXX")))
          (def input
            (.o (:: @ (.get runner input))
              scenario:
              (.o (:: @ (.get method scenario))
                root: implementation-root entry: catalog profile: native-profile)
              tools: compiler-tools
              module-owner: owner
              driver: runner))
          (def review
            ((.get runner evidence open-review)
              catalog (.o factors: (list (.get native-profile factor)))
              'configured-example
              ((.get runner snapshot) input)
              ((.get runner scopes) input 'configured-example)))
          (def result (.call input .verify (path-expand "actual-native" directory)))
          (check-equal? (hash-ref ((.get runner record) result) "outcome") "pass")
          ((.get runner register!) review (list result))
          (def frozen-query (gerbil-ascent-session-run review))
          (check-equal? (length ((.get frozen-query rows-of) 'support)) 1)
          (select-example "source-contracts-disabled.ss")
          (check-exception (.call owner admit-current) error?)
          (check-exception ((.get runner current!) result) error?)
          (check-exception ((.get runner register!) review (list result)) error?)
          (check-equal? (length ((.get frozen-query rows-of) 'support)) 1)
          (check-equal?
            (length ((.get (gerbil-ascent-session-run review) rows-of) 'witness)) 1)
          (def next-owner (yuanxu-load-modules entry))
          (def next-profile (.get next-owner modules Library source-contract-profiles))
          (def disabled (.get next-profile plan-library))
          (check-equal? (.get disabled config enable) #f)
          (.call next-owner admit-current)
          (check-exception
            (.call disabled plan (.get disabled strategies cbmc)
                   (.get next-profile profiles capacity-body))
            (lambda (failure)
              (and (Error? failure)
                   (equal? (Error-message failure)
                           "source-contract capability is disabled; no plan issued"))))
          (check-equal? (.get frozen-plan method) 'cbmc)
          (check-equal? (pair? (.get frozen-plan steps)) #t))))))

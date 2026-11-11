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
  (test-suite "Unified program Config through actual native owners"
    (test-case "C and C++ settings drive real evidence; disabling C retains history and C++ settings"
      (call-with-temporary-directory "source-contract-owner-config"
        (lambda (directory)
          (for-each
            (lambda (name)
              (copy-file (path-expand name root) (path-expand name directory)))
            '("types.ss" "config.ss" "gerbil.pkg"))
          (def library (path-expand "library" directory))
          (create-directory library)
          (for-each
            (lambda (name)
              (copy-directory-source
                (path-expand (string-append "library/" name) root)
                (path-expand name library)))
            '("source-contracts" "source-contract-profiles" "bounded-capacity"
              "resource-lifetime" "evidence"))
          (def examples (path-expand "examples" directory))
          (create-directory examples)
          (copy-file (path-expand "examples/programs.ss" root)
                     (path-expand "programs.ss" examples))
          (def configuration (path-expand "source-contract-profiles/config.ss" library))
          (def (write-configuration disabled?)
            (write-text configuration
              (string-append
                "(import :clan/poo/object (only-in :yuanxu/configuration/json config-defaults) (prefix-in \"../../config.ss\" defaults-) (prefix-in \"../../examples/programs.ss\" user-))\n(export Config)\n"
                "(.def (Config @ (config-defaults defaults-Config "
                (if disabled?
                    "(config-defaults user-Config (.o programs: (.o deterministic-engineering: (.o languages: (.o c: (.o enable: #f))))))"
                    "user-Config")
                ")))\n")))
          (write-configuration #f)
          (def entry (path-expand "init.ss" directory))
          (write-text entry
            "(import :yuanxu/module-system/selection/init-syntax)\n(yuanxu! :load-modules \"./library\" mode: auto rename: Library (source-contract-profiles))\n")
          (def owner (yuanxu-load-modules entry))
          (def selected (.get owner modules Library))
          (def profile-module (.get selected source-contract-profiles))
          (def generic-method (.get profile-module plan-library))
          (def c (.get profile-module languages c))
          (def cpp (.get profile-module languages cpp))
          (def method (.get c plan-library))
          (check-equal? (.get method config enable)
                        (.get profile-module config programs deterministic-engineering languages c enable))
          (check-equal? (.get method config settings timeout) 30)
          (check-equal? (.get cpp plan-library config settings timeout) 20)
          (check-equal? (.get method config settings safety-flags)
                        (.get generic-method config settings safety-flags))
          (def profile (.get profile-module profiles capacity-body))
          (def frozen-plan
            (.call generic-method plan (.get generic-method strategies cbmc) profile))
          (.call owner admit-current)
          ;; A downstream POO contribution is selected without a second registry.
          (def contributed
            (.o (:: @ profile-module)
              config:
              (.call profile-module configure
                (.o programs: (.o deterministic-engineering:
                  (.o languages: (.o c: (.o settings: (.o profile: 'project-capacity)))))))
              profiles: =>.+
              (.o project-capacity:
                (.o (:: @ (.get profile-module profiles capacity-native))
                  identity: 'project-capacity))))
          (check-equal? (.get contributed languages c profile identity) 'project-capacity)
          (def wrong-language
            (.cc profile-module 'config
              (.call profile-module configure
                (.o programs: (.o deterministic-engineering:
                  (.o languages: (.o c: (.o settings: (.o profile: 'lifetime-native)))))))))
          (check-exception
            (.get wrong-language languages c)
            (lambda (failure)
              (and (Error? failure)
                   (equal? (Error-message failure)
                           "engineering Profile belongs to another language"))))
          (def compiler-tools
            (.o cbmc: (getenv "SOURCE_CONTRACT_CBMC")
                goto-cc: (getenv "SOURCE_CONTRACT_GOTO_CC")
                goto-instrument: (getenv "SOURCE_CONTRACT_GOTO_INSTRUMENT")
                cc: (getenv "SOURCE_CONTRACT_CC")
                cxx: (getenv "SOURCE_CONTRACT_CXX")))
          (def implementation-root root)
          (def (run-language language catalog usage output)
            (def scoped-method (.get language plan-library))
            (def selected-profile (.get language profile))
            (def observer
              (source-contract-test-support scoped-method (.get selected evidence)))
            (def input
              (.o (:: @ (.get observer input))
                scenario:
                (.o (:: @ (.get scoped-method scenario))
                  root: implementation-root entry: catalog profile: selected-profile)
                tools: compiler-tools module-owner: owner driver: observer))
            (def review
              ((.get observer evidence open-review)
                catalog (.o factors: (list (.get selected-profile factor))) usage
                ((.get observer snapshot) input) ((.get observer scopes) input usage)))
            (def result (.call input .verify output))
            (check-equal? (hash-ref ((.get observer record) result) "outcome") "pass")
            ((.get observer register!) review (list result))
            (.o runner: observer subject: input evidence: review observation: result
                query: (gerbil-ascent-session-run review)))
          (def captured
            (run-language c (.get selected bounded-capacity entry) 'configured-c
                          (path-expand "actual-c" directory)))
          (def captured-cpp
            (run-language cpp (.get selected resource-lifetime entry) 'configured-cpp
                          (path-expand "actual-cpp" directory)))
          (check-equal? (length ((.get captured query rows-of) 'support)) 1)
          (check-equal? (length ((.get captured-cpp query rows-of) 'support)) 1)
          ;; An actual result from a 30-second context is not a 25-second receipt.
          (def budget-scope
            (.cc profile-module 'config
              (.call profile-module configure
                (.o programs: (.o deterministic-engineering:
                  (.o languages: (.o c: (.o settings: (.o timeout: 25)))))))))
          (def budget-method (.get budget-scope languages c plan-library))
          (def budget-observer
            (source-contract-test-support budget-method (.get selected evidence)))
          (def budget-subject (.cc (.get captured subject) 'driver budget-observer))
          (def old-basis ((.get captured runner basis) (.get captured subject)))
          (def new-basis ((.get budget-observer basis) budget-subject))
          (check-equal? (cdr (assoc 'source old-basis)) (cdr (assoc 'source new-basis)))
          (check-equal? (equal? (cdr (assoc 'method old-basis)) (cdr (assoc 'method new-basis))) #f)
          (def budget-profile (.get budget-scope languages c profile))
          (def budget-review
            ((.get budget-observer evidence open-review)
              (.get selected bounded-capacity entry)
              (.o factors: (list (.get budget-profile factor))) 'budget-25
              ((.get budget-observer snapshot) budget-subject)
              ((.get budget-observer scopes) budget-subject 'budget-25)))
          ((.get budget-observer register!) budget-review (list (.get captured observation)))
          (def budget-query (gerbil-ascent-session-run budget-review))
          (check-equal? ((.get budget-query rows-of) 'support) '())
          (check-equal? (pair? ((.get budget-query rows-of) 'mismatch)) #t)
          (check-equal? (length ((.get budget-query rows-of) 'witness)) 1)
          (write-configuration #t)
          (check-exception (.call owner admit-current) error?)
          (check-exception ((.get captured runner current!) (.get captured observation)) error?)
          (check-exception
            ((.get captured runner register!) (.get captured evidence)
              (list (.get captured observation))) error?)
          (check-equal? (length ((.get captured query rows-of) 'support)) 1)
          (check-equal?
            (length ((.get (gerbil-ascent-session-run (.get captured evidence)) rows-of) 'witness)) 1)
          (def next-owner (yuanxu-load-modules entry))
          (def next-profile (.get next-owner modules Library source-contract-profiles))
          (def disabled (.get next-profile languages c plan-library))
          (check-equal? (.get disabled config enable) #f)
          (check-equal? (.get disabled config settings timeout) 30)
          (check-equal? (.get disabled config settings safety-flags)
                        (.get method config settings safety-flags))
          (check-equal? (.get next-profile languages cpp config enable) #t)
          (check-equal? (.get next-profile languages cpp plan-library config settings timeout) 20)
          (check-equal? (length ((.get captured-cpp query rows-of) 'support)) 1)
          (check-equal?
            (.get (.call (.get next-profile languages cpp plan-library) plan
                    (.get next-profile languages cpp profile executor)
                    (.get next-profile languages cpp profile)) timeout)
            20)
          (check-equal? (.get frozen-plan timeout) 45)
          (.call next-owner admit-current)
          (check-exception
            (.call disabled plan (.get disabled strategies cbmc) (.get next-profile languages c profile))
            (lambda (failure)
              (and (Error? failure)
                   (equal? (Error-message failure)
                           "source-contract capability is disabled; no plan issued"))))
          (check-equal? (.get frozen-plan method) 'cbmc)
          (check-equal? (pair? (.get frozen-plan steps)) #t))))))

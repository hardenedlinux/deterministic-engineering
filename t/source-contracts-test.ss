;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import
  :std/test
  "support/source-contracts.ss"
  :clan/poo/object
  :gerbil-ascent/program/session
  (only-in :std/source this-source-file)
  (only-in :std/io/tempfile call-with-temporary-directory)
  (only-in :std/misc/ports read-all-as-string)
  (only-in :std/string/misc string-subst)
  (only-in :clan/poo/mop validate TypeError?)
  (only-in :yuanxu/poo-clos/objects poo-clos-failure?)
  (only-in :yuanxu/module-system/interface yuanxu-load-modules))
(export source-contract-positive-test source-contract-change-test source-contract-refusal-test)

(def root (path-expand ".." (path-directory (this-source-file))))
(def module-view (yuanxu-load-modules (path-expand "init.ss" root)))
(def selected (.get module-view modules Library))
(def driver
  (source-contract-test-support (.get selected source-contracts) (.get selected evidence)))
(def evidence (.get driver evidence))
(def profiles (.get selected source-contract-profiles profiles))
(def capacity (.get selected bounded-capacity entry))
(def lifetime (.get selected resource-lifetime entry))
(def tool-paths
  (.o cbmc: (getenv "SOURCE_CONTRACT_CBMC")
      goto-cc: (getenv "SOURCE_CONTRACT_GOTO_CC")
      goto-instrument: (getenv "SOURCE_CONTRACT_GOTO_INSTRUMENT")
      cc: (getenv "SOURCE_CONTRACT_CC")
      cxx: (getenv "SOURCE_CONTRACT_CXX")))
(def (rows result relation) ((.get result rows-of) relation))
(def (subject base catalog selected-profile)
  (def selected-runner driver)
  (def leaf
    (.o (:: @ (.get selected-runner input))
      root: base entry: catalog profile: selected-profile
      tools: tool-paths
      module-owner: module-view
      driver: selected-runner))
  ((.get driver basis) leaf)
  leaf)
(def (run base entry profile out)
  (.call (subject base entry profile) .verify out))
(def (session entry profile basis usage)
  ((.get evidence open-review) entry (.o factors: (list (.get profile factor)))
    usage ((.get driver snapshot) basis) ((.get driver scopes) basis usage)))
(def (write-text path text)
  (call-with-output-file (list path: path truncate: #t) (cut display text <>)))
(def (read-text path) (call-with-input-file path read-all-as-string))
(def (flat-profile profile)
  (.cc profile
    'units (map path-strip-directory (.get profile units))
    'inputs (map path-strip-directory (.get profile inputs))))
(def (copy-project base profile)
  (for-each
    (lambda (path)
      (write-text (path-expand (path-strip-directory path) base)
                  (read-text (path-expand path root))))
    (.get profile inputs)))
(def (supported? session)
  (pair? (rows (gerbil-ascent-session-run session) 'support)))

(def source-contract-positive-test
  (test-suite "Actual C/C++ source contracts through native owners"
    (test-case "contract body, independent callers, C++ lifetime and native artifact"
      (call-with-temporary-directory "source-contract-positive"
        (lambda (out)
          ;; Existing native selection publishes the actual domain and driver.
          (check-equal? (.get capacity family) 'numeric.bounded-capacity)
          (check-equal? (.get lifetime family) 'memory.resource-lifetime)
          (check-equal? (.get profiles capacity-body method) 'cbmc)
          (check-equal? (.get profiles capacity-native method) 'native)
          (for-each
            (lambda (row)
              (def entry (car row))
              (def profile (cadr row))
              (displayln "VERIFY-PROFILE " (.get profile identity))
              (def basis (subject root entry profile))
              (def review (session entry profile basis (.get profile identity)))
              (check-equal? (rows (gerbil-ascent-session-run review) 'support) '())
              (def result
                (with-catch
                  (lambda (cause)
                    (when (poo-clos-failure? cause)
                      (displayln "GENERIC-FAILURE " (.get cause code)))
                    (raise cause))
                  (lambda ()
                    (run root entry profile
                      (path-expand (symbol->string (.get profile identity)) out)))))
              (check-equal? (hash-ref ((.get driver record) result) "outcome") "pass")
              ((.get driver register!) review (list result))
              (check-equal? (length (rows (gerbil-ascent-session-run review) 'support)) 1)
              (check-equal? (rows (gerbil-ascent-session-run review) 'pending) '()))
            (list (list capacity (.get profiles capacity-contract))
                  (list capacity (.get profiles capacity-body))
                  (list capacity (.get profiles capacity-callers))
                  (list capacity (.get profiles capacity-native))
                  (list lifetime (.get profiles lifetime-body))
                  (list lifetime (.get profiles lifetime-native))
                  ;; A descendant uses the inherited generic method, without a
                  ;; method-name switch or a second driver implementation.
                  (list capacity
                    (.cc (.get profiles capacity-body) 'identity 'derived-cbmc
                      'executor (.o (:: @ (.get driver strategies cbmc))
                                  identity: 'derived-cbmc))))))))))

(def source-contract-change-test
  (test-suite "Cross-usage reuse and source mutation"
    (test-case "shared witness, new source capture, late registration and frozen query"
      (call-with-temporary-directory "source-contract-change"
        (lambda (base)
          (copy-project base (.get profiles capacity-body))
          (def profile (flat-profile (.get profiles capacity-body)))
          (def basis (subject base capacity profile))
          (def first (session capacity profile basis 'parser-project))
          (def second (session capacity profile basis 'pool-project))
          (def result (run base capacity profile (path-expand "initial" base)))
          ((.get driver register!) first (list result))
          ((.get driver register!) second (list result))
          (check-equal? (and (supported? first) (supported? second)) #t)
          (def frozen (gerbil-ascent-session-run first))
          (def source (path-expand "capacity.c" base))
          (def original (read-text source))
          (write-text source (string-append original "\n/* Comment-only new revision. */\n"))
          (check-exception ((.get driver current!) result) error?)
          (check-exception ((.get driver register!) first (list result)) error?)
          (def changed (subject base capacity profile))
          (gerbil-ascent-session-replace-source! first 'scope
            ((.get driver scopes) changed 'parser-project))
          (def stale (gerbil-ascent-session-run first))
          (check-equal? (rows stale 'support) '())
          (check-equal? (pair? (rows stale 'mismatch)) #t)
          (check-equal? (length (rows stale 'witness)) 1)
          (check-equal? (length (rows frozen 'support)) 1)
          ;; New implementation evidence is actually rerun, not relabeled.
          (def refreshed (run base capacity profile (path-expand "refreshed" base)))
          ((.get driver register!) first (list refreshed))
          (check-equal? (supported? first) #t)
          (check-equal? (length (rows (gerbil-ascent-session-run first) 'witness)) 2)
          (check-equal? (length (rows frozen 'support)) 1))))))

(def source-contract-refusal-test
  (test-suite "Independent negative controls preserve opposing evidence"
    (test-case "real source mutant yields a counter; shape and missing-property forgery refuse"
      (call-with-temporary-directory "source-contract-refusal"
        (lambda (base)
          (copy-project base (.get profiles capacity-body))
          (def profile (flat-profile (.get profiles capacity-body)))
          (def source (path-expand "capacity.c" base))
          (write-text source
            (string-subst (read-text source)
              "payload > UINT32_MAX - overhead" "0"))
          (def basis (subject base capacity profile))
          (def review (session capacity profile basis 'mutant))
          (def failed (run base capacity profile (path-expand "counter" base)))
          (check-equal? (hash-ref ((.get driver record) failed) "outcome") "fail")
          ((.get driver register!) review (list failed))
          (def queried (gerbil-ascent-session-run review))
          (check-equal? (length (rows queried 'counter)) 1)
          (check-equal? (rows queried 'support) '())
          (check-equal? (rows queried 'pending) '((mutant CAP-BODY cbmc)))
          ;; Plain serialized output cannot acquire private issuer authority.
          (check-exception ((.get driver register!) review
                            (list ((.get driver record) failed))) error?)
          (check-exception (subject base capacity (.cc profile 'language 'rust)) TypeError?)
          (check-exception (subject base capacity (.cc profile 'obligation 'FOREIGN)) error?)
          (check-exception (subject base capacity (.cc profile 'inputs '())) error?)
          (check-exception
            (run base capacity
              (.cc profile 'executor
                (.o identity: 'unregistered method: 'cbmc requires-properties?: #t))
              (path-expand "unknown-executor" base))
            poo-clos-failure?)
          (check-exception (run base capacity
                             (.cc profile 'expected-properties '("absent.oracle"))
                             (path-expand "missing-property" base)) error?)
          ;; Changing a result log after issuance prevents registration.
          (write-text (path-expand "counter/cbmc.log" base) "[]")
          (check-exception ((.get driver register!) review (list failed)) error?)
          (check-equal? (length (rows queried 'counter)) 1))))))

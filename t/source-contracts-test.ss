;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import
  :std/test
  (only-in :std/error Error? Error-message)
  "support/source-contracts.ss"
  :clan/poo/object
  (prefix-in "../library/source-contracts/config.ss" declared-)
  :gerbil-ascent/program/session
  (only-in :std/source this-source-file)
  (only-in :std/io/tempfile call-with-temporary-directory)
  (only-in :std/misc/ports read-all-as-string)
  (only-in :std/string/misc string-subst)
  (only-in :clan/poo/mop validate TypeError?)
  (only-in :yuanxu/poo-clos/objects poo-clos-failure?)
  (only-in :yuanxu/module-system/interface yuanxu-load-modules))
(export source-contract-positive-test source-contract-change-test
        source-contract-refusal-test source-contract-cross-project-test
        source-contract-scenario-test source-contract-tool-closure-test)

(def (stage label)
  (displayln "SOURCE-CONTRACT-STAGE " label)
  (force-output))

(stage 'imports-ready)
(def root (path-expand ".." (path-directory (this-source-file))))
(stage 'prepare-module-view)
(def module-view (yuanxu-load-modules (path-expand "t/support/source-contract-modules.ss" root)))
(stage 'prepare-selected)
(def selected (.get module-view modules Library))
(stage 'prepare-plan-library)
(def profile-library (.get selected source-contract-profiles))
(def plan-library (.get profile-library plan-library))
(stage 'prepare-evidence-library)
(def evidence-library (.get selected evidence))
(stage 'prepare-driver)
(def driver (source-contract-test-support plan-library evidence-library))
(stage 'prepare-evidence)
(def evidence (.get driver evidence))
(stage 'prepare-profiles)
(def profiles (.get profile-library profiles))
(stage 'prepare-capacity)
(def capacity (.get selected bounded-capacity entry))
(stage 'prepare-lifetime)
(def lifetime (.get selected resource-lifetime entry))
(stage 'selected-domains-ready)
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
      scenario:
      (.o (:: @ (.get selected-runner plan-library scenario))
        root: base entry: catalog profile: selected-profile)
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
          (check-exception (subject #f capacity profile) TypeError?)
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
          (check-equal? (length (rows queried 'counter)) 1))))
    (test-case "occupied C++ transfer cannot drop a live source on refusal"
      (call-with-temporary-directory "source-contract-lifetime-counter"
        (lambda (base)
          (copy-project base (.get profiles lifetime-body))
          (def profile (flat-profile (.get profiles lifetime-body)))
          (def source (path-expand "slot.hpp" base))
          (def original (read-text source))
          (def mutant
            (string-subst original
              "if (destination.owns())\n      return false;"
              "if (destination.owns()) {\n      live_ = nullptr;\n      return false;\n    }"))
          (check-equal? (equal? original mutant) #f)
          (write-text source mutant)
          (def basis (subject base lifetime profile))
          (def review (session lifetime profile basis 'occupied-lifetime-mutant))
          (def failed (run base lifetime profile (path-expand "counter" base)))
          (check-equal? (hash-ref ((.get driver record) failed) "outcome") "fail")
          ((.get driver register!) review (list failed))
          (def queried (gerbil-ascent-session-run review))
          (check-equal? (length (rows queried 'counter)) 1)
          (check-equal? (rows queried 'support) '())
          (check-equal? (rows queried 'pending)
                        '((occupied-lifetime-mutant LIFE-BODY cbmc))))))))

;; These are independent native consumer declarations over the same actual
;; Library and verified implementation, not two labels on one prepared view.
(def (consumer-context directory)
  (create-directory directory)
  (write-text (path-expand "gerbil.pkg" directory)
    (object->string (list package: (string->symbol (path-strip-directory directory)))))
  (def example (read-text (path-expand "t/support/source-contract-modules.ss" root)))
  (def declaration
    (string-subst example "\"../../library\""
      (object->string (path-expand "library" root))))
  (write-text (path-expand "init.ss" directory) declaration)
  (def selected-owner (yuanxu-load-modules (path-expand "init.ss" directory)))
  (def modules (.get selected-owner modules Library))
  (def profile-module (.get modules source-contract-profiles))
  (def runner
    (source-contract-test-support (.get profile-module plan-library) (.get modules evidence)))
  (.o owner: selected-owner
      driver: runner
      entry: (.get modules bounded-capacity entry)
      profile: (flat-profile (.get profile-module profiles capacity-body))))

(def (consumer-subject context source-root)
  (def runner (.get context driver))
  (.o (:: @ (.get runner input))
    scenario:
    (.o (:: @ (.get runner plan-library scenario))
      root: source-root
      entry: (.get context entry)
      profile: (.get context profile))
    tools: tool-paths
    module-owner: (.get context owner)
    driver: runner))

(def (consumer-review context basis usage)
  (def runner (.get context driver))
  ((.get runner evidence open-review)
    (.get context entry) (.o factors: (list (.get context profile factor)))
    usage ((.get runner snapshot) basis) ((.get runner scopes) basis usage)))

(def source-contract-cross-project-test
  (test-suite "Real independent consumer contexts share one verified subject"
    (test-case "two user declarations reuse one witness and retain separate source guards"
      (call-with-temporary-directory "source-contract-projects"
        (lambda (workspace)
          (def source-root (path-expand "shared-subject" workspace))
          (create-directory source-root)
          (copy-project source-root (.get profiles capacity-body))
          (def parser (consumer-context (path-expand "parser" workspace)))
          (def pool (consumer-context (path-expand "pool" workspace)))
          (check-equal? (eq? (.get parser owner) (.get pool owner)) #f)
          (def parser-basis (consumer-subject parser source-root))
          (def pool-basis (consumer-subject pool source-root))
          (check-equal? ((.get parser driver snapshot) parser-basis)
                        ((.get pool driver snapshot) pool-basis))
          (def parser-review (consumer-review parser parser-basis 'parser-project))
          (def pool-review (consumer-review pool pool-basis 'pool-project))
          (def result (.call parser-basis .verify (path-expand "verified" workspace)))
          ((.get parser driver register!) parser-review (list result))
          ((.get pool driver register!) pool-review (list result))
          (check-equal? (and (supported? parser-review) (supported? pool-review)) #t)
          (def frozen (gerbil-ascent-session-run pool-review))
          (check-equal? (length (rows frozen 'witness)) 1)
          ;; A changed consumer selection is not a current target context.
          (def pool-init (path-expand "pool/init.ss" workspace))
          (write-text pool-init (string-append (read-text pool-init) "\n; New consumer revision.\n"))
          (check-exception (.call (.get pool owner) admit-current) error?)
          (check-equal? (length (rows frozen 'support)) 1)
          ;; Its sibling remains current; a shared subject mutation then
          ;; invalidates the actual issued result for every new registration.
          (.call (.get parser owner) admit-current)
          (def implementation (path-expand "capacity.c" source-root))
          (write-text implementation
            (string-append (read-text implementation) "\n/* New subject revision. */\n"))
          (check-exception ((.get parser driver current!) result) error?)
          (check-exception ((.get pool driver register!) pool-review (list result)) error?)
          (check-equal? (length (rows frozen 'support)) 1))))))

(def source-contract-scenario-test
  (test-suite "Declarative Library Scenario boundary"
    (test-case "imported Config and plain assignment drive the native plan"
      (def direct-value declared-Config)
      (def assigned-value
        (.o enable: #t settings: (.get direct-value settings)))
      (validate (.get plan-library config-type) direct-value)
      (validate (.get plan-library config-type) assigned-value)
      (def partial (.call plan-library configure (.o settings: (.o timeout: 30))))
      (check-equal? (.get partial enable) #t)
      (check-equal? (.get partial settings timeout) 30)
      (check-equal? (.get partial settings safety-flags) (.get direct-value settings safety-flags))
      (check-equal? (.get (.call plan-library configure (.o)) settings timeout) 45)
      (def partial-scope (.cc plan-library 'config partial))
      (check-equal?
        (.get (.call partial-scope plan (.get plan-library strategies cbmc)
                     (.get profiles capacity-body)) timeout)
        30)
      (for-each
        (lambda (invalid)
          (check-exception (.call plan-library configure invalid) TypeError?))
        (list (.o settings: (.o timeout: 46))
              (.o settings: (.o timeout: 0))
              (.o settings: (.o safety-flags: '()))
              (.o settings: (.o timout: 30))
              (.o enabled: #f)))
      (def assigned-scope (.cc plan-library 'config assigned-value))
      (def plan
        ((.get assigned-scope plan)
          (.get plan-library strategies cbmc) (.get profiles capacity-body)))
      (check-equal? (.get plan method) 'cbmc)
      (check-equal? (and (member "--bounds-check" (.get (car (.get plan steps)) arguments)) #t) #t)
      (for-each
        (lambda (invalid)
          (check-exception (validate (.get plan-library config-type) invalid) TypeError?))
        (list (.o enable: 'yes settings: (.get direct-value settings))
              (.o enable: #t settings: (.o timeout: 180 safety-flags: '()))
              (.cc direct-value 'enabled #t)
              (.o enable: #t)
              (.o enable: #t
                  settings: (.cc (.get direct-value settings) 'timeout-seconds 45))))
      (check-exception
        (validate (.get profile-library config-type)
          (.cc (.get profile-library config)
            'verfication (.get profile-library config programs)))
        TypeError?)
      (call-with-temporary-directory "source-contract-disabled"
        (lambda (directory)
          (def disabled-scope
            (.cc plan-library 'config
              (.o enable: #f settings: (.get direct-value settings))))
          (def disabled-driver (.cc driver 'plan-library disabled-scope))
          (def implementation-root root)
          (def input
            (.o (:: @ (.get disabled-driver input))
              scenario:
              (.o (:: @ (.get disabled-scope scenario))
                root: implementation-root entry: capacity profile: (.get profiles capacity-body))
              tools: tool-paths
              module-owner: module-view
              driver: disabled-driver))
          (def output (path-expand "must-not-exist" directory))
          (check-exception
            (.call input .verify output)
            (lambda (failure)
              (and (Error? failure)
                   (equal? (Error-message failure)
                           "source-contract capability is disabled; no plan issued"))))
          (check-equal? (file-exists? output) #f))))
    (test-case "Scenario validation does not capture source or run a tool"
      (call-with-temporary-directory "source-contract-declaration"
        (lambda (directory)
          (def absent (path-expand "not-created" directory))
          (def declaration
            (.o (:: @ (.get plan-library scenario))
              root: absent
              entry: capacity
              profile: (.get profiles capacity-body)))
          (def admitted (validate (.get plan-library contracts scenario) declaration))
          (check-equal? (.get admitted root) absent)
          (check-equal? (file-exists? absent) #f)
          (check-equal? (.slot? declaration 'tools) #f)
          (check-equal? (.slot? declaration '.verify) #f)
          ;; A derived scope must use its final Config, never a captured policy.
          (def invalid-policy-scope
            (.o (:: @ plan-library)
              config: (.o enable: #t settings: (.o timeout: 45 safety-flags: '()))))
          (check-exception
            ((.get invalid-policy-scope plan)
              (.get plan-library strategies cbmc)
              (.get profiles capacity-body))
            TypeError?)
          (for-each
            (lambda (profile)
              (check-exception
                (validate (.get plan-library contracts scenario)
                          (.cc declaration 'profile profile))
                TypeError?))
            (list (.cc (.get profiles capacity-body) 'method 'native)
                  (.cc (.get profiles capacity-body) 'enforce "foreign_function")
                  (.cc (.get profiles capacity-body) 'obligation 'FOREIGN)
                  (.cc (.get profiles capacity-body) 'inputs '())
                  (.cc (.get profiles capacity-body) 'inputs '("omitted-unit.c"))
                  (.cc (.get profiles capacity-body) 'expected-properties '())))
          (check-exception
            (validate (.get plan-library contracts scenario)
                      (.cc declaration 'entry (.o identity: 'unadmitted)))
            TypeError?))))))


(def source-contract-tool-closure-test
  (test-suite "Actual tool dependency closure"
    (test-case "unused tool changes preserve a native witness; compiler changes refuse reuse"
      (for-each
        (lambda (row)
          (def profile (.ref profiles (car row)))
          (check-equal?
            (.get (.call plan-library plan (.get profile executor) profile) external-tools)
            (cadr row)))
        '((capacity-body (cbmc))
          (capacity-contract (goto-cc goto-instrument cbmc))
          (capacity-callers (goto-cc goto-instrument cbmc))
          (capacity-native (cc))
          (lifetime-body (cbmc))
          (lifetime-native (cxx))))
      (call-with-temporary-directory "source-contract-tool-closure"
        (lambda (directory)
          (def compiler (path-expand "compiler" directory))
          (copy-file (.get tool-paths cc) compiler)
          (def unused (path-expand "unused-cbmc" directory))
          (def selected-tools (.cc tool-paths 'cc compiler 'cbmc unused))
          (def profile (.get profiles capacity-native))
          (def input (.cc (subject root capacity profile) 'tools selected-tools))
          (def review (session capacity profile input 'native-tool-closure))
          (def result (.call input .verify (path-expand "actual-native" directory)))
          ((.get driver register!) review (list result))
          (check-equal? (supported? review) #t)
          (def frozen (gerbil-ascent-session-run review))
          ;; There was no CBMC executable here, and the native plan did not need it.
          (check-equal? (file-exists? unused) #f)
          (write-text unused "unused tool changed; this plan never invokes it\n")
          ((.get driver current!) result)
          ((.get driver register!) review (list result))
          (check-equal? (supported? review) #t)
          ;; The actually executed compiler is retained and checked by the issuer.
          (write-text compiler "replaced compiler bytes; no new result may be issued\n")
          (check-exception ((.get driver current!) result) error?)
          (check-exception ((.get driver register!) review (list result)) error?)
          (check-equal? (length (rows frozen 'support)) 1))))))

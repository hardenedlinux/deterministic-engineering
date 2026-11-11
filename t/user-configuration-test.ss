;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :std/test
        :clan/poo/object
        (only-in :clan/poo/mop validate TypeError?)
        (only-in :yuanxu/configuration/json config-defaults)
        (only-in "../library/source-contract-profiles/types.ss" ConfigType)
        (prefix-in "../config.ss" defaults-)
        (prefix-in "../examples/programs.ss" user-)
        (only-in :std/source this-source-file)
        (only-in :yuanxu/module-system/source/init module-init-intent))
(export user-configuration-test)

(def root (path-expand ".." (path-directory (this-source-file))))
(def (example-intent name)
  (def path (path-expand (string-append "t/support/" name "-modules.ss") root))
  (module-init-intent (call-with-input-file path read-all) path))
(def (decisions intent disabled?)
  (map (cut .get <> identity)
    (filter (lambda (row) (eq? (.get row disabled?) disabled?))
            (.get intent decisions))))

(def user-configuration-test
  (test-suite "Actual user declarations through native Yuanxu"
    (test-case "maintained unified Config leaves both languages inactive"
      (def configuration (validate ConfigType defaults-Config))
      (check-equal? (.get configuration programs deterministic-engineering languages c enable) #f)
      (check-equal? (.get configuration programs deterministic-engineering languages cpp enable) #f))
    (test-case "actual Example recursively overrides language settings"
      (def configuration (validate ConfigType (config-defaults defaults-Config user-Config)))
      (check-equal? (.get configuration programs deterministic-engineering languages c enable) #t)
      (check-equal? (.get configuration programs deterministic-engineering languages c settings timeout) 30)
      (check-equal? (.get configuration programs deterministic-engineering languages cpp settings profile) 'lifetime-native)
      (check-equal? (.get configuration programs deterministic-engineering languages cpp settings timeout) 20))
    (test-case "omitted siblings inherit and explicit false remains false"
      (def supplied
        (.o programs: (.o deterministic-engineering:
          (.o languages: (.o c: (.o enable: #t settings: (.o timeout: 25)))))))
      (def merged (validate ConfigType (config-defaults defaults-Config supplied)))
      (check-equal? (.get merged programs deterministic-engineering languages c settings profile) 'capacity-body)
      (check-equal? (.get merged programs deterministic-engineering languages c settings timeout) 25)
      (check-equal? (.get merged programs deterministic-engineering languages cpp enable) #f)
      (check-exception
        (validate ConfigType
          (config-defaults defaults-Config
            (.o programs: (.o deterministic-engineering:
              (.o languages: (.o c: (.o settings: (.o timout: 25))))))))
        TypeError?))
    (test-case "C/C++ internal selection selects assurance declarations and excludes application cases"
      (def intent (example-intent "source-contract"))
      (check-equal? (decisions intent #f)
                    '(source-contract-profiles))
      (check-equal? (decisions intent #t)
                    '(backpressure-tokio-rayon gateway-profiles))
      (check-equal? (map (cut .get <> mount) (.get intent windows)) '(Library))
      (check-equal? (.get (car (.get intent windows)) mode) 'auto)
      (check-equal? (.get (car (.get intent windows)) profile) 'source-contract)
      (check-equal? (andmap (cut .get <> disable-specified?) (.get intent decisions)) #t))
    (test-case "Rust internal selection has a different explicit selection over the same Library"
      (def intent (example-intent "rust-backpressure"))
      (check-equal? (decisions intent #f) '(backpressure-tokio-rayon))
      (check-equal? (decisions intent #t) '(source-contract-profiles gateway-profiles)))
    (test-case "computed enable decisions are refused instead of evaluated"
      (check-exception
        (module-init-intent
          '((yuanxu! mode: explicit
              (source-contracts disable: (error "must not execute"))))
          "init.ss")
        error?))))

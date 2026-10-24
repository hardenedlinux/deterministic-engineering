;;; -*- Gerbil -*-
(import :std/test :deterministic-engineering/init :clan/poo/object
        :deterministic-engineering/profiles/gateway
        (only-in :clan/poo/mop validate)
        (only-in :gerbil-ascent/rules/declaration rule-module-program))
(export module-design-test)
(def module-design-test
  (test-suite "Gateway publications have distinct engineering responsibilities"
    (test-case "independent Profiles bind the Library and one Scenario"
      (def domain (.get init.Modules rust-resources scope))
      (def evidence (.get init.Modules resource-evidence scope))
      (def scene (.get init.Scenarios gateway-review scope))
      (for-each (lambda (p) (validate (.ref domain 'profile-contract) p))
                (list LocalProfile Cap2Profile CacheProfile RetryProfile))
      (check-equal? (.ref LocalProfile 'capacity) 2)
      (check-equal? (.ref Cap2Profile 'capacity) 4)
      (check-equal? (.ref Cap2Profile 'queue) (.ref LocalProfile 'queue))
      (check-equal? (.ref CacheProfile 'cache-bytes) 128)
      (check-equal? (.ref LocalProfile 'cache-bytes) 0)
      (check-exception (validate (.ref domain 'profile-contract) (.cc LocalProfile 'capacity 0)) (lambda (_) #t))
      (check-equal? (.get scene Scenario library-key) (.get domain entry identity))
      (check-equal? (.get scene Scenario profile identity) 'C1)
      (check-equal? (.get scene Scenario profile capacity) 2)
      (check-equal? (.slot? domain 'profiles) #f)
      (check-equal? (procedure? (.ref scene 'open-review)) #t)
      (check-equal? (pair? (.ref (rule-module-program ((.ref evidence 'make-evidence))) 'rules)) #t)
      (init.build-spec '("init"))
      (init.build-current!))))

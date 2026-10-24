;;; -*- Gerbil -*-
(import :clan/poo/object
        (only-in :yuanxu/types yuanxu-predicate-contract)
        (only-in "../../library/concurrency/resource-control/backpressure-memory/rust/types.ss" RustResourcesScopeContract)
        (only-in "../../modules/resource-evidence/types.ss" ResourceEvidenceScopeContract))
(export RustResourcesScopeContract ResourceEvidenceScopeContract ScenarioScopeContract)
(def ScenarioScopeContract
  (yuanxu-predicate-contract 'gateway/scenario-scope
    (lambda (v) (and (object? v) (.slot? v 'open-review)
                     (procedure? (.ref v 'open-review))))
    (lambda (_v _c) '())))

;;; -*- Gerbil -*-
(import :clan/poo/object (only-in :yuanxu/object-types/contracts yuanxu-predicate-contract)
        (only-in "../../library/concurrency/resource-control/backpressure-memory/rust/types.ss" RustResourcesScopeContract)
        (only-in "../../modules/resource-evidence/types.ss" ResourceEvidenceScopeContract))
(export RustResourcesScopeContract ResourceEvidenceScopeContract ResourceLifecycleScopeContract)
(def ResourceLifecycleScopeContract
  (yuanxu-predicate-contract 'resource-lifecycle/scope
    (lambda (v) (and (object? v) (.slot? v 'open-review) (.slot? v 'methods)
      (.slot? v 'capture) (procedure? (.ref v 'capture)) (procedure? (.ref v 'open-review))))
    (lambda (_v _c) '())))

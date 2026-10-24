;;; -*- Gerbil -*-
(import :clan/poo/object
        (only-in :yuanxu/types yuanxu-predicate-contract))
(export ResourceEvidenceScopeContract)
(def ResourceEvidenceScopeContract
  (yuanxu-predicate-contract 'resource-evidence/scope
    (lambda (v) (and (object? v) (.slot? v 'make-evidence)
                     (procedure? (.ref v 'make-evidence))
                     (.slot? v 'open-review) (procedure? (.ref v 'open-review))))
    (lambda (_v _c) '())))

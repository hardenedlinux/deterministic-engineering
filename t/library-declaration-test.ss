;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

(import :std/test :clan/poo/object
        (only-in :clan/poo/mop validate)
        "../types.ss"
        "../library/concurrency/resource-control/backpressure-memory/abstract/types.ss"
        "../library/concurrency/resource-control/backpressure-memory/abstract/objects.ss")
(export library-declaration-test)
(def library-declaration-test
 (test-suite "Library-owned declaration metadata and Generic model"
  (test-case "version comes from the actual expected family Contract"
   (def checked (validate (.get BackpressureModelContract value-contract) BackpressureModel))
   (check-equal? (eq? (.get checked contract) BackpressureModelContract) #t)
   (check-equal? (eq? (.get checked declaration-contract) BackpressureDeclarationContract) #t)
   (check-equal? (.get checked contract declaration-contract contract-version) "V1")
   (check-equal? (.slot? checked 'contract-version) #f)
   (check-equal? (.get checked revision) "ownership-budget/v1"))
  (test-case "a submitted generation or descriptor cannot choose validation"
   (check-exception (validate (.get BackpressureModelContract value-contract)
     (.cc BackpressureModel 'contract-version "V2")) error?)
   (check-exception (validate (.get BackpressureModelContract value-contract)
     (.cc BackpressureModel 'contract (.cc BackpressureModelContract 'identity 'forged))) error?)
   (check-exception (validate (.get BackpressureModelContract value-contract)
     (.cc BackpressureModel 'declaration-contract
       (.cc BackpressureDeclarationContract 'contract-version "V2"))) error?))
  (test-case "native closed shape refuses unknown fields without forcing them"
   (def touched 0)
   (.def (Wrong @ BackpressureModel)
    typo: (begin (set! touched (+ touched 1)) (error "unknown getter forced")))
   (check-exception (validate (.get BackpressureModelContract value-contract) Wrong) error?)
   (check-equal? touched 0))
  (test-case "semantic revision is independent; Generic parent and role remain constrained"
   (def changed (.cc BackpressureModel 'revision "ownership-budget/qualified-fixture"))
   (def checked (validate (.get BackpressureModelContract value-contract) changed))
   (check-equal? (.get checked contract declaration-contract contract-version) "V1")
   (check-exception (validate (.get BackpressureModelContract value-contract)
     (.cc BackpressureModel 'parent BackpressureModel)) error?)
   (check-exception (validate (.get BackpressureModelContract value-contract)
     (.cc BackpressureModel 'role 'policy)) error?))))

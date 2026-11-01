;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

(import :std/test :clan/poo/object
        (only-in :clan/poo/mop validate)
        "../library/drivers/rust-resources/types.ss"
        "../library/drivers/rust-resources/objects.ss"
        "../library/drivers/rust-resources/func.ss"
        "../profiles/resource-lifecycle.ss")
(export library-method-binding-test)
(def library-method-binding-test
  (test-suite "Actual method definition to Function/provider binding"
    (test-case "all four operations retain checked definitions and normalized Functions"
      (def bundle (bind-resource-methods RustMethodDefinitions))
      (for-each (lambda (key)
                  (def definition (.ref (.get bundle definitions) key))
                  (def binding (.ref (.get bundle bindings) key))
                  (check-equal? (eq? definition (.get binding definition)) #t)
                  (check-equal? (.get binding operation-name) (.get definition operation))
                  (check-equal? (eq? (.get binding operation) (.ref (.get bundle operations) key)) #t)
                  (check-equal? (and (memq 'compiled-origins (.get definition input-demands)) #t) #t))
                '(native quint lean integration)))
    (test-case "swapped operation, false strength, missing source demand and wrong modes refuse"
      (def expected (.get ResourceMethodDefinitionContract value-contract))
      (def native (.get RustMethodDefinitions native))
      (check-exception (validate expected (.cc native 'strength 'arithmetic)) error?)
      (check-exception (validate expected (.cc native 'input-demands '(source))) error?)
      (check-exception (validate expected (.cc (.get RustMethodDefinitions quint) 'input-demands '(interpretation-source compiled-origins))) error?)
      (check-exception (validate expected (.cc native 'modes '(grant))) error?)
      (check-exception (bind-resource-methods (.cc RustMethodDefinitions 'native (.get RustMethodDefinitions lean))) error?))))

(export library-binding-inheritance-test)
(def library-binding-inheritance-test
  (test-suite "Native POO binding refinement"
    (test-case "a refined definition changes dispatch after the original operation was read"
      (def bundle (bind-resource-methods RustMethodDefinitions))
      (def original (.get bundle bindings native))
      (def held (.get original operation))
      (def quint (.get RustMethodDefinitions quint))
      (def selected (.o (:: @ (.get original definition))
                        operation: 'quint
                        model-ids: (.get quint model-ids)
                        claims: (.get quint claims)
                        assets: (.get quint assets)))
      (validate (.get ResourceMethodDefinitionContract value-contract) selected)
      (def refined (.cc original 'definition selected))
      (check-equal? (.get refined operation-name) 'quint)
      (check-equal? (.get original operation-name) 'native)
      (check-equal? (eq? (.get original operation) held) #t)
      (check-equal? (eq? (.get refined current!) (.get bundle operations current!)) #t)
      (check-exception
       ((.get refined operation) "" LifecycleProfile "tool" "out") error?))))

(import :std/test :clan/poo/object
 (only-in :clan/poo/mop validate)
 "../library/concurrency/resource-control/backpressure-memory/rust/types.ss"
 "../library/concurrency/resource-control/backpressure-memory/rust/objects.ss"
 "../library/concurrency/resource-control/backpressure-memory/rust/func.ss")
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

;;; -*- Gerbil -*-
(import
  :clan/poo/object
  (only-in :clan/poo/mop validate map-object-values)
  "types.ss"
  "methods.ss"
  "oracle.ss")
(export
  bind-resource-methods)
(def ResourceUtilities
  (.o
    native-context: resource-native-context
    context-current!: resource-context-current!
    integration-scopes: resource-integration-scopes
    native-oracle: resource-native-oracle
    native-scopes: resource-native-scopes
    scopes: resource-real-scopes
    register: resource-register-results!
    record: resource-result-record
    id: resource-result-id
    reference: resource-result-reference
    claim: resource-result-claim
    current!: resource-result-current!
    file-digest: resource-digest-file
    value-digest: resource-digest-value
    write-json: resource-write-json))

(def (current-result-set! results)
  (for-each resource-result-current! results)
  results)

;; The only operation-to-implementation association. No model meaning lives here.
(def MethodImplementations
  (.o
    native: (.o run: resource-run-native current!: current-result-set!)
    quint: (.o run: resource-run-qnt current!: resource-result-current!)
    lean: (.o run: resource-run-lean current!: resource-result-current!)
    integration: (.o run: resource-run-integration current!: current-result-set!)))

(.def ResourceMethodBinding.
  definition: (error "A method binding requires its admitted definition")
  provider: 'rust-resources
  operation-name: (.get definition operation)
  operation: (validate (.get definition signature)
               (.get (.ref MethodImplementations operation-name) run))
  current!: (.get (.ref MethodImplementations operation-name) current!))

(def (bind-resource-methods expected-definitions)
  (def selected-definitions (validate ResourceMethodDefinitionsShape expected-definitions))
  (def (bind-entry row)
    (def key (car row))
    (def definition-value (cdr row))
    (unless (eq? (.get definition-value operation) key)
      (error "method definition/operation mismatch" key))
    (cons key (.o (:: @ ResourceMethodBinding.) definition: definition-value)))
  (def selected-bindings
    (object<-alist (map bind-entry (.alist selected-definitions))))
  (def selected-operations
    (.+
      ResourceUtilities
      (map-object-values (lambda (binding) (.get binding operation)) selected-bindings)))
  (.o
    definitions: selected-definitions
    bindings: selected-bindings
    operations: selected-operations))

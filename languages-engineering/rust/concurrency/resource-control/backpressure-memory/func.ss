;;; -*- Gerbil -*-
(import
  :clan/poo/object
  (only-in :clan/poo/mop validate map-object-values)
  "./types.ss"
  "./objects.ss"
  "./methods.ss"
  "./oracle.ss")
(export
  ResourceMethods
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

(def (bind-resource-methods expected-definitions)
  (def selected-definitions (validate ResourceMethodDefinitionsShape expected-definitions))
  (def (binding key implementation)
    (def definition-value (.ref selected-definitions key))
    (unless (eq? (.get definition-value operation) key)
      (error "method definition/operation mismatch" key))
    (def checked-operation (validate (.get definition-value signature) implementation))
    (.o
      definition: definition-value
      provider: 'rust-resources
      operation-name: key
      operation: checked-operation
      current!: (if (memq key '(native integration))
                    (lambda (results) (for-each resource-result-current! results) results)
                    resource-result-current!)))
  (def selected-bindings
    (.o
      native: (binding 'native resource-run-native)
      quint: (binding 'quint resource-run-qnt)
      lean: (binding 'lean resource-run-lean)
      integration: (binding 'integration resource-run-integration)))
  (def selected-operations
    (.+
     ResourceUtilities
     (map-object-values (lambda (binding) (.get binding operation)) selected-bindings)))
  (.o
    definitions: selected-definitions
    bindings: selected-bindings
    operations: selected-operations))
(def DefaultMethods (bind-resource-methods RustMethodDefinitions))
(def ResourceMethods (.get DefaultMethods operations))

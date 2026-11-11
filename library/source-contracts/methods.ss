;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure verification-plan declarations. Consumers own execution and evidence issuance.
(import
  :clan/poo/object
  (only-in :clan/poo/mop validate)
  (only-in :yuanxu/poo-clos/generic-syntax .defgeneric .defmethod)
  "types.ss"
  "objects.ss")
(export contract-plan)

(.defgeneric verification-steps (executor profile policy))
(.defgeneric instrumentation-steps (instrumentation profile))

(.defmethod (instrumentation-steps
              (instrumentation (prototype DirectContract.)) profile)
  (.o steps: '() solver-inputs: '(sources)))

;; Replacement inherits this method; its native prototype supplies the option.
(.defmethod (instrumentation-steps
              (instrumentation (prototype CheckedContract.)) profile)
  (.o
    steps:
    (list
      (.o tool: 'goto-cc
          arguments: (list "-D__CPROVER" "--function" (.get profile function)
                           "-o" 'raw-module 'sources)
          expected: 'zero
          artifacts: '(raw-module))
      (.o tool: 'goto-instrument
          arguments: (list "--dfcc" (.get profile function)
                           (.get instrumentation option) (.get profile enforce)
                           'raw-module 'checked-module)
          expected: 'zero
          artifacts: '(checked-module)))
    solver-inputs: '(checked-module)))

(.defmethod (verification-steps (executor (prototype CbmcExecutor.)) profile policy)
  (def preparation
    (instrumentation-steps (.get profile instrumentation) profile))
  (append
    (.get preparation steps)
    (list
      (.o tool: 'cbmc
          arguments:
          (append (.get preparation solver-inputs)
                  (.get profile language verifier-flags)
                  (list "--function" (.get profile function) "--json-ui")
                  (.get policy safety-flags))
          expected: 'solver
          artifacts: '()))))

(.defmethod (verification-steps (executor (prototype NativeExecutor.)) profile policy)
  (list
    (.o tool: (.get profile language compiler-key)
        arguments: (list (.get profile language native-standard)
                         "-Wall" "-Wextra" "-Werror" "-o" 'native-binary 'sources)
        expected: 'zero
        artifacts: '(native-binary))
    (.o tool: 'native-binary
        arguments: '()
        expected: 'zero
        artifacts: '())))

(def (contract-plan configuration executor profile)
  (def selected-config (validate SourceContractConfig configuration))
  (unless (.get selected-config enable)
    (error "source-contract capability is disabled; no plan issued"))
  (def selected-policy (.get selected-config settings))
  (def selected-profile (validate SourceContractProfile profile))
  (unless (eq? (.get selected-profile method) (.get executor method))
    (error "Profile and executor declare different methods"))
  (unless (eq? (.get selected-profile instrumentation requires-function?)
               (not (string=? (.get selected-profile enforce) "")))
    (error "Profile and instrumentation declare different function boundaries"))
  (.o
    kind: 'verification-plan
    obligation: (.get selected-profile obligation)
    method: (.get selected-profile method)
    steps: (verification-steps executor selected-profile selected-policy)
    external-tools:
    (foldr
      (lambda (tool names)
        (if (or (eq? tool 'native-binary) (memq tool names))
            names
            (cons tool names)))
      '()
      (map (lambda (step) (.get step tool)) steps))
    expected-properties: (.get selected-profile expected-properties)
    boundary: "A plan declares checks; it neither executes tools nor issues evidence or authority."))

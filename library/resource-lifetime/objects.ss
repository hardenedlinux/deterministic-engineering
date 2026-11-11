;;; Ownership is generic; concrete holders and language semantics are Profile inputs.
(import :clan/poo/object)
(export LifetimeModel)

(.def LifetimeModel
  identity: 'memory.resource-lifetime
  family: 'memory.resource-lifetime
  parent: #f
  revision: "1"
  factor-implications: '()
  rules: '((resource-transfer LIFE-BODY cbmc)
           (native-lifetime LIFE-NATIVE native))
  dependencies: '((LIFE-BODY source) (LIFE-BODY profile) (LIFE-BODY method)
                  (LIFE-NATIVE source) (LIFE-NATIVE profile) (LIFE-NATIVE method))
  invariant: "Transfer preserves unique ownership; refusal preserves both owners; release is idempotent."
  limits: "The initial Profile covers explicit transfer and normal destruction, not exceptions or concurrency.")

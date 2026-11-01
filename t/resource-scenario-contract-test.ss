;;; -*- Gerbil -*-
(import
  :std/test
  (only-in :clan/poo/object .o .cc .get)
  (only-in :clan/poo/mop validate TypeError? map-object-values)
  (only-in :clan/poo/type Record)
  (only-in :clan/poo/recursive-validation close-validation closed-ref)
  :deterministic-engineering/init
  (only-in :deterministic-engineering/profiles/resource-lifecycle LifecycleProfile)
  (only-in "../scenarios/resource-lifecycle/func.ss" resource-lifecycle-scope))

(export
  resource-scenario-contract-test)

(def resource-scenario-contract-test
  (test-suite "Owner-bound native Scenario method contracts"
    (test-case "revalidation retains the published Scope, owner handles and installed functions"
      (def scope (.get deterministic-engineering.init.exports Scenarios resource-lifecycle scope))
      (def contract (.get scope contracts scope))
      (def capture (.get scope capture))
      (def review (.get scope open-review))
      (check-equal? (eq? (.get scope validation) (.get (validate contract scope) validation)) #t)
      (check-equal? (eq? (validate contract scope) scope) #t)
      (check-equal? (eq? (.get (validate contract scope) capture) capture) #t)
      (check-equal? (eq? (.get (validate contract scope) open-review) review) #t)
      (check-equal? (eq? (.get scope entry) (.get scope domain entry)) #t)
      (check-equal? (eq? (.get scope methods) (.get scope domain methods)) #t))
    (test-case "a fresh producer uses the actual selected owner Contract"
      (def selected (.get deterministic-engineering.init.exports Scenarios resource-lifecycle scope))
      (def contract (.get selected contracts scope))
      (def raw
        (resource-lifecycle-scope (.get selected domain) (.get selected evidence) contract))
      ;; Exercise cached parent fields before native normalization.
      (def original-entry (.get raw entry))
      (def normalized (validate contract raw))
      (check-equal? (eq? (.get normalized domain) (.get selected domain)) #t)
      (check-equal? (eq? (.get normalized evidence) (.get selected evidence)) #t)
      (check-equal? (eq? (.get normalized entry) original-entry) #t)
      (check-equal? (eq? (validate contract normalized) normalized) #t)
      (check-exception
       (validate
        contract
        (resource-lifecycle-scope
         (.get selected domain)
         (.get selected evidence)
         (.get selected domain contracts scope)))
       TypeError?))
    (test-case "a child owner override is read after the parent fields were cached"
      (def selected (.get deterministic-engineering.init.exports Scenarios resource-lifecycle scope))
      (def contract (.get selected contracts scope))
      (def original-domain (.get selected domain))
      (def child-domain (.cc original-domain))
      (check-equal? (eq? original-domain child-domain) #f)
      (check-equal?
       (eq? (validate (.get original-domain contracts scope) child-domain) child-domain)
       #t)
      (def parent
        (resource-lifecycle-scope original-domain (.get selected evidence) contract))
      (def cached-entry (.get parent entry))
      (def cached-capture (.get parent capture))
      (def child (validate contract (.cc parent 'domain child-domain)))
      (check-equal? (eq? (.get child domain) child-domain) #t)
      (check-equal? (eq? (.get child entry) (.get child-domain entry)) #t)
      (check-equal? (eq? (.get child methods) (.get child-domain methods)) #t)
      (check-equal? (eq? (.get parent domain) original-domain) #t)
      (check-equal? (eq? (.get parent entry) cached-entry) #t)
      (check-equal? (eq? (.get parent capture) cached-capture) #t))
    (test-case "closed validation cannot mask substituted associations or methods"
      (def selected (.get deterministic-engineering.init.exports Scenarios resource-lifecycle scope))
      (def contract (.get selected contracts scope))
      (for-each
       (lambda (changed) (check-exception (validate contract changed) TypeError?))
       (list
        (.cc selected 'entry (.cc (.get selected entry) 'revision (.get selected entry revision)))
        (.cc selected 'methods (.cc (.get selected methods) 'unexpected-operation void))
        (.cc selected 'capture (lambda args 'unqualified))
        (.cc selected 'authorization #t)
        (.cc selected 'validation (.get selected domain validation)))))
    (test-case "a generic native closure cannot masquerade as Scenario normalization"
      (def selected (.get deterministic-engineering.init.exports Scenarios resource-lifecycle scope))
      (def contract (.get selected contracts scope))
      (def raw
        (.cc
            (resource-lifecycle-scope (.get selected domain) (.get selected evidence) contract)
          'capture (lambda args 'unqualified)))
      ;; This is a genuine native graph, but it checked a different descriptor.
      (def foreign-graph
        (close-validation (lambda (_reference) (list (list 'scope (Record) raw))) 1))
      (def forged
        (.cc (map-object-values identity (closed-ref foreign-graph 'scope))
          'validation foreign-graph))
      (check-exception (validate contract forged) TypeError?))
    (test-case "capture inputs refuse before the body and result checks occur after the body"
      (def selected (.get deterministic-engineering.init.exports Scenarios resource-lifecycle scope))
      (def contract (.get selected contracts scope))
      (def calls 0)
      (def raw
        (.cc
            (resource-lifecycle-scope (.get selected domain) (.get selected evidence) contract)
          'capture (lambda args (set! calls (1+ calls)) (.o))))
      (def checked (validate contract raw))
      (for-each
       (lambda (arguments)
         (check-exception (apply (.get checked capture) arguments) TypeError?))
       (list
        (list "" LifecycleProfile "crate" "cargo" "rustc" 'u)
        (list "root" (.o) "crate" "cargo" "rustc" 'u)
        (list "root" LifecycleProfile "crate" "cargo" "rustc" "u")
        (list "root" LifecycleProfile "crate" "cargo" "rustc" 'u 'unsupported)))
      (check-equal? calls 0)
      (check-exception
       ((.get checked capture) "root" LifecycleProfile "crate" "cargo" "rustc" 'u)
       TypeError?)
      (check-equal? calls 1))
    (test-case "review recognizes the selected owner's Context before calling its body"
      (def selected (.get deterministic-engineering.init.exports Scenarios resource-lifecycle scope))
      (def contract (.get selected contracts scope))
      (def calls 0)
      (def checked
        (validate
         contract
         (.cc
             (resource-lifecycle-scope (.get selected domain) (.get selected evidence) contract)
           'open-review (lambda (context) (set! calls (1+ calls)) 'not-a-session))))
      (check-exception ((.get checked open-review) (.o)) TypeError?)
      (check-equal? calls 0))))

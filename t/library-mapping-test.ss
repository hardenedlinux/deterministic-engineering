;;; Authored meaning versus historical observation: no execution receipt is issued.
(import :std/test :std/encoding/json :clan/poo/object
        (only-in :clan/poo/mop validate)
        "../library/concurrency/resource-control/backpressure-memory/abstract/objects.ss"
        "../languages-engineering/rust/concurrency/resource-control/backpressure-memory/objects.ss"
        "../languages-engineering/rust/concurrency/resource-control/backpressure-memory/types.ss"
        "../languages-engineering/rust/concurrency/resource-control/backpressure-memory/correspondence.ss")
(export library-mapping-test)
(def (integration)
 (validate (.get BackpressureIntegrationContract value-contract)
  (make-backpressure-integration (specialize-backpressure BackpressureModel))))
(def library-mapping-test
 (test-suite "Integration owns observation mapping, QNT delta and reusable catalog"
  (test-case "case links and artifact renderers consume the selected declaration"
   (def selected (integration))
   (check-equal? (.get selected mapping catalog-id) (.get selected catalog identity))
   (check-equal? (.get selected case-links) (map (cut .get <> obligations) (.get selected mapping cases)))
   (def projection (hash ("case" "M01") ("cuts" '())
      ("states" (list (hash ("stage" "waiting") ("reserved" #f))))))
   (def qnt (resource-trace-qnt selected "module Test {\n}" projection))
   (check-equal? (and (string-contains qnt "action cancelQueued") #t) #t)
   (check-equal? (and (string-contains (resource-trace-sysml selected projection) "import BackpressureOwnership::*") #t) #t)
   (def changed (.cc selected 'mapping (.cc (.get selected mapping) 'delta
     (.cc (.get selected mapping delta) 'identity 'disposeBeforeRun))))
   (check-equal? (and (string-contains (resource-trace-qnt changed "module Test {}" projection) "action disposeBeforeRun") #t) #t)
   (check-equal? (string-contains (resource-trace-sysml selected projection) "part def Ownership") #f))
  (test-case "incomplete frames, catalog mismatch and undeclared cases refuse"
   (def selected (integration))
   (def mapping (.get selected mapping))
   (check-exception (validate (.get BackpressureTraceMappingContract value-contract)
    (.cc mapping 'delta (.cc (.get mapping delta) 'frame '(limit)))) error?)
   (check-exception (validate (.get BackpressureIntegrationContract value-contract)
    (.cc selected 'catalog (.cc (.get selected catalog) 'identity 'foreign))) error?)
   (check-exception (validate (.get BackpressureTraceMappingContract value-contract)
    (.cc mapping 'transitions (cons
      (.cc (car (.get mapping transitions)) 'cases '("UNKNOWN")) (cdr (.get mapping transitions))))) error?))
  (test-case "historical native fixture retains five support paths and the reservation counter"
   (def path (getenv "LIBRARY_TRACE_FIXTURE" #f))
   (unless path (error "explicit historical native observation fixture required"))
   (def observed (call-with-input-file path (cut read-json <> object-as-hash: #t)))
   (def selected (integration))
   (def projections (resource-trace-projections selected observed))
   (check-equal? (map (cut hash-ref <> "outcome") projections) '("pass" "pass" "pass" "pass" "pass" "fail"))
   (check-equal? (map (cut hash-ref <> "mappingIdentity") projections)
     (make-list 6 (symbol->string (.get selected mapping identity))))
   (check-exception (resource-trace-projections
     (.cc selected 'mapping (.cc (.get selected mapping) 'transitions '())) observed) error?))))

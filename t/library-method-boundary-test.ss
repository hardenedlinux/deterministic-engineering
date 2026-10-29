;;; Real Ops and QNT; altered interpretation bytes invalidate an issued result.
(import :std/test :clan/poo/object
        (only-in :gerbil/expander core-resolve-library-module-path datum->syntax)
        (only-in :gerbil/runtime/loader __find-library-module)
        (only-in :std/misc/ports read-all-as-string)
        "../profiles/resource-lifecycle.ss"
        :deterministic-engineering/init)
(def ResourceMethods
  (.get deterministic-engineering.init.exports Library rust-resources scope methods))
(export library-method-boundary-test)
(def library-method-boundary-test
 (test-suite "Selected method Function and interpretation footprint boundaries"
  (test-case "selected provider resolves compiled interfaces and actual native generations"
   (def expected (getenv "LIBRARY_PROVIDER_LIB"))
   (for-each (lambda (name)
    (def interface (core-resolve-library-module-path
      (datum->syntax #f (string->symbol (string-append ":" name)))))
    (def native (__find-library-module name))
    (check-equal? (path-extension interface) ".ssi")
    (check-equal? (string-prefix? expected interface) #t)
    (check-equal? (string-prefix? expected native) #t)
    (check-equal? (string-prefix? ".o" (path-extension native)) #t)
    (displayln "PROVIDER-LOAD " name " " interface " " native))
    '("agentic-ai-lab/modules/ai-agentic-context/clue-query"
      "agentic-ai-lab/modules/ai-agentic-context/clue-exchange"
      "agentic-ai-lab/modules/temporal-causality/trajectory/ascent-ledger")))
  (test-case "invalid execution arguments refuse before process work"
   (check-exception ((.get ResourceMethods quint) "" LifecycleProfile "tool" "out") error?)
   (def fake-body-called #f)
   (def fake (.o .run: (lambda () (set! fake-body-called #t) (error "forged executor"))))
   (check-exception ((.get ResourceMethods quint) fake "root" LifecycleProfile "tool" "out") error?)
   (check-equal? fake-body-called #f)
   (check-exception ((.get ResourceMethods native) "root" "crate" "cargo" "rustc" 0 "out") error?)
   (check-exception ((.get ResourceMethods lean) "root" LifecycleProfile "tool") error?))
  (test-case "actual QNT result rejects altered declaration bytes and supports original-byte repair"
   (def root (getenv "LIBRARY_METHOD_ROOT"))
   (def tool (getenv "LIBRARY_QUINT"))
   (def out (path-expand "observation" root))
   (def result ((.get ResourceMethods quint) root LifecycleProfile tool out))
   ((.get ResourceMethods current!) result)
   (def path (path-expand "library/drivers/rust-resources/objects.ss" root))
   (def before (call-with-input-file path read-all-as-string))
   (try
    (call-with-output-file (list path: path truncate: #t)
     (lambda (port) (display before port) (display "\n;; changed declaration\n" port)))
    (check-exception ((.get ResourceMethods current!) result) error?)
    (finally (call-with-output-file (list path: path truncate: #t) (cut display before <>))))
   ((.get ResourceMethods current!) result)
   (check-equal? (hash-ref (hash-ref ((.get ResourceMethods record) result) "observation") "outcome") "pass"))))

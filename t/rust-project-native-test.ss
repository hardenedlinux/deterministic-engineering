;;; Rust inputs are executed by the admitted Scheme driver, not loaded as Modules.
(import
  :std/test
  :clan/poo/object
  :deterministic-engineering/init
  :deterministic-engineering/profiles/resource-lifecycle
  :gerbil-ascent/program/session
  (only-in :agentic-ai-lab/modules/temporal-causality/trajectory/ascent-ledger ascent-trajectory)
  (only-in :std/io/tempfile call-with-temporary-directory))
(export rust-project-native-test)

(def rust-project-native-test
  (test-suite "Rust-only project through the original native method owner"
    (test-case "six actual lifecycle observations retain the independent negative control"
      (def root (current-directory))
      (def crate
        (path-expand
          "languages-engineering/rust/concurrency/resource-control/backpressure-memory"
          root))
      (def methods
        (.get deterministic-engineering.init.exports Library rust-resources scope methods))
      (call-with-temporary-directory
        "rust-only-native"
        (lambda (directory)
          (def results
            ((.get methods native)
              root crate (getenv "RESOURCE_CARGO") (getenv "RESOURCE_RUSTC")
              64 (path-expand "observed" directory)))
          (def records (map (.get methods record) results))
          (check-equal?
            (map (lambda (record) (hash-ref (hash-ref record "observation") "obligation")) records)
            '("RL-M01" "RL-M02" "RL-M03" "RL-M04" "RL-M05" "RL-M06"))
          (check-equal?
            (map (lambda (record) (hash-ref (hash-ref record "observation") "outcome")) records)
            '("pass" "pass" "pass" "pass" "pass" "fail"))
          (for-each (.get methods current!) results)
          (def usage 'rust-only-native)
          (def scopes
            ((.get methods native-scopes)
              root crate (getenv "RESOURCE_CARGO") (getenv "RESOURCE_RUSTC") 64 usage))
          (def snapshot ((.get methods value-digest) scopes))
          (def entry
            (.get deterministic-engineering.init.exports Library rust-resources scope entry))
          (def evidence
            (.get deterministic-engineering.init.exports Library evidence scope))
          (def session
            ((.get evidence open-review) entry LifecycleProfile usage snapshot scopes))
          (def trajectory
            (hash-ref
              (ascent-trajectory
                (hash ("action" "open") ("task" "rust-only-native")
                      ("sourceIdentity" snapshot)))
              "trajectory"))
          (for-each
            (lambda (result)
              (ascent-trajectory
                (hash
                  ("action" "append") ("trajectory" trajectory)
                  ("event"
                    (hash
                      ("id" ((.get methods id) result))
                      ("kind" "evidence") ("sourceIdentity" snapshot)
                      ("resultReference" ((.get methods reference) result))
                      ("pathIdentity" ((.get methods claim) result)))))))
            results)
          ((.get methods register) session results trajectory
            (path-expand "library/drivers/evidence/func.ss" root))
          (def frozen (gerbil-ascent-session-run session))
          (def (rows result relation) ((.get result rows-of) relation))
          (check-equal? (length (rows frozen 'support)) 5)
          (check-equal? (map cadr (rows frozen 'counter)) '(RL-M06))
          (check-equal? (and (member '(rust-only-native RL-M06 native) (rows frozen 'pending)) #t) #t)
          ;; A second actual usage reuses only the same captured input bases.
          (gerbil-ascent-session-replace-sources! session
            (list
              (cons 'application (list (list 'reused snapshot (.get entry identity))))
              (cons 'factor (map (cut list 'reused <>) (.get LifecycleProfile factors)))
              (cons 'scope
                ((.get methods native-scopes)
                  root crate (getenv "RESOURCE_CARGO") (getenv "RESOURCE_RUSTC") 64 'reused))))
          (def reused (gerbil-ascent-session-run session))
          (check-equal? (length (rows reused 'support)) 5)
          (check-equal? (map cadr (rows reused 'counter)) '(RL-M06))
          (check-equal? (length (rows reused 'witness)) 6)
          (check-equal? (rows frozen 'application)
            (list (list usage snapshot (.get entry identity)))))))))

;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

(import
  :std/test
  :clan/poo/object
  "../library/drivers/project-formation/func.ss"
  "../scenarios/project-formation/func.ss"
  "../library/project-organization/objects.ss"
  "../profiles/library-formation.ss")
(export
  project-formation-test)
(def project-formation-test
  (test-suite "Declarative project formation"
    (test-case "baseline actual ASCENT consequences"
      (def result
        (reason-project-formation (formation-inputs ProjectOrganization LibraryFormationProfile)))
      (check-equal? ((.ref result 'rows-of) 'structurally_covered) '(("LIB-C01")))
      (check-equal? ((.ref result 'rows-of) 'runtime_ready) '()))))

(def (run-profile p (d ProjectOrganization))
  (reason-project-formation (formation-inputs d p)))
(def (rows r name) ((.ref r 'rows-of) name))
(def (with-candidates xs) (.cc LibraryFormationProfile 'candidates xs))
(def chosen (car (.ref LibraryFormationProfile 'candidates)))

(export
  formation-control-01-test)
(def formation-control-01-test
  (test-suite "Formation control 01"
    (test-case "independent exact conflicts and gaps"
      (def r (run-profile LibraryFormationProfile))
      (check-equal? (length (rows r 'conflict)) 8)
      (check-equal? (length (rows r 'gap)) 34)
      (check-equal? (length (rows r 'layout_node)) 9)
      (check-equal? (length (rows r 'layout_edge)) 11))))

(export
  formation-control-02-test)
(def formation-control-02-test
  (test-suite "Formation control 02"
    (test-case "candidate names do not control selection"
      (def r (run-profile (with-candidates (list (.cc chosen 'identity "another-proposal")))))
      (check-equal? (rows r 'structurally_covered) '(("another-proposal"))))))

(export
  formation-control-03-test)
(def formation-control-03-test
  (test-suite "Formation control 03"
    (test-case "missing capture cannot disappear with proposal"
      (def owners (filter (lambda (r) (not (equal? (car r) "capture"))) (.ref chosen 'owners)))
      (def r (run-profile (with-candidates (list (.cc chosen 'owners owners)))))
      (check-equal? (and (member '("LIB-C01" "role" "capture") (rows r 'gap)) #t) #t)
      (check-equal? (rows r 'structurally_covered) '()))))

(export
  formation-control-04-test)
(def formation-control-04-test
  (test-suite "Formation control 04"
    (test-case "changed confirmed intent invalidates all old proposals"
      (def r (run-profile (.cc LibraryFormationProfile 'intent "different-intent")))
      (check-equal? (length (rows r 'invalidated)) 3)
      (check-equal? (rows r 'structurally_covered) '()))))

(export
  formation-control-05-test)
(def formation-control-05-test
  (test-suite "Formation control 05"
    (test-case "multiple eligible proposals refuse model generation"
      (def r (run-profile (with-candidates (list chosen (.cc chosen 'identity "LIB-C04")))))
      (check-equal? (length (rows r 'structurally_covered)) 2)
      (check-exception (render-formation-model r) (lambda (_) #t)))))

(export
  formation-control-06-test)
(def formation-control-06-test
  (test-suite "Formation control 06"
    (test-case "independently added obligation changes outcomes"
      (def declaration
        (.cc ProjectOrganization 'duties (cons "NEW-DUTY" (.ref ProjectOrganization 'duties))))
      (def r (run-profile LibraryFormationProfile declaration))
      (check-equal? (rows r 'structurally_covered) '())
      (check-equal? (length (filter (lambda (r) (equal? (caddr r) "NEW-DUTY")) (rows r 'gap))) 3))))

(export
  formation-control-07-test)
(def formation-control-07-test
  (test-suite "Formation control 07"
    (test-case "declaratively added role extends model without changing rules"
      (def d
        (.cc ProjectOrganization
          'roles (append (.ref ProjectOrganization 'roles) '(("new-concern" "documents" "document")))))
      (def c (.cc chosen 'owners (append (.ref chosen 'owners) '(("new-concern" "documents")))))
      (def p
        (.cc (with-candidates (list c)) 'layout
             (append
              (.ref LibraryFormationProfile 'layout)
              '(("new-concern" "newConcern" "NewConcern" "products::explanation")))))
      (def r (run-profile p d))
      (check-equal? (length (rows r 'layout_node)) 10)
      (check-equal?
       (and
        (member
         '("LIB-C01" "newConcern" "NewConcern" "documents" "products::explanation")
         (rows r 'layout_node))
        #t)
       #t)
      (check-equal? (string? (render-formation-model r)) #t))))

(export
  formation-control-08-test)
(def formation-control-08-test
  (test-suite "Formation control 08"
    (test-case "empty demand and duplicate candidate identity refused"
      (check-exception
       (run-profile LibraryFormationProfile (.cc ProjectOrganization 'roles '()))
       (lambda (_) #t))
      (check-exception (run-profile (with-candidates (list chosen chosen))) (lambda (_) #t))
      (check-exception
       (run-profile
        (.cc LibraryFormationProfile 'dependencies '(("unknown-edge" "unknown-role" "definitions"))))
       (lambda (_) #t)))))

(export
  formation-control-09-test)
(def formation-control-09-test
  (test-suite "Formation control 09"
    (test-case "incompatible owner retained and no root materialized"
      (def c
        (.cc chosen 'owners (map (lambda (r) (if (equal? (car r) "capture") '("capture" "library") r)) (.ref chosen 'owners))))
      (def r (run-profile (with-candidates (list c))))
      (check-equal? (length (rows r 'conflict)) 2)
      (check-exception (render-formation-model r) (lambda (_) #t)))))

(export
  formation-control-10-test)
(def formation-control-10-test
  (test-suite "Formation control 10"
    (test-case "declared capability conditions and contradictory status"
      (def caps
        (map (lambda (k) (list k "established")) (.ref ProjectOrganization 'required-capabilities)))
      (def positive (.cc chosen 'capabilities caps))
      (def reported (run-profile (with-candidates (list positive))))
      (check-equal? (rows reported 'declared_ready) '(("LIB-C01")))
      (check-equal? (rows reported 'runtime_ready) '())
      (check-equal? (rows reported 'runtime_blocked) '(("LIB-C01")))
      (def mixed (.cc positive 'capabilities (cons '("source-load" "stale") caps)))
      (check-equal? (rows (run-profile (with-candidates (list mixed))) 'runtime_ready) '()))))

(export
  formation-control-11-test)
(def formation-control-11-test
  (test-suite "Formation control 11"
    (test-case "actual Program coverage rejects omitted empty, duplicate and foreign sources"
      (def batch (formation-inputs ProjectOrganization LibraryFormationProfile))
      (check-exception
       (reason-project-formation (filter (lambda (r) (not (eq? (car r) 'declared_capability))) batch))
       error?)
      (check-exception (reason-project-formation (cons (car batch) batch)) error?)
      (check-exception (reason-project-formation (cons '(uncontrolled) (cdr batch))) error?))))

(export
  formation-control-12-test)
(def formation-control-12-test
  (test-suite "Formation control 12"
    (test-case "public rows own string cells on every read"
      (def result (run-profile LibraryFormationProfile))
      (def first (rows result 'structurally_covered))
      (string-set! (caar first) 0 #\X)
      (check-equal? (rows result 'structurally_covered) '(("LIB-C01")))
      (def bindings ((.ref result 'output-bindings)))
      (set-car! bindings '(foreign . foreign))
      (check-equal? (assq 'foreign ((.ref result 'output-bindings))) #f)
      (check-equal?
       (assq 'declared_blocked ((.ref result 'output-bindings)))
       '(declared_blocked . declared_blocked)))))

(export
  formation-control-13-test)
(def formation-control-13-test
  (test-suite "Formation control 13"
    (test-case "root and dependency identity are declarations, independent of row order"
      (def p
        (.cc LibraryFormationProfile 'model-root "another-project-root"
             'dependencies (reverse (.ref LibraryFormationProfile 'dependencies))))
      (def result (run-profile p))
      (check-equal? (list-ref (car (rows result 'model_context)) 6) "another-project-root")
      (check-equal?
       (and
        (member
         '("LIB-C01" "selection-definitions" "selection" "definitions")
         (rows result 'layout_edge))
        #t)
       #t)
      (check-equal? (string? (render-formation-model result)) #t))))

(export
  formation-projection-order-test)
(def formation-projection-order-test
  (test-suite "Formation projection boundary"
    (test-case "declaration order does not change the rendered model"
      (def baseline (run-profile LibraryFormationProfile))
      (def reordered
        (run-profile
         (.cc LibraryFormationProfile
           'dependencies (reverse (.ref LibraryFormationProfile 'dependencies)))))
      (check-equal? (render-formation-model reordered) (render-formation-model baseline))
      (check-equal? (rows reordered 'runtime_ready) '()))
    (test-case "part references retain independently specified name quoting"
      (def result (run-profile LibraryFormationProfile))
      (def model (render-formation-model result))
      (check-equal?
       (and
        (string-contains
         model
         "dependency 'selection-definitions' from 'libraryProject'::'selection' to 'libraryProject'::'definitions';")
        #t)
       #t))))

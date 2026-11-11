;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;; -*- Gerbil -*-
(import :std/test :clan/poo/object :deterministic-engineering/init


        (only-in :clan/poo/mop validate)
        (only-in :std/io/tempfile call-with-temporary-directory)
        (only-in "../library/rust-resources/types.ss"
          ResourceProfileContract ResourceNativeProfileContract)
        (only-in "../library/evidence/types.ss" ResourceEvidenceScopeContract))
(def LocalProfile (.get deterministic-engineering.init.exports Library gateway-profiles profiles LocalProfile))
(def Cap2Profile (.get deterministic-engineering.init.exports Library gateway-profiles profiles Cap2Profile))
(def LifecycleProfile (.get deterministic-engineering.init.exports Library resource-lifecycle-profiles profiles LifecycleProfile))
(def LargerPayloadProfile (.get deterministic-engineering.init.exports Library resource-lifecycle-profiles profiles LargerPayloadProfile))
(export library-owner-test)
(def (unsupported-scope? e)
  (and (string-contains (call-with-output-string (cut display-exception e <>)) "unsupported QNT Profile/mode") #t))
(def library-owner-test
  (test-suite "Parent Library ownership and bounded native admission"
    (test-case "POO specialization preserves parent rules and dependency obligations"
      (def parent (.get (.get deterministic-engineering.init.exports Library) backpressure-memory entry))
      (def domain (.get (.get deterministic-engineering.init.exports Library) rust-resources))
      (def child (.ref domain 'entry))
      (def scope-contract (.get domain contracts scope))
      (check-equal? (eq? (.ref child 'parent) parent) #t)
      (for-each (lambda (row) (check-equal? (and (member row (.ref child 'rules)) #t) #t)) (.ref parent 'rules))
      (for-each (lambda (row) (check-equal? (and (member row (.ref child 'dependencies)) #t) #t)) (.ref parent 'dependencies))
      (check-equal? (eq? (validate scope-contract domain) domain) #t)
      (check-exception (validate scope-contract (.cc domain 'entry
        (.cc child 'rules (filter (lambda (r) (not (eq? (cadr r) 'BP-O02))) (.ref child 'rules))))) (lambda (_) #t))
      (check-exception (validate scope-contract (.cc domain 'methods (.o))) (lambda (_) #t))
      (check-exception (validate ResourceEvidenceScopeContract (.o make-evidence: void)) (lambda (_) #t)))
    (test-case "unsupported model scopes fail before a basis can alias another Profile"
      (def methods (.get (.get deterministic-engineering.init.exports Library) rust-resources methods))
      (for-each (lambda (p) (validate ResourceProfileContract p)) (list LocalProfile Cap2Profile LifecycleProfile))
      (def unsupported (.cc LifecycleProfile 'queue 2))
      (check-exception (validate ResourceProfileContract unsupported) (lambda (_) #t))
      (check-exception ((.ref methods 'scopes) (current-directory) unsupported 'invalid "absent-source.rs") unsupported-scope?)
      (check-exception ((.ref methods 'scopes) (current-directory) Cap2Profile 'invalid "absent-source.rs" 'early-release) unsupported-scope?)
      (check-exception (validate ResourceProfileContract (.cc LocalProfile 'factors '(tokio rayon))) (lambda (_) #t))
      (validate ResourceNativeProfileContract LifecycleProfile)
      (validate ResourceNativeProfileContract LargerPayloadProfile)
      (for-each (lambda (pair)
        (check-exception (validate ResourceNativeProfileContract
          (.cc LifecycleProfile (car pair) (cdr pair))) (lambda (_) #t)))
        '((runtime . "multi-thread/rayon1/unwind") (inventory . "unqualified-owner-set")
          (workload . "production-traffic") (lock . "unverified-lock")))
      (check-exception (validate ResourceNativeProfileContract (.cc LifecycleProfile 'factors '(bounded-retention tokio rayon))) (lambda (_) #t))
      (check-exception (validate ResourceNativeProfileContract LocalProfile) (lambda (_) #t))
      (check-exception (validate ResourceNativeProfileContract (.cc LifecycleProfile 'rayon-workers 2)) (lambda (_) #t)))
    (test-case "an extra Cargo ancestor configuration refuses execution before tools run"
      (def methods (.get (.get deterministic-engineering.init.exports Library) rust-resources methods))
      (def root (current-directory))
      (call-with-temporary-directory "native-cargo-config"
        (lambda (directory)
          (create-directory (path-expand ".cargo" directory))
          (call-with-output-file (path-expand ".cargo/config.toml" directory)
            (lambda (p) (display "[build]\nrustflags = [\"--cfg=unbound_config\"]\n" p)))
          (check-exception ((.ref methods 'native) root "absent-crate" "absent-cargo" "absent-rustc" 64
            (path-expand "output" directory))
            (lambda (e) (and (string-contains (call-with-output-string (cut display-exception e <>))
              "native output has an unbound Cargo configuration") #t))))))
    (test-case "native Scenario accepts one capture and refuses the removed split-input API"
      (def scene (.get (.get deterministic-engineering.init.exports Library) resource-lifecycle))
      (check-equal? (procedure? (.ref scene 'capture)) #t)
      (check-exception ((.ref scene 'open-review) LifecycleProfile 'usage "old-snapshot" "ignored-source" '()) (lambda (_) #t))
      (check-exception ((.ref scene 'open-review) (.o)) (lambda (_) #t)))))

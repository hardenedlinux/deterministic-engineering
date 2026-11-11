;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;; -*- Gerbil -*-
(import :std/test :clan/poo/object :gerbil-ascent/rules/interface
        (only-in :clan/poo/mop validate)
        "../library/project-organization/objects.ss" "../library/project-organization/types.ss"
        "../library/backpressure-memory/objects.ss"
        "../library/rust-resources/objects.ss"
        "../library/backpressure-tokio-rayon/objects.ss"
        "../library/rust-resources/types.ss"

        "../library/project-intake/func.ss" "../library/gateway-review/func.ss"
        "../library/project-formation/func.ss" "../library/evidence/func.ss")
(import :deterministic-engineering/init)
(def LocalProfile (.get deterministic-engineering.init.exports Library gateway-profiles profiles LocalProfile))
(def CacheProfile (.get deterministic-engineering.init.exports Library gateway-profiles profiles CacheProfile))
(def RetryProfile (.get deterministic-engineering.init.exports Library gateway-profiles profiles RetryProfile))
(def LifecycleProfile (.get deterministic-engineering.init.exports Library resource-lifecycle-profiles profiles LifecycleProfile))
(def LibraryFormationProfile (.get deterministic-engineering.init.exports Library library-formation-profiles profiles LibraryFormationProfile))
(export layer-declarative-alignment-test)
(def selected-method-references
  (map (lambda (key) (method-ref (.ref RustMethodDefinitions key))) '(native quint lean)))
(def selected-integration-reference
  (method-ref (.get RustMethodDefinitions integration)))
(def (rows result name) ((.get result rows-of) name))
(def layer-declarative-alignment-test
  (test-suite "Native declarations across Library, Profile, Module and Scenario"
    (test-case "organization method references follow effective definitions after cache reads"
      (def held (.get ProjectOrganization method-refs))
      (def selected (.o (:: @ ProjectOrganization)
                        methods: =>.+ (.o reason: =>.+ (.o revision: "reviewed-rules"))))
      (validate (.get OrganizationModelContract value-contract) selected)
      (check-equal? (.get (car (.get selected method-refs)) revision) "reviewed-rules")
      (check-equal? (.get ProjectOrganization method-refs) held)
      (check-equal? (.get selected methods reason kind) 'application-reasoning)
      (check-exception (validate (.get OrganizationMethodContract value-contract)
                                 (.cc (.get selected methods reason) 'signature OrganizationRenderSignature)) error?))
    (test-case "Profile accounting fields derive while factors retain inherited policy"
      (def held (.get LifecycleProfile workload))
      (def larger (.o (:: @ LifecycleProfile) identity: 'resource-256 item: 256))
      (validate ResourceNativeProfileContract larger)
      (check-equal? (.get larger workload) "controlled-six-case-suite/256")
      (check-equal? (.get LifecycleProfile workload) held)
      (for-each (lambda (profile)
                  (check-equal? (andmap (cut memq <> (.get profile factors)) (.get LocalProfile factors)) #t))
                (list CacheProfile RetryProfile))
      (check-exception (validate ResourceNativeProfileContract (.cc larger 'workload held)) error?))
    (test-case "one finite QNT coverage table preserves every initializer and rejects escape"
      (for-each (lambda (row)
                  (def profile (.o capacity: (car row) queue: (cadr row)))
                  (check-equal? (resource-model-initializer profile 'normal) (caddr row))
                  (check-equal? (resource-model-initializer profile 'early-release) (cadddr row)))
                '((1 1 "initResource" "initResourceRunning") (2 2 "init" "initRunning") (4 2 "initC2" #f)))
      (check-equal? (resource-model-profile-supported? (.o capacity: 1 queue: 2) 'normal) #f)
      (check-equal? (resource-model-initializer LifecycleProfile 'foreign) #f))
    (test-case "Scenario refinement reaches real formation rules without retargeting proposals"
      (def library (.o entry: ProjectOrganization))
      (def engine (.o reason: reason-project-formation render: render-formation-model))
      (def scene (project-formation-scope library engine (.o)))
      (def held ((.get scene inputs) LibraryFormationProfile))
      (def baseline ((.get scene run) LibraryFormationProfile))
      (def changed (.o (:: @ scene) library: (.o entry:
                                                 (.o (:: @ ProjectOrganization) products: => (cut append <> '("D-NEW"))))))
      (def result ((.get changed run) LibraryFormationProfile))
      (check-equal? (rows baseline 'structurally_covered) '(("LIB-C01")))
      (check-equal? (and (member '("LIB-C01" "product" "D-NEW") (rows result 'gap)) #t) #t)
      (check-equal? (rows result 'structurally_covered) '())
      (check-equal? ((.get scene inputs) LibraryFormationProfile) held)
      (def retargeted ((.get scene run) (.cc LibraryFormationProfile 'project "OTHER-PROJECT")))
      (check-equal? (rows retargeted 'structurally_covered) '())
      (check-equal? (length (rows retargeted 'invalidated)) 3))
    (test-case "effective Scenario domain reaches actual evidence obligation and pending queries"
      (def model (specialize-backpressure BackpressureModel selected-method-references))
      (def selected-domain (.o entry: model methods: (.o) profile-contract: ResourceProfileContract))
      (def scene (gateway-review-scope selected-domain (.o open-review: open-resource-review)))
      (def held (.get scene entry))
      (def selected (.o (:: @ model)
                        rules: => (cut append <> '((cache EXTRA-CACHE review)))
                        dependencies: => (cut append <> '((EXTRA-CACHE inventory)))))
      (def refined (.o (:: @ scene) domain: (.cc selected-domain 'entry selected)))
      (def result (gerbil-ascent-session-run
                   ((.get refined open-review) CacheProfile 'cache-use "cut/cache" "source/current")))
      (check-equal? (.get scene entry) held)
      (check-equal? (and (member '(cache-use EXTRA-CACHE review) (rows result 'obligation)) #t) #t)
      (check-equal? (and (member '(cache-use EXTRA-CACHE review) (rows result 'pending)) #t) #t)
      (check-equal? (rows result 'support) '())
      (check-exception ((.get (.cc refined 'entry model) open-review)
                        CacheProfile 'bad "cut/bad" "source/current") error?))))

(import
  :clan/poo/object
  (only-in :clan/poo/mop Any Function)
  (only-in :clan/poo/type String Symbol List)
  (only-in :clan/poo/object-contract ObjectContract.)
  (only-in :yuanxu/object-types/contracts YuanxuContract. yuanxu-predicate-type)
  "../../types.ss"
  (only-in
   "../../library/drivers/rust-resources/types.ss"
   RustResourcesScopeContract)
  (only-in :yuanxu/object-types/contracts yuanxu-predicate-contract)
  "../../library/project-organization/types.ss"
  "../../library/drivers/project-formation/types.ss")
(export
  FormationProfileContract
  FormationCaptureRequestContract
  RustResourcesScopeContract
  OrganizationScopeContract
  FormationScopeContract
  FormationScenarioContract)
(def FormationScenarioContract
  (yuanxu-predicate-contract
   'project-formation/scenario
   (lambda (v)
     (and
      (object? v)
      (andmap
       (lambda (slot) (and (.slot? v slot) (procedure? (.ref v slot))))
       '(inputs
         run
         render
         acquire
         input-current!
         observe-inputs
         select
         prepare-capture
         acquire-codex
         codex-current!
         observe-codex
         verify-codex
         codex-verification-current!
         revoke-codex!
         authorize-codex
         codex-authorized!
         codex-authority-observation))))
   (lambda (_v _c) '())))

(def (text-row size)
  (yuanxu-predicate-type
   'formation/text-row
   (lambda (v) (and (list? v) (= (length v) size) (andmap string? v)))))
(def CandidateShape
  (.cc ObjectContract. 'responsibilities
       (.o
         identity: LibraryNonemptyString
         project: LibraryNonemptyString
         basis: LibraryNonemptyString
         owners: (List (text-row 2))
         products: (List LibraryNonemptyString)
         duties: (List LibraryNonemptyString)
         capabilities: (List (text-row 2)))))
(def FormationProfileContract
  (.cc YuanxuContract. 'identity 'project-formation/profile
       'value-contract (.cc ObjectContract. 'responsibilities
                            (.o
                              project: LibraryNonemptyString
                              intent: LibraryNonemptyString
                              model-root: LibraryNonemptyString
                              model-package: LibraryNonemptyString
                              model-instance: LibraryNonemptyString
                              model-library: LibraryNonemptyString
                              layout: (List (text-row 4))
                              dependencies: (List (text-row 3))
                              candidates: (List CandidateShape)
                              project-inputs: (List LibraryNonemptyString)
                              input-byte-limit: (yuanxu-predicate-type
                                                 'formation/byte-bound
                                                 (lambda (v) (and (exact-integer? v) (> v 0) (<= v 16777216))))
                              input-lifetime-seconds: (yuanxu-predicate-type
                                                       'formation/lifetime
                                                       (lambda (v) (and (real? v) (> v 0) (<= v 120))))
                              organization: Symbol
                              model-catalog: Symbol
                              model-mapping: Symbol
                              resource-model: Symbol
                              integration: Symbol
                              coding-policy: Symbol
                              design-policy: Symbol
                              resource-methods: (List Symbol)))))
(def FormationCaptureRequestContract
  (.cc YuanxuContract. 'identity 'project-formation/capture-request
       'value-contract (.cc ObjectContract. 'responsibilities
                            (.o
                              purpose: (yuanxu-predicate-type
                                        'formation/capture-purpose
                                        (lambda (v) (eq? v 'repository-design)))
                              root: LibraryNonemptyString
                              profile: (.get FormationProfileContract value-contract)))))

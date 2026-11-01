;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

(import
  :clan/poo/object
  :std/list/list
  "../../library/drivers/project-formation/inputs.ss"
  "./codex.ss"
  "./types.ss"
  (only-in :clan/poo/mop validate))
(export
  formation-inputs
  project-formation-scope)
(def (formation-inputs declaration profile)
  (def candidates (.ref profile 'candidates))
  (unless (pair? (.ref profile 'layout)) (error "selected model layout must be nonempty"))
  (def (unique-values? xs) (= (length xs) (length (delete-duplicates/hash xs))))
  (for-each
   (lambda (slot)
     (unless (and (pair? (.ref declaration slot)) (list? (.ref declaration slot)))
       (error "formation requires independent nonempty demand" slot)))
   '(roles products duties required-capabilities))
  (unless (and
           (pair? candidates)
           (list? candidates)
           (unique-values? (map (lambda (c) (.ref c 'identity)) candidates))
           (unique-values? (map car (.ref declaration 'roles)))
           (unique-values? (map car (.ref profile 'layout)))
           (unique-values? (map cadr (.ref profile 'layout)))
           (unique-values? (map caddr (.ref profile 'layout)))
           (unique-values? (map car (.ref profile 'dependencies))))
    (error "ambiguous candidate/role/layout identity"))
  (def role-names (map car (.ref declaration 'roles)))
  (unless (andmap
           (lambda (edge)
             (and
              (list? edge)
              (= (length edge) 3)
              (member (cadr edge) role-names)
              (member (caddr edge) role-names)))
           (.ref profile 'dependencies))
    (error "dependency must reference declared roles"))
  (for-each
   (lambda (c)
     (unless (unique-values? (map car (.ref c 'owners)))
       (error "ambiguous role assignment" (.ref c 'identity))))
   candidates)
  (def (rows slot)
    (append-map (lambda (c) (map (lambda (r) (cons (.ref c 'identity) r)) (.ref c slot))) candidates))
  (map
   (lambda (entry)
     (cons
      (car entry)
      (map
       (lambda (row)
         (map
          (lambda (cell)
            (unless (string? cell) (error "formation facts must be strings" cell))
            (string-copy cell))
          row))
       (cdr entry))))
   (list
    (cons 'intent (list (list (.ref profile 'project) (.ref profile 'intent))))
    (cons
     'project_layout
     (list
      (list
       (.ref profile 'project)
       (.ref profile 'model-package)
       (.ref profile 'model-instance)
       (.ref profile 'model-library)
       (.ref profile 'model-root))))
    (cons
     'candidate
     (map (lambda (c) (list (.ref c 'identity) (.ref c 'project) (.ref c 'basis))) candidates))
    (cons 'proposed_owner (rows 'owners))
    (cons
     'proposed_product
     (append-map
      (lambda (c) (map (lambda (x) (list (.ref c 'identity) x)) (.ref c 'products)))
      candidates))
    (cons
     'proposed_duty
     (append-map (lambda (c) (map (lambda (x) (list (.ref c 'identity) x)) (.ref c 'duties))) candidates))
    (cons 'declared_capability (rows 'capabilities))
    (cons 'required_role (map (lambda (r) (list (car r))) (.ref declaration 'roles)))
    (cons 'allowed_owner (map (lambda (r) (list (car r) (cadr r))) (.ref declaration 'roles)))
    (cons 'role_scope (map (lambda (r) (list (car r) (caddr r))) (.ref declaration 'roles)))
    (cons 'owner_kind (.ref declaration 'owner-kinds))
    (cons 'protected_owner (.ref declaration 'protected))
    (cons 'required_product (map list (.ref declaration 'products)))
    (cons 'required_duty (map list (.ref declaration 'duties)))
    (cons 'required_capability (map list (.ref declaration 'required-capabilities)))
    (cons 'role_layout (.ref profile 'layout))
    (cons 'role_dependency (.ref profile 'dependencies)))))
;; Composition keeps dependency owners as values. Derived callables use the
;; effective Scenario; acquisition and authority checks remain in their owners.
(.def FormationScenario.
  library: (error "Formation Scenario requires its Library")
  engine: (error "Formation Scenario requires its engine")
  resources: (error "Formation Scenario requires its resource scope")
  acquire-codex: formation-acquire-codex
  codex-current!: formation-codex-current!
  observe-codex: formation-codex-observation
  authorize-codex: formation-authorize-codex
  codex-authorized!: formation-codex-authorized!
  codex-authority-observation: formation-codex-authority-observation
  verify-codex: formation-verify-codex
  codex-verification-current!: formation-codex-verification-current!
  revoke-codex!: formation-revoke-codex!
  select: (lambda (profile) (select-formation-profile library engine resources profile))
  prepare-capture: (lambda (request (authority #f))
                     (prepare-formation-capture library engine resources request authority))
  input-current!: formation-inputs-current!
  observe-inputs: formation-input-observation
  acquire: (lambda (root profile)
             (formation-acquire-inputs
              root
              (.get profile project-inputs)
              (.get profile input-byte-limit)
              (.get profile input-lifetime-seconds)))
  inputs: (lambda (profile) (formation-inputs (.get library entry) profile))
  run: (lambda (profile) ((.get engine reason) (inputs profile)))
  render: (.get engine render))
(def (project-formation-scope selected-library selected-engine selected-resources)
  (.o (:: @ FormationScenario.)
      library: selected-library
      engine: selected-engine
      resources: selected-resources))

(def (select-formation-profile library engine selected-resource-scope profile-input)
  (def selected-profile (validate (.get FormationProfileContract value-contract) profile-input))
  (def organization-model (.get library entry))
  (def integration-model (.get selected-resource-scope integration-entry))
  (unless (and
           (eq? (.get engine library entry) organization-model)
           (eq? (.get selected-profile organization) (.get organization-model identity))
           (eq? (.get selected-profile model-catalog) (.get organization-model catalog identity))
           (eq? (.get selected-profile model-mapping) (.get organization-model mapping identity))
           (equal?
            (.get selected-profile model-library)
            (symbol->string (.get organization-model catalog package)))
           (eq? (.get selected-profile resource-model) (.get selected-resource-scope entry identity))
           (eq? (.get selected-profile integration) (.get integration-model identity))
           (eq? (.get integration-model parent) (.get selected-resource-scope entry))
           (eq? (.get selected-resource-scope entry parent) (.get selected-resource-scope parent entry))
           (eq? (.get selected-profile coding-policy) (.get selected-resource-scope policies coding identity))
           (eq? (.get selected-profile design-policy) (.get selected-resource-scope policies design identity)))
    (error "Profile choice or admitted parent/Library/Program association differs"))
  (def selected-methods (.get selected-profile resource-methods))
  (unless (and
           (pair? selected-methods)
           (= (length selected-methods) (length (delete-duplicates/hash selected-methods)))
           (andmap
            (lambda (key) (.slot? (.get selected-resource-scope bound-methods bindings) key))
            selected-methods))
    (error "Profile must select distinct actual published method bindings"))
  (for-each
   (lambda (row)
     (def mapping-row (assoc (car row) (.get organization-model mapping roles)))
     (unless (and mapping-row (equal? (caddr row) (cadr mapping-row)) (equal? (cadddr row) (cadr mapping-row)))
       (error "Profile layout does not reference its selected Library catalog/mapping" row)))
   (.get selected-profile layout))
  (.o
    profile: selected-profile
    organization: library
    module: engine
    resources: selected-resource-scope
    methods: (map
              (lambda (key) (.ref (.get selected-resource-scope bound-methods bindings) key))
              selected-methods)))

;; This is an actual preparation and missing-capability report, never C issuance.
;; No callback/record/namespace spelling is admitted as original user authority.
(def (prepare-formation-capture library engine selected-resource-scope request-input authority)
  (def request (validate (.get FormationCaptureRequestContract value-contract) request-input))
  (when authority (formation-codex-authorized! authority (.get request purpose) (.get request root)))
  (def selected
    (select-formation-profile library engine selected-resource-scope (.get request profile)))
  (def profile-value (.get selected profile))
  (def acquired
    (formation-acquire-inputs
     (.get request root)
     (.get profile-value project-inputs)
     (.get profile-value input-byte-limit)
     (.get profile-value input-lifetime-seconds)))
  (def repository-observation (formation-input-observation acquired))
  (def origin-findings
    (map
     (lambda (role-value)
       (.o
         kind: 'missing-original-source-capability
         role: role-value
         requirement: "A qualified original host/source occurrence and verifier are required; declared content is not origin."))
     (filter
      (lambda (role-value) (not (and authority (eq? role-value 'role-mandate))))
      (.get repository-observation missing-origins))))
  (when authority (formation-codex-authorized! authority (.get request purpose) (.get request root)))
  (.o
    status: 'capture-blocked
    purpose: (.get request purpose)
    selection: selected
    local-authority: (and authority (formation-codex-authority-observation authority))
    repository-inputs: acquired
    observation: repository-observation
    findings: (append
               origin-findings
               (map
                (lambda (binding)
                  (.o
                    kind: 'unacquired-method-footprint
                    method: (.get binding definition identity)
                    required-inputs: (.get binding definition input-demands)))
                (.get selected methods)))
    capture: #f))

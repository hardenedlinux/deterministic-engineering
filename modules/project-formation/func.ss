(import
  :clan/poo/object
  (only-in :clan/poo/mop validate)
  :std/list/list
  :std/format
  :gerbil-ascent/rules/interface
  "./types.ss"
  (only-in :gerbil-ascent/rules/declaration rule-module-program rule-module-bindings))
(export
  bind-formation-methods
  FormationProgram
  make-formation-program
  reason-project-formation
  render-formation-model)
(define-program
  (make-formation-program)
  (sources
   intent
   project_layout
   candidate
   proposed_owner
   proposed_product
   proposed_duty
   declared_capability
   required_role
   allowed_owner
   role_scope
   owner_kind
   protected_owner
   required_product
   required_duty
   required_capability
   role_layout
   role_dependency)
  (outputs
   conflict
   gap
   role_support
   structurally_covered
   invalidated
   runtime_blocked
   runtime_ready
   declared_ready
   declared_blocked
   candidate_state
   layout_node
   layout_edge
   product_node
   duty_node
   model_context)
  (relation intent ((project string?) (basis string?)))
  (relation
   project_layout
   ((project string?) (package string?) (instance string?) (catalog string?) (root string?)))
  (relation
   model_context
   ((id string?)
    (package string?)
    (instance string?)
    (catalog string?)
    (project string?)
    (basis string?)
    (root string?)))
  (relation candidate ((id string?) (project string?) (basis string?)))
  (relation proposed_owner ((id string?) (role string?) (owner string?)))
  (relation proposed_product ((id string?) (product string?)))
  (relation proposed_duty ((id string?) (duty string?)))
  (relation declared_capability ((id string?) (cap string?) (status string?)))
  (relation required_role ((role string?)))
  (relation allowed_owner ((role string?) (owner string?)))
  (relation role_scope ((role string?) (scope string?)))
  (relation owner_kind ((owner string?) (kind string?)))
  (relation protected_owner ((role string?) (owner string?)))
  (relation required_product ((product string?)))
  (relation required_duty ((duty string?)))
  (relation required_capability ((cap string?)))
  (relation role_layout ((role string?) (slot string?) (type string?) (reference string?)))
  (relation role_dependency ((edge string?) (from string?) (to string?)))
  (relation conflict ((id string?) (role string?) (reason string?)))
  (relation gap ((id string?) (kind string?) (item string?)))
  (relation role_support ((id string?) (role string?) (owner string?)))
  (relation invalidated ((id string?)))
  (relation structural_gap ((id string?)))
  (relation structurally_covered ((id string?)))
  (relation runtime_blocked ((id string?)))
  (relation runtime_ready ((id string?)))
  (relation declared_ready ((id string?)))
  (relation declared_blocked ((id string?)))
  (relation candidate_state ((id string?) (state string?)))
  (relation
   layout_node
   ((id string?) (slot string?) (type string?) (owner string?) (reference string?)))
  (relation layout_edge ((id string?) (edge string?) (from string?) (to string?)))
  (relation product_node ((id string?) (product string?)))
  (relation duty_node ((id string?) (duty string?)))
  ;; LR01/02: reusable/project separation and existing protected owners.
  ((conflict C R (lit "project-input-in-definition"))
   <--
   (candidate C P B)
   (proposed_owner C R O)
   (role_scope R (lit "project"))
   (owner_kind O (lit "definition")))
  ((conflict C R (lit "duplicate-framework-owner"))
   <--
   (candidate C P B)
   (proposed_owner C R O)
   (protected_owner R E)
   (if (O E) (not (equal? O E))))
  ((conflict C R (lit "incompatible-owner"))
   <--
   (candidate C P B)
   (proposed_owner C R O)
   (required_role R)
   (not (allowed_owner R O)))
  ((conflict C R (lit "undeclared-role"))
   <--
   (candidate C P B)
   (proposed_owner C R O)
   (not (required_role R)))
  ((gap C (lit "model-context") P) <-- (candidate C P B) (not (project_layout P _ _ _ _)))
  ;; LR03/04: demand precedes candidates and compatibility is positive data.
  ((role_support C R O)
   <--
   (candidate C P B)
   (required_role R)
   (proposed_owner C R O)
   (allowed_owner R O))
  ((gap C (lit "role") R) <-- (candidate C P B) (required_role R) (not (role_support C R _)))
  ((gap C (lit "product") D) <-- (candidate C P B) (required_product D) (not (proposed_product C D)))
  ((gap C (lit "duty") D) <-- (candidate C P B) (required_duty D) (not (proposed_duty C D)))
  ((gap C (lit "layout") R) <-- (candidate C P B) (required_role R) (not (role_layout R _ _ _)))
  ((structural_gap C) <-- (gap C K D) (if (K) (not (equal? K "capability"))))
  ;; LR06: preserve incompatible basis rather than silently selecting it.
  ((invalidated C) <-- (candidate C P B) (intent P E) (if (B E) (not (equal? B E))))
  ((invalidated C) <-- (candidate C P B) (not (intent P _)))
  ((structurally_covered C)
   <--
   (candidate C P B)
   (intent P B)
   (not (structural_gap C))
   (not (conflict C _ _))
   (not (invalidated C)))
  ;; LR05/08: missing capability never becomes established by absent errors.
  ((gap C (lit "capability") K)
   <--
   (candidate C P B)
   (required_capability K)
   (not (declared_capability C K (lit "established"))))
  ((declared_blocked C) <-- (candidate C P B) (not (structurally_covered C)))
  ((declared_blocked C) <-- (gap C (lit "capability") K))
  ((declared_blocked C)
   <--
   (candidate C P B)
   (required_capability K)
   (declared_capability C K S)
   (if (S) (not (equal? S "established"))))
  ;; These inputs are declarations. Their conditional readiness is not an
  ;; executed/current capability finding; no rule issues runtime_ready here.
  ((declared_ready C) <-- (structurally_covered C) (not (declared_blocked C)))
  ;; This raw-design operation has no trusted capability-evidence provider.
  ;; Absence of a declaration conflict never clears the real runtime gate.
  ((runtime_blocked C) <-- (candidate C P B) (required_capability K))
  ((runtime_blocked C) <-- (candidate C P B) (not (structurally_covered C)))
  ;; LR07: every candidate/outcome remains visible; this is not an approval.
  ((candidate_state C (lit "elaborate")) <-- (structurally_covered C))
  ((candidate_state C (lit "conflict")) <-- (conflict C R X))
  ((candidate_state C (lit "gap")) <-- (gap C K X))
  ((candidate_state C (lit "invalidated")) <-- (invalidated C))
  ((model_context C Package Instance Catalog P B Root)
   <--
   (structurally_covered C)
   (candidate C P B)
   (project_layout P Package Instance Catalog Root))
  ((layout_node C S T O Ref)
   <--
   (structurally_covered C)
   (role_support C R O)
   (role_layout R S T Ref))
  ((layout_edge C Edge S T)
   <--
   (structurally_covered C)
   (role_dependency Edge R Q)
   (role_layout R S _ _)
   (role_layout Q T _ _))
  ((product_node C D) <-- (structurally_covered C) (required_product D) (proposed_product C D))
  ((duty_node C D) <-- (structurally_covered C) (required_duty D) (proposed_duty C D))
  (bounds 4096 4096 4096))
(def FormationDeclaration (make-formation-program))
(def FormationProgram (rule-module-program FormationDeclaration))
(def (copy-fact value)
  (cond
   ((string? value) (string-copy value))
   ((pair? value) (cons (copy-fact (car value)) (copy-fact (cdr value))))
   ((null? value) '())
   (else (error "unsupported application fact cell" value))))

;; This public probe reports design assertions only. Qualified same-C handoff
;; requires the acquisition and evidence owners; raw rows cannot issue it.
(def (reason-project-formation replacements)
  (def declaration FormationDeclaration)
  (def program FormationProgram)
  (def expected (.ref program 'source-handles))
  (unless (and
           (list? replacements)
           (= (length expected) (length replacements))
           (andmap (lambda (entry) (and (pair? entry) (symbol? (car entry)))) replacements)
           (= (length replacements) (length (delete-duplicates/hash (map car replacements))))
           (andmap (lambda (name) (assq name replacements)) expected))
    (error "formation requires the actual complete Program source set, including empty sources"))
  ;; Every relation owns its string cells before native evaluation. Native source
  ;; replacement owns the transaction; do not introduce a second evaluator.
  (def prepared (map (lambda (entry) (cons (car entry) (copy-fact (cdr entry)))) replacements))
  (def session (gerbil-ascent-open-session program))
  (def result
    (gerbil-ascent-session-replace-sources!
     session
     prepared
     (lambda (prospective)
       (and
        (.ref prospective 'finished)
        (andmap
         (lambda (entry)
           ;; ASCENT relations are sets. Compare both directions without
           ;; silently interpreting ordered/bag inputs as this declared domain.
           (let ((actual ((.ref prospective 'rows-of) (car entry))) (wanted (cdr entry)))
             (and
              (andmap (cut member <> wanted) actual)
              (andmap (cut member <> actual) wanted))))
         prepared)))))
  (unless (.ref result 'finished) (error "formation evaluation incomplete"))
  ;; Public native rows detach spines but share strings. Every outward read owns
  ;; primitive cells too; a caller cannot mutate retained engine/publication data.
  (def native-rows (.ref result 'rows-of))
  (def output-bindings
    (filter
     (lambda (binding) (not (memq (cdr binding) expected)))
     (rule-module-bindings declaration)))
  (.cc result 'rows-of (lambda (name) (copy-fact (native-rows name)))
       'output-bindings (lambda ()
                          (map (lambda (binding) (cons (car binding) (cdr binding))) output-bindings))))

;; Materialize only a unique structurally eligible model; all names/edges are data.
(def (model-name text)
  (unless (and
           (string? text)
           (> (string-length text) 0)
           (andmap
            (lambda (c)
              (or
               (char-alphabetic? c)
               (char-numeric? c)
               (memv c '(#\_ #\- #\:))))
            (string->list text)))
    (error "unsafe SysML name" text))
  (string-append "'" text "'"))
(def (qualified-reference catalog text)
  (model-name text)
  (string-append (model-name catalog) "::" text))
(def (row-key row)
  (call-with-output-string (lambda (p) (write row p))))
(def (ordered rows) (list-sort (lambda (a b) (string<? (row-key a) (row-key b))) rows))
;; Pure render fragments consume only selected ASCENT rows. Formatting never
;; performs capture, validation/admission or publication.
(def (selected-model-rows result relation candidate)
  (filter (lambda (row) (equal? (car row) candidate)) ((.ref result 'rows-of) relation)))
(def (render-model-part catalog row)
  (format "        part %a : %a;\n" (model-name (cadr row)) (qualified-reference catalog (caddr row))))
(def (render-model-edge instance edge-name from to)
  (format
   "    dependency %a from %a::%a to %a;\n"
   (model-name edge-name)
   instance
   (model-name from)
   to))
(def (render-model-section section-name names)
  (string-append
   (format "    part %a {\n" section-name)
   (apply string-append (map (lambda (name) (format "        part %a;\n" (model-name name))) names))
   "    }\n"))
(def (render-formation-model result)
  (def selected ((.ref result 'rows-of) 'structurally_covered))
  (unless (= (length selected) 1)
    (error "model materialization requires one structural candidate; retain alternatives" selected))
  (def chosen (caar selected))
  (def (rows relation) (selected-model-rows result relation chosen))
  (def nodes (ordered (rows 'layout_node)))
  (unless (pair? nodes) (error "no declared layout nodes"))
  (def contexts (rows 'model_context))
  (unless (= (length contexts) 1) (error "one selected model context required" contexts))
  (match
      (car contexts)
    ([_ package-name instance-name catalog project-name intent-name root-name]
     (def instance (model-name instance-name))
     (string-append
      "// Generated from the ProjectFormation ASCENT result; design-only module projection.\n"
      "// Model context and companion catalog are selected in project_layout.\n"
      (format "package %a {\n    private import %a::*;\n" (model-name package-name) (model-name catalog))
      (format
       "    doc /* Project %a; declared intent %a; structural candidate %a. Design assertions only; runtime capability gates remain separate. */\n"
       (model-name project-name)
       (model-name intent-name)
       (model-name chosen))
      (format "    part <%a> %a {\n" (model-name root-name) instance)
      (apply string-append (map (cut render-model-part catalog <>) nodes))
      "    }\n"
      (apply
       string-append
       (map
        (lambda (row)
          (render-model-edge
           instance
           (cadr row)
           (caddr row)
           (string-append instance "::" (model-name (cadddr row)))))
        (ordered (rows 'layout_edge))))
      (apply
       string-append
       (map
        (lambda (row)
          (render-model-edge
           instance
           (string-append "source-" (cadr row))
           (cadr row)
           (qualified-reference catalog (list-ref row 4))))
        nodes))
      (render-model-section (model-name "requiredProducts") (map cadr (ordered (rows 'product_node))))
      (render-model-section (model-name "requiredDuties") (map cadr (ordered (rows 'duty_node))))
      (render-model-section
       "openCapabilities"
       (map caddr (ordered (filter (lambda (row) (equal? (cadr row) "capability")) (rows 'gap)))))
      "}\n"))))

(def (bind-formation-methods library-scope)
  (def expected-definitions (.get library-scope entry methods))
  (def (binding key implementation)
    (def definition-value (.ref expected-definitions key))
    (unless (and
             (eq? (.get definition-value operation) key)
             (eq? (.get definition-value program-ref identity) 'project-formation.program))
      (error "Formation definition/Program mismatch" key))
    (def checked-operation (validate (.get definition-value signature) implementation))
    (.o
      definition: definition-value
      provider: 'project-formation
      operation-name: key
      operation: checked-operation
      program: FormationProgram))
  (.o
    reason: (binding 'reason reason-project-formation)
    render: (binding 'render render-formation-model)))

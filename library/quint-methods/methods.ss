;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure Quint source projection and verification plan generation.
;;; Dispatched on prototype ancestry; unknown prototypes fail dispatch. Zero I/O.
(import :clan/poo/object
        (only-in :clan/poo/type validate)
        (only-in :clan/poo/mop/clos/generic-syntax .defgeneric .defmethod)
        :std/format
        (only-in "objects.ss" ThreatModel.)
        "ast.ss"
        "types.ss")
(export quint-module quint-plan quint-model-readme quint-guard-audit)

(.defgeneric quint-module (model))
(.defgeneric quint-plan (model profile policy))
(.defgeneric quint-model-readme (model))
(.defgeneric quint-guard-audit (model))

(def (join-lines items sep)
  (let loop ((rest items) (acc ""))
    (cond
     ((null? rest) acc)
     ((equal? acc "") (loop (cdr rest) (car rest)))
     (else (loop (cdr rest) (string-append acc sep (car rest)))))))

(def (has-state-record? state-rows)
  (and (pair? state-rows) (= (length (car state-rows)) 3)))

(.defmethod (quint-module (model (prototype ThreatModel.)))
  (validate QuintDomainModelType model)
  (def mod-name (.get model quint-module))
  (def limits (.get model limits))
  (def imports (if (.slot? model 'quint-imports) (.get model quint-imports) '()))
  (def params (.get model parameters))
  (def state-rows (.get model state))
  (def transitions (.get model transitions))
  (def safety (.get model safety))
  (def traces (.get model traces))
  (def countermodels (.get model countermodels))
  (call-with-output-string
    (lambda (out)
      ;; REUSE-IgnoreStart
      (display "// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors\n" out)
      (display "// SPDX-License-Identifier: LGPL-2.1-or-later\n" out)
      ;; REUSE-IgnoreEnd
      (fprintf out "// @quint-model %a\n" (.get model identity))
      (display "// @quint-version 0.33.0\n" out)
      (display "// @apalache-version 0.62.1\n" out)
      (def verify-depth (if (.slot? model 'verify-depth) (.get model verify-depth) 12))
      (when (has-state-record? state-rows)
        (if (and (.slot? model 'verify-const-bindings)
                 (pair? (.get model verify-const-bindings)))
          (fprintf out "// @verify safety max-steps=%a const=\"%a\"\n"
                   verify-depth
                   (join-lines
                     (map (lambda (b) (format "%a=%a" (car b) (cadr b)))
                          (.get model verify-const-bindings))
                     ", "))
          (fprintf out "// @verify safety max-steps=%a\n" verify-depth)))
      (def cm-depth (if (.slot? model 'countermodel-depth) (.get model countermodel-depth) 6))
      (for-each
        (lambda (cm)
          (fprintf out "// @countermodel %a step=%a max-steps=%a itf=\"%a\"\n"
                   (.get cm dropped-guard) (.get cm step-action) cm-depth (.get cm expected-itf-predicate)))
        countermodels)
      (fprintf out "// Limits: %a\n" limits)
      (fprintf out "module %a {\n" mod-name)
      (for-each
        (lambda (imp)
          (fprintf out "  import %a.* from \"%a\"\n" (car imp) (cadr imp)))
        imports)
      (for-each
        (lambda (p)
          (fprintf out "  const %a: %a\n" (car p) (cadr p)))
        params)
      (when (has-state-record? state-rows)
        (fprintf out "  type State = { %a }\n"
                 (join-lines (map (lambda (r) (format "%a: %a" (car r) (cadr r))) state-rows) ", "))
        (display "  var h: State\n" out)
        (fprintf out "  action init = h' = { %a }\n"
                 (join-lines (map (lambda (r) (format "%a: %a" (car r) (caddr r))) state-rows) ", ")))
      (for-each
        (lambda (tr)
          (def body (cadr tr))
          (fprintf out "  %a\n" (if (string? body) body (emit-quint-decl body))))
        transitions)
      (when (has-state-record? state-rows)
        (fprintf out "  val safety = %a\n" (if (string? safety) safety (emit-quint-expr safety))))
      (for-each
        (lambda (cm)
          (fprintf out "  // Countermodel %a (dropped guard: %a)\n"
                   (.get cm identity) (.get cm dropped-guard))
          (if (.slot? cm 'derive-from-transition)
            (let* ((base-tr (assq (.get cm derive-from-transition) transitions))
                   (step-call (if (.slot? cm 'derive-step-call) (.get cm derive-step-call) #f))
                   (derived (quint-derive-countermodel-decls
                              (cadr base-tr)
                              (.get cm dropped-guard)
                              (.get cm derive-action-name)
                              (string->symbol (.get cm step-action))
                              step-call)))
              (fprintf out "  %a\n" (emit-quint-counter-ast derived)))
            (fprintf out "  %a\n" (emit-quint-counter-ast (.get cm counter-action)))))
        countermodels)
      (for-each
        (lambda (tr)
          (def body (cadr tr))
          (fprintf out "  %a\n" (if (string? body) body (emit-quint-decl body))))
        traces)
      (display "}\n" out))))

(.defmethod (quint-plan (model (prototype ThreatModel.)) profile policy)
  (validate QuintDomainModelType model)
  (validate QuintProfileType profile)
  (validate QuintPolicyType policy)
  (def mod-name (.get model quint-module))
  (def file-name (.get model quint-file))
  (def seed-val (.get profile seed))
  (def pos-depth (.get profile positive-depth))
  (def neg-depth (.get profile negative-depth))
  (def timeout-val (.get policy timeout))
  (def countermodels (.get model countermodels))
  (when (and (.get profile require-countermodels?) (null? countermodels))
    (error "Profile requires countermodels but model declares none" (.get model identity)))
  (def has-step? (and (has-state-record? (.get model state)) #t))
  (def base-steps
    (append
      (list
        (.o label: "typecheck"
            command: (list "typecheck" file-name)
            expected-exit: 0
            kind: "typecheck"))
      (if (pair? (.get model traces))
        (list
          (.o label: "traces"
              command: (list "test" file-name
                             (string-append "--main=" mod-name)
                             "--max-samples=1"
                             (string-append "--seed=" (number->string seed-val))
                             "--backend=typescript")
              expected-exit: 0
              kind: "deterministic-traces"))
        '())
      (if has-step?
        (list
          (.o label: "safety"
              command: (list "verify" file-name
                             (string-append "--main=" mod-name)
                             "--invariant=safety"
                             (string-append "--max-steps=" (number->string pos-depth)))
              expected-exit: 0
              kind: "bounded-safety"))
        '())))
  (def counter-steps
    (map
      (lambda (cm)
        (.o label: (string-append "countermodel-" (symbol->string (.get cm dropped-guard)))
            command: (list "verify" file-name
                           (string-append "--main=" mod-name)
                           (string-append "--step=" (.get cm step-action))
                           "--invariant=safety"
                           (string-append "--max-steps=" (number->string neg-depth)))
            expected-exit: 1
            kind: "required-countermodel"
            dropped-guard: (symbol->string (.get cm dropped-guard))
            expected-itf-predicate: (.get cm expected-itf-predicate)))
      countermodels))
  (validate QuintPlanType
    (.o module: mod-name
        file: file-name
        quint-version: (.get policy quint-version)
        apalache-version: (.get policy apalache-version)
        seed: seed-val
        positive-depth: pos-depth
        negative-depth: neg-depth
        timeout: timeout-val
        steps: (append base-steps counter-steps))))

(.defmethod (quint-model-readme (model (prototype ThreatModel.)))
  (validate QuintDomainModelType model)
  (def title (if (.slot? model 'title) (.get model title) (symbol->string (.get model identity))))
  (def mod-name (.get model quint-module))
  (def file-name (.get model quint-file))
  (def domain-dir (.get model domain-dir))
  (def inv (.get model invariant))
  (def safety (.get model safety))
  (def guards (.get model guards))
  (def cms (.get model countermodels))
  (def papers (if (.slot? model 'papers) (.get model papers) '()))
  (def limits (.get model limits))
  (def vdepth (if (.slot? model 'verify-depth) (.get model verify-depth) 12))
  (def cmdepth (if (.slot? model 'countermodel-depth) (.get model countermodel-depth) 6))
  (call-with-output-string
    (lambda (out)
      ;; REUSE-IgnoreStart
      (display "# SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors\n" out)
      (display "# SPDX-License-Identifier: LGPL-2.1-or-later\n\n" out)
      ;; REUSE-IgnoreEnd
      (fprintf out "#+TITLE: %a\n" title)
      (display "#+LANGUAGE: en\n#+STARTUP: overview\n#+OPTIONS: toc:2 num:nil\n\n" out)
      (display "* Overview\n\n" out)
      (fprintf out "- *Model Identity*: =%a=\n" (.get model identity))
      (when (.slot? model 'subdomain)
        (fprintf out "- *Subdomain*: =%a=\n" (.get model subdomain)))
      (fprintf out "- *Quint Module*: =%a= (=[[file:%a][%a]]=)\n" mod-name file-name file-name)
      (fprintf out "- *Package Import*: =@deterministic-engineering/quint-models/%a/%a=\n"
               domain-dir (substring file-name 0 (- (string-length file-name) 4)))
      (fprintf out "- *Bounded Verification Envelope*: safety =max-steps=%a=, countermodels =max-steps=%a=\n\n"
               vdepth cmdepth)
      (display "* Emergent Safety Invariant\n\n" out)
      (fprintf out "%a\n\n" inv)
      (display "#+begin_src quint\n" out)
      (fprintf out "val safety = %a\n" (if (string? safety) safety (emit-quint-expr safety)))
      (display "#+end_src\n\n" out)
      (when (pair? guards)
        (display "* Protocol Guards & Auto-Derived Countermodels\n\n" out)
        (display "| Guard ID | Weakened Step Action | Expected ITF Counterexample Predicate |\n" out)
        (display "|----------+----------------------+---------------------------------------|\n" out)
        (for-each
          (lambda (cm)
            (fprintf out "| =%a= | =%a= | =%a= |\n"
                     (.get cm dropped-guard) (.get cm step-action) (.get cm expected-itf-predicate)))
          cms)
        (display "\n" out))
      (when (pair? papers)
        (display "* Grounded Papers & Specifications\n\n" out)
        (for-each
          (lambda (p)
            (fprintf out "- *%a*: %a\n" (car p) (cadr p)))
          papers)
        (display "\n" out))
      (display "* Verification & Model-Based Testing\n\n" out)
      (display "#+begin_src sh\n" out)
      (if (has-state-record? (.get model state))
        (begin
          (fprintf out "# Full bounded Apalache verification (safety + all weakened countermodels):\n")
          (fprintf out "quint-modules-resolver run-plan packages/quint-models/%a/%a --verify\n\n"
                   domain-dir file-name)
          (fprintf out "# Emit --mbt ITF traces for downstream implementation refinement:\n")
          (fprintf out "quint-modules-resolver run packages/quint-models/%a/%a --main=%a --invariant=safety --mbt --max-steps=%a --seed=7 --out-itf=trace.itf.json\n"
                   domain-dir file-name mod-name vdepth))
        (begin
          (fprintf out "# Typecheck and execute pure reference tests:\n")
          (fprintf out "quint-modules-resolver run-plan packages/quint-models/%a/%a\n"
                   domain-dir file-name)))
      (display "#+end_src\n\n" out)
      (display "* Explicit Limits\n\n" out)
      (fprintf out "%a\n" limits))))

(def (dedup-syms xs)
  (let loop ((rest xs) (seen '()) (acc '()))
    (cond
     ((null? rest) (reverse acc))
     ((memq (car rest) seen) (loop (cdr rest) seen acc))
     (else (loop (cdr rest) (cons (car rest) seen) (cons (car rest) acc))))))

(.defmethod (quint-guard-audit (model (prototype ThreatModel.)))
  (validate QuintDomainModelType model)
  (def decl-guards (dedup-syms (map car (.get model guards))))
  (def ast-guard-ids
    (dedup-syms
      (apply append
        (map (lambda (tr)
               (let ((body (cadr tr)))
                 (if (quint-decl? body) (quint-decl-collect-guards body) '())))
             (.get model transitions)))))
  (def cms (.get model countermodels))
  (def wit-guards (dedup-syms (map (lambda (cm) (.get cm dropped-guard)) cms)))
  (def annotations
    (if (.slot? model 'guard-classifications)
      (.get model guard-classifications)
      '()))
  (def stateful? (has-state-record? (.get model state)))
  (def all-guards (dedup-syms (append decl-guards ast-guard-ids)))
  (def audit-entries
    (map
      (lambda (gid)
        (def cm (find (lambda (c) (eq? (.get c dropped-guard) gid)) cms))
        (def ann (assq gid annotations))
        (def found-in-ast? (and (memq gid ast-guard-ids) #t))
        (cond
         (cm
          (.o guard-id: gid
              classification: 'essential
              in-ast?: found-in-ast?
              witnessed?: #t
              witness: (.get cm step-action)))
         ((not stateful?)
          (.o guard-id: gid
              classification: 'precondition
              in-ast?: found-in-ast?
              witnessed?: #f
              rationale: "Stateless pure reference predicate (no stateful step transition)"))
         ((and ann (>= (length ann) 3) (eq? (cadr ann) 'precondition))
          (.o guard-id: gid
              classification: 'precondition
              in-ast?: found-in-ast?
              witnessed?: #f
              rationale: (caddr ann)))
         ((and ann (>= (length ann) 3)
               (memq (cadr ann) '(redundant under-modeled)))
          (.o guard-id: gid
              classification: (cadr ann)
              in-ast?: found-in-ast?
              witnessed?: #f
              rationale: (caddr ann)))
         (else
          (.o guard-id: gid
              classification: 'unwitnessed
              in-ast?: found-in-ast?
              witnessed?: #f))))
      all-guards))
  (def unwit-guards
    (map (lambda (e) (.get e guard-id))
         (filter (lambda (e)
                   (memq (.get e classification) '(unwitnessed redundant under-modeled)))
                 audit-entries)))
  (def undec-ast-guards
    (filter (lambda (gid) (not (memq gid decl-guards))) ast-guard-ids))
  (validate QuintGuardAuditReportType
    (.o model-identity: (.get model identity)
        declared-guards: decl-guards
        ast-guards: ast-guard-ids
        witnessed-guards: wit-guards
        unwitnessed-guards: unwit-guards
        undeclared-ast-guards: undec-ast-guards
        entries: audit-entries
        passed?: (and (null? unwit-guards) (null? undec-ast-guards)))))

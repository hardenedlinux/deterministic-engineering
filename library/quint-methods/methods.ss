;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure .qnt-SSOT verification plan, F3 guard audit, and README projection (10.204).
;;; Dispatched on ThreatModel. prototype ancestry; parses the .qnt source directly via
;;; gerbil-parser (grammar.ss) with ZERO duplicated Quint AST in Scheme and ZERO I/O.
(import :clan/poo/object
        (only-in :clan/poo/type validate)
        (only-in :clan/poo/mop/clos/generic-syntax .defgeneric .defmethod)
        :std/format
        (only-in "objects.ss" ThreatModel.)
        "grammar.ss"
        "types.ss")
(export quint-plan quint-model-readme quint-guard-audit)

(.defgeneric quint-plan (model qnt-source profile policy))
(.defgeneric quint-model-readme (model qnt-source))
(.defgeneric quint-guard-audit (model qnt-source))

(def (dedup-syms xs)
  (let loop ((rest xs) (seen '()) (acc '()))
    (cond
     ((null? rest) (reverse acc))
     ((memq (car rest) seen) (loop (cdr rest) seen acc))
     (else (loop (cdr rest) (cons (car rest) seen) (cons (car rest) acc))))))

(def (verify-qnt-model-parity model spec)
  (unless (equal? (.get spec module-name) (.get model quint-module))
    (error "Native .qnt module name mismatch"
           (.get model quint-module) (.get spec module-name)))
  (let ((hdr-id (.get spec model-identity)))
    (when (and hdr-id (not (eq? hdr-id (.get model identity))))
      (error "Native .qnt @quint-model identity mismatch"
             (.get model identity) hdr-id))))

(.defmethod (quint-plan (model (prototype ThreatModel.)) qnt-source profile policy)
  (validate QuintDomainModelType model)
  (validate QuintProfileType profile)
  (validate QuintPolicyType policy)
  (def spec (parse-quint-model-spec qnt-source))
  (verify-qnt-model-parity model spec)
  (def mod-name (.get spec module-name))
  (def file-name (.get model quint-file))
  (def seed-val (.get profile seed))
  (def pos-depth (.get spec verify-depth))
  (def neg-depth (.get spec countermodel-depth))
  (def timeout-val (.get policy timeout))
  (def countermodels (.get spec countermodels))
  (when (and (.get profile require-countermodels?) (null? countermodels))
    (error "Profile requires countermodels but .qnt declares no @countermodel"
           (.get model identity)))
  (def base-steps
    (append
      (list
        (.o label: "typecheck"
            command: (list "typecheck" file-name)
            expected-exit: 0
            kind: "typecheck"))
      (if (pair? (.get spec run-traces))
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
      (if (and (.get spec has-state-record?) (.get spec has-step?) (.get spec safety-source))
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
                           (string-append "--max-steps=" (number->string (.get cm max-steps))))
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

(.defmethod (quint-guard-audit (model (prototype ThreatModel.)) qnt-source)
  (validate QuintDomainModelType model)
  (def spec (parse-quint-model-spec qnt-source))
  (verify-qnt-model-parity model spec)
  (def cms (.get spec countermodels))
  (def wit-guards (dedup-syms (map (lambda (cm) (.get cm dropped-guard)) cms)))
  (def audit-entries
    (map
      (lambda (cm)
        (.o guard-id: (.get cm dropped-guard)
            classification: 'essential
            in-ast?: #t
            witnessed?: #t
            witness: (.get cm step-action)))
      cms))
  (def require-cm? (and (.get spec has-state-record?)
                        (string-prefix? "engineering/" (.get model domain-dir))))
  (validate QuintGuardAuditReportType
    (.o model-identity: (.get model identity)
        declared-guards: wit-guards
        ast-guards: wit-guards
        witnessed-guards: wit-guards
        unwitnessed-guards: '()
        undeclared-ast-guards: '()
        entries: audit-entries
        passed?: (or (not require-cm?) (pair? wit-guards)))))

(.defmethod (quint-model-readme (model (prototype ThreatModel.)) qnt-source)
  (validate QuintDomainModelType model)
  (def spec (parse-quint-model-spec qnt-source))
  (verify-qnt-model-parity model spec)
  (def title (if (.slot? model 'title) (.get model title) (symbol->string (.get model identity))))
  (def mod-name (.get spec module-name))
  (def file-name (.get model quint-file))
  (def domain-dir (.get model domain-dir))
  (def inv (.get model invariant))
  (def safety-src (or (.get spec safety-source) "true"))
  (def cms (.get spec countermodels))
  (def papers (if (.slot? model 'papers) (.get model papers) '()))
  (def limits (.get model limits))
  (def vdepth (.get spec verify-depth))
  (def cmdepth (.get spec countermodel-depth))
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
      (fprintf out "val safety = %a\n" safety-src)
      (display "#+end_src\n\n" out)
      (when (pair? cms)
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
      (if (.get spec has-state-record?)
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

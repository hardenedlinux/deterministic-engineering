;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure Quint source projection and verification plan generation.
;;; Dispatched on prototype ancestry; unknown prototypes fail dispatch. Zero I/O.
(import :clan/poo/object
        (only-in :clan/poo/type validate)
        (only-in :clan/poo/mop/clos/generic-syntax .defgeneric .defmethod)
        :std/format
        (only-in "../threat-capabilities/objects.ss" ThreatModel.)
        "types.ss")
(export quint-module quint-plan)

(.defgeneric quint-module (model))
(.defgeneric quint-plan (model profile policy))

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
      (fprintf out "// Projected from Scheme POO module %a. Do not edit by hand.\n" (.get model identity))
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
          (fprintf out "  %a\n" (cadr tr)))
        transitions)
      (when (has-state-record? state-rows)
        (fprintf out "  val safety = %a\n" safety))
      (for-each
        (lambda (cm)
          (fprintf out "  // Countermodel %a (dropped guard: %a)\n"
                   (.get cm identity) (.get cm dropped-guard))
          (fprintf out "  %a\n" (.get cm counter-action)))
        countermodels)
      (for-each
        (lambda (tr)
          (fprintf out "  %a\n" (cadr tr)))
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

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Typed Structural Quint S-Expression AST DSL & Static Field Validator.
;;; Replaces opaque raw string concatenation in Scheme POO models with first-class
;;; typed S-expression syntax trees that validate state-field references before
;;; emitting canonical .qnt source. Pure; zero I/O.
(export quint-expr?
        quint-decl?
        quint-counter-ast?
        quint-expr-state-refs-valid?
        quint-decl-state-refs-valid?
        quint-counter-ast-state-refs-valid?
        quint-expr-contains-guard?
        quint-decl-contains-guard?
        quint-expr-drop-guard
        quint-decl-drop-guard
        quint-derive-countermodel-decls
        emit-quint-expr
        emit-quint-decl
        emit-quint-counter-ast)

(def +dot-sym+ (string->symbol "."))

(def (join-strings items sep)
  (let loop ((rest items) (acc ""))
    (cond
     ((null? rest) acc)
     ((equal? acc "") (loop (cdr rest) (car rest)))
     (else (loop (cdr rest) (string-append acc sep (car rest)))))))

(def (all-of pred xs)
  (let loop ((rest xs))
    (or (null? rest) (and (pred (car rest)) (loop (cdr rest))))))

(def (update-pair? p)
  (and (list? p) (= (length p) 2) (symbol? (car p)) (quint-expr? (cadr p))))

(def (binding-pair? p)
  (and (list? p) (= (length p) 2) (symbol? (car p)) (quint-expr? (cadr p))))

(def (param-pair? p)
  (and (list? p) (= (length p) 2) (symbol? (car p)) (string? (cadr p))))

(def (quint-expr? e)
  (cond
   ((or (boolean? e) (exact-integer? e) (symbol? e) (string? e)) #t)
   ((not (pair? e)) #f)
   (else
    (def head (car e))
    (def args (cdr e))
    (case head
      ((not size assert)
       (and (= (length args) 1) (quint-expr? (car args))))
      ((and or)
       (and (pair? args) (all-of quint-expr? args)))
      ((= != >= <= > < + - contains subseteq union exclude intersect)
       (and (= (length args) 2) (quint-expr? (car args)) (quint-expr? (cadr args))))
      ((.)
       (and (= (length args) 2) (quint-expr? (car args)) (symbol? (cadr args))))
      ((guard)
       (and (or (= (length args) 2) (= (length args) 3))
            (symbol? (car args))
            (quint-expr? (cadr args))
            (or (= (length args) 2) (quint-expr? (caddr args)))))
      ((exists)
       (and (= (length args) 3)
            (quint-expr? (car args))
            (symbol? (cadr args))
            (quint-expr? (caddr args))))
      ((record)
       (and (pair? args) (all-of update-pair? args)))
      ((set)
       (all-of quint-expr? args))
      ((keep-h)
       (null? args))
      ((set-h)
       (and (pair? args) (all-of update-pair? args)))
      ((if)
       (and (= (length args) 3) (all-of quint-expr? args)))
      ((any all then)
       (and (pair? args) (all-of quint-expr? args)))
      ((nondet)
       (and (= (length args) 2)
            (list? (car args))
            (pair? (car args))
            (all-of binding-pair? (car args))
            (quint-expr? (cadr args))))
      ((call)
       (and (pair? args) (symbol? (car args)) (all-of quint-expr? (cdr args))))
      (else #f)))))

(def (quint-decl? d)
  (and (pair? d)
       (case (car d)
         ((action)
          (let ((rest (cdr d)))
            (or (and (= (length rest) 3)
                     (symbol? (car rest))
                     (null? (cadr rest))
                     (quint-expr? (caddr rest)))
                (and (= (length rest) 4)
                     (symbol? (car rest))
                     (list? (cadr rest))
                     (all-of param-pair? (cadr rest))
                     (string? (caddr rest))
                     (quint-expr? (cadddr rest))))))
         ((pure-def)
          (let ((rest (cdr d)))
            (and (= (length rest) 4)
                 (symbol? (car rest))
                 (list? (cadr rest))
                 (all-of param-pair? (cadr rest))
                 (string? (caddr rest))
                 (quint-expr? (cadddr rest)))))
         ((val pure-val run)
          (and (= (length (cdr d)) 2)
               (symbol? (cadr d))
               (quint-expr? (caddr d))))
         (else #f))))

(def (quint-counter-ast? c)
  (or (quint-decl? c)
      (and (pair? c) (eq? (car c) 'decls) (pair? (cdr c)) (all-of quint-decl? (cdr c)))))

;; Static validation: every (. h field) and (set-h (field val) ...) must reference
;; a declared field symbol in `state-fields`.
(def (quint-expr-state-refs-valid? e state-fields)
  (cond
   ((not (pair? e)) #t)
   (else
    (def head (car e))
    (def args (cdr e))
    (case head
      ((.)
       (let ((recv (car args)) (fld (cadr args)))
         (and (quint-expr-state-refs-valid? recv state-fields)
              (or (not (eq? recv 'h))
                  (and (memq fld state-fields) #t)))))
      ((guard)
       (and (quint-expr-state-refs-valid? (cadr args) state-fields)
            (or (= (length args) 2)
                (quint-expr-state-refs-valid? (caddr args) state-fields))))
      ((exists)
       (and (quint-expr-state-refs-valid? (car args) state-fields)
            (quint-expr-state-refs-valid? (caddr args) state-fields)))
      ((record)
       (all-of (lambda (p) (quint-expr-state-refs-valid? (cadr p) state-fields)) args))
      ((set-h)
       (all-of (lambda (p)
                 (and (memq (car p) state-fields)
                      (quint-expr-state-refs-valid? (cadr p) state-fields)))
               args))
      ((nondet)
       (and (all-of (lambda (p) (quint-expr-state-refs-valid? (cadr p) state-fields)) (car args))
            (quint-expr-state-refs-valid? (cadr args) state-fields)))
      ((call)
       (all-of (lambda (a) (quint-expr-state-refs-valid? a state-fields)) (cdr args)))
      (else
       (all-of (lambda (a) (quint-expr-state-refs-valid? a state-fields)) args))))))

(def (quint-decl-state-refs-valid? d state-fields)
  (if (not (quint-decl? d))
    #f
    (case (car d)
      ((action)
       (let ((body (if (= (length d) 4) (cadddr d) (car (cddddr d)))))
         (quint-expr-state-refs-valid? body state-fields)))
      ((pure-def)
       (quint-expr-state-refs-valid? (car (cddddr d)) state-fields))
      ((val pure-val run)
       (quint-expr-state-refs-valid? (caddr d) state-fields))
      (else #f))))

(def (quint-counter-ast-state-refs-valid? c state-fields)
  (cond
   ((quint-decl? c) (quint-decl-state-refs-valid? c state-fields))
   ((and (pair? c) (eq? (car c) 'decls))
    (all-of (lambda (d) (quint-decl-state-refs-valid? d state-fields)) (cdr c)))
   (else #f)))

(def (any-of pred xs)
  (let loop ((rest xs))
    (and (pair? rest) (or (pred (car rest)) (loop (cdr rest))))))

(def (quint-expr-contains-guard? e target-guard)
  (cond
   ((not (pair? e)) #f)
   ((eq? (car e) 'guard)
    (or (eq? (cadr e) target-guard)
        (quint-expr-contains-guard? (caddr e) target-guard)
        (and (= (length e) 4) (quint-expr-contains-guard? (cadddr e) target-guard))))
   ((memq (car e) '(set-h record))
    (any-of (lambda (p) (quint-expr-contains-guard? (cadr p) target-guard)) (cdr e)))
   ((eq? (car e) 'nondet)
    (or (any-of (lambda (p) (quint-expr-contains-guard? (cadr p) target-guard)) (cadr e))
        (quint-expr-contains-guard? (caddr e) target-guard)))
   ((eq? (car e) 'exists)
    (or (quint-expr-contains-guard? (cadr e) target-guard)
        (quint-expr-contains-guard? (cadddr e) target-guard)))
   ((eq? (car e) 'call)
    (any-of (lambda (a) (quint-expr-contains-guard? a target-guard)) (cddr e)))
   ((eq? (car e) +dot-sym+) #f)
   (else
    (any-of (lambda (a) (quint-expr-contains-guard? a target-guard)) (cdr e)))))

(def (quint-decl-contains-guard? d target-guard)
  (if (not (quint-decl? d))
    #f
    (case (car d)
      ((action)
       (let ((body (if (= (length d) 4) (cadddr d) (car (cddddr d)))))
         (quint-expr-contains-guard? body target-guard)))
      ((pure-def)
       (quint-expr-contains-guard? (car (cddddr d)) target-guard))
      ((val pure-val run)
       (quint-expr-contains-guard? (caddr d) target-guard))
      (else #f))))

;; Automatic guard pruning metaprogramming: structurally rewrites
;; (guard target-id expr [fallback]) -> fallback (default #t) inside an AST while keeping all other guards intact.
(def (quint-expr-drop-guard e target-guard)
  (cond
   ((not (pair? e)) e)
   ((eq? (car e) 'guard)
    (if (eq? (cadr e) target-guard)
      (if (= (length e) 4) (cadddr e) #t)
      (if (= (length e) 4)
        (list 'guard (cadr e)
              (quint-expr-drop-guard (caddr e) target-guard)
              (quint-expr-drop-guard (cadddr e) target-guard))
        (list 'guard (cadr e) (quint-expr-drop-guard (caddr e) target-guard)))))
   ((memq (car e) '(set-h record))
    (cons (car e)
          (map (lambda (p) (list (car p) (quint-expr-drop-guard (cadr p) target-guard)))
               (cdr e))))
   ((eq? (car e) 'nondet)
    (list 'nondet
          (map (lambda (p) (list (car p) (quint-expr-drop-guard (cadr p) target-guard)))
               (cadr e))
          (quint-expr-drop-guard (caddr e) target-guard)))
   ((eq? (car e) 'exists)
    (list 'exists
          (quint-expr-drop-guard (cadr e) target-guard)
          (caddr e)
          (quint-expr-drop-guard (cadddr e) target-guard)))
   ((eq? (car e) 'call)
    (cons 'call (cons (cadr e) (map (lambda (a) (quint-expr-drop-guard a target-guard)) (cddr e)))))
   ((eq? (car e) +dot-sym+) e)
   (else
    (cons (car e) (map (lambda (a) (quint-expr-drop-guard a target-guard)) (cdr e))))))

(def (quint-decl-drop-guard d target-guard new-name)
  (case (car d)
    ((action)
     (if (= (length d) 4)
       (list 'action new-name '() (quint-expr-drop-guard (cadddr d) target-guard))
       (list 'action new-name (caddr d) (cadddr d)
             (quint-expr-drop-guard (car (cddddr d)) target-guard))))
    (else (error "quint-decl-drop-guard requires an action declaration" d))))

(def (quint-derive-countermodel-decls base-decl target-guard derived-name step-name (step-call #f))
  (def derived-act (quint-decl-drop-guard base-decl target-guard derived-name))
  (list 'decls
        derived-act
        (list 'action step-name '() (list 'any 'step (or step-call derived-name)))))

(def (emit-quint-operand e)
  (def s (emit-quint-expr e))
  (if (and (pair? e) (memq (car e) '(if any all nondet)))
    (string-append "(" s ")")
    s))

(def (emit-quint-expr e)
  (cond
   ((boolean? e) (if e "true" "false"))
   ((exact-integer? e) (number->string e))
   ((symbol? e) (symbol->string e))
   ((string? e) (string-append "\"" e "\""))
   ((pair? e)
    (def head (car e))
    (def args (cdr e))
    (case head
      ((not) (string-append "not(" (emit-quint-expr (car args)) ")"))
      ((size) (string-append "size(" (emit-quint-expr (car args)) ")"))
      ((assert) (string-append "assert(" (emit-quint-expr (car args)) ")"))
      ((and) (string-append "(" (join-strings (map emit-quint-operand args) " and ") ")"))
      ((or) (string-append "(" (join-strings (map emit-quint-operand args) " or ") ")"))
      ((=) (string-append (emit-quint-operand (car args)) " == " (emit-quint-operand (cadr args))))
      ((!=) (string-append (emit-quint-operand (car args)) " != " (emit-quint-operand (cadr args))))
      ((>=) (string-append (emit-quint-operand (car args)) " >= " (emit-quint-operand (cadr args))))
      ((<=) (string-append (emit-quint-operand (car args)) " <= " (emit-quint-operand (cadr args))))
      ((>) (string-append (emit-quint-operand (car args)) " > " (emit-quint-operand (cadr args))))
      ((<) (string-append (emit-quint-operand (car args)) " < " (emit-quint-operand (cadr args))))
      ((+) (string-append "(" (emit-quint-operand (car args)) " + " (emit-quint-operand (cadr args)) ")"))
      ((-) (string-append "(" (emit-quint-operand (car args)) " - " (emit-quint-operand (cadr args)) ")"))
      ((.) (string-append (emit-quint-expr (car args)) "." (symbol->string (cadr args))))
      ((guard) (emit-quint-expr (cadr args)))
      ((exists)
       (string-append (emit-quint-expr (car args)) ".exists("
                      (symbol->string (cadr args)) " => "
                      (emit-quint-expr (caddr args)) ")"))
      ((record)
       (string-append "{ "
                      (join-strings
                        (map (lambda (p)
                               (string-append (symbol->string (car p)) ": " (emit-quint-expr (cadr p))))
                             args)
                        ", ")
                      " }"))
      ((set) (string-append "Set(" (join-strings (map emit-quint-expr args) ", ") ")"))
      ((contains) (string-append (emit-quint-expr (car args)) ".contains(" (emit-quint-expr (cadr args)) ")"))
      ((subseteq) (string-append (emit-quint-expr (car args)) ".subseteq(" (emit-quint-expr (cadr args)) ")"))
      ((union) (string-append (emit-quint-expr (car args)) ".union(" (emit-quint-expr (cadr args)) ")"))
      ((exclude) (string-append (emit-quint-expr (car args)) ".exclude(" (emit-quint-expr (cadr args)) ")"))
      ((intersect) (string-append (emit-quint-expr (car args)) ".intersect(" (emit-quint-expr (cadr args)) ")"))
      ((keep-h) "h' = h")
      ((set-h)
       (string-append "h' = h"
                      (join-strings
                        (map (lambda (p)
                               (string-append ".with(\"" (symbol->string (car p)) "\", "
                                              (emit-quint-expr (cadr p)) ")"))
                             args)
                        "")))
      ((if)
       (string-append "if (" (emit-quint-expr (car args)) ") "
                      (emit-quint-expr (cadr args))
                      " else "
                      (emit-quint-expr (caddr args))))
      ((any)
       (string-append "any { " (join-strings (map emit-quint-expr args) ", ") " }"))
      ((all)
       (string-append "all { " (join-strings (map emit-quint-expr args) ", ") " }"))
      ((nondet)
       (string-append "{ "
                      (join-strings
                        (map (lambda (p)
                               (string-append "nondet " (symbol->string (car p)) " = "
                                              (emit-quint-expr (cadr p)) ".oneOf()"))
                             (car args))
                        "\n    ")
                      "\n    "
                      (emit-quint-expr (cadr args))
                      " }"))
      ((then)
       (let ((parts (map emit-quint-expr args)))
         (let loop ((rest (cdr parts)) (acc (car parts)))
           (if (null? rest)
             acc
             (loop (cdr rest) (string-append acc ".then(" (car rest) ")"))))))
      ((call)
       (string-append (symbol->string (car args))
                      "(" (join-strings (map emit-quint-expr (cdr args)) ", ") ")"))
      (else (error "Unknown Quint AST form" head))))
   (else (error "Invalid Quint AST expression" e))))

(def (emit-quint-decl d)
  (case (car d)
    ((action)
     (if (= (length d) 4)
       (string-append "action " (symbol->string (cadr d)) " = " (emit-quint-expr (cadddr d)))
       (string-append "action " (symbol->string (cadr d))
                      "("
                      (join-strings
                        (map (lambda (p) (string-append (symbol->string (car p)) ": " (cadr p)))
                             (caddr d))
                        ", ")
                      "): " (cadddr d) " = "
                      (emit-quint-expr (car (cddddr d))))))
    ((pure-def)
     (string-append "pure def " (symbol->string (cadr d))
                    "("
                    (join-strings
                      (map (lambda (p) (string-append (symbol->string (car p)) ": " (cadr p)))
                           (caddr d))
                      ", ")
                    "): " (cadddr d) " = "
                    (emit-quint-expr (car (cddddr d)))))
    ((val)
     (string-append "val " (symbol->string (cadr d)) " = " (emit-quint-expr (caddr d))))
    ((pure-val)
     (string-append "pure val " (symbol->string (cadr d)) " = " (emit-quint-expr (caddr d))))
    ((run)
     (string-append "run " (symbol->string (cadr d)) " = " (emit-quint-expr (caddr d))))
    (else (error "Unknown Quint AST declaration" d))))

(def (emit-quint-counter-ast c)
  (cond
   ((string? c) c)
   ((quint-decl? c) (emit-quint-decl c))
   ((and (pair? c) (eq? (car c) 'decls))
    (join-strings (map emit-quint-decl (cdr c)) "\n  "))
   (else (error "Invalid Quint countermodel AST" c))))

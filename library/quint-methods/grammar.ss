;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Native Gerbil-Parser deterministic LR structural grammar pack for Quint 0.33.0.
;;; Uses :gerbil-parser/language-support/grammar (deflanguage) to compile a
;;; zero-ambiguity, source-preserving structural parser directly inside Gerbil
;;; Scheme, plus parser-verified SpanEdit rewriting via :gerbil-parser/graph-support/edit.
(import (only-in :clan/poo/object .o)
        (only-in :gerbil-parser/language-support/grammar deflanguage)
        (only-in :gerbil-parser/language-support/entry
                 deflanguage-parser-loader language-parser-entry-ref)
        (only-in :gerbil-parser/execution/artifact
                 parse-artifact-success?
                 parse-artifact-valid?
                 parse-artifact-valid-for-source?
                 parse-artifact-roundtrip
                 parse-artifact-events
                 event-kind
                 event-start
                 event-end
                 token-event?
                 token-event-lexeme)
        (only-in :gerbil-parser/graph-support/edit
                 span-edit-insert
                 span-edit-replace
                 utf8-byte-slice
                 apply-span-edits/verified))
(export quint-core-syntax
        quint-core-language
        quint-core-language-grammar
        parse-quint-core
        quint-source-qualified?
        quint-cst-module-info
        quint-cst-declarations
        parse-quint-model-spec
        quint-span-append-decl
        quint-span-strengthen-safety
        quint-span-extend-step
        quint-span-compose-overlay)

(deflanguage quint-core
  (syntax
    (lexical
     (root source-file)
     (lex
      (horizontal-whitespace HorizontalWhitespace (horizontal-whitespace+))
      (newline Newline (newline+))
      (comment Comment (line-comment "//"))
      (string String (quoted-string "\""))
      (number Number (decimal-digit+))
      (identifier Identifier (identifier))
      (punctuation Punctuation
                   (literals "..." "==" "!=" ">=" "<=" "=>" "->" ".*" "'" "=" "<" ">" "+" "-" "*" "/"
                             "(" ")" "[" "]" "{" "}" "," ":" ".")))
     (extras horizontal-whitespace newline comment)
     (keywords
      (kw-module "module")
      (kw-import "import")
      (kw-from "from")
      (kw-const "const")
      (kw-type "type")
      (kw-var "var")
      (kw-pure "pure")
      (kw-def "def")
      (kw-val "val")
      (kw-action "action")
      (kw-run "run")
      (kw-if "if")
      (kw-else "else")
      (kw-and "and")
      (kw-or "or")
      (kw-any "any")
      (kw-all "all")
      (kw-nondet "nondet")
      (kw-true "true")
      (kw-false "false"))
     (recoveries (module "GERBIL-PARSER-QUINT-V1" preserve-source))
     (conflicts selective-glr)
     (case-insensitive #f)))
  (rules
    (source-file
     (node SourceFile (repeat (field module module-decl))))
    (module-decl
     (node Module "module" (field name identifier) "{"
           (repeat (field decl module-item))
           "}"))
    (module-item
     (choice import-decl const-decl type-decl var-decl op-decl))
    (import-decl
     (node ImportDeclaration "import" (field target identifier)
           (optional (seq "(" (field binding param-binding)
                          (repeat (seq "," (field binding param-binding))) ")"))
           ".*" (optional (seq "from" (field source string)))))
    (param-binding
     (node ParamBinding (field name identifier) "=" (field value expr)))
    (const-decl
     (node ConstDeclaration "const" (field name identifier) ":" (field type type-expr)))
    (type-decl
     (node TypeDeclaration "type" (field name identifier) "=" (field type type-expr)))
    (var-decl
     (node VarDeclaration "var" (field name identifier) ":" (field type type-expr)))
    (op-decl
     (node OpDeclaration
           (optional "pure")
           (field qualifier (choice "action" "val" "def" "run"))
           (field name identifier)
           (optional (seq "("
                          (optional (seq (field param param-decl)
                                         (repeat (seq "," (field param param-decl)))))
                          ")"))
           (optional (seq ":" (field return-type type-expr)))
           "=" (field body expr)))
    (param-decl
     (node ParamDecl (field name identifier) ":" (field type type-expr)))
    (type-expr
     (choice
      (node GenericType (field name identifier) "[" (field arg type-expr)
            (repeat (seq "," (field arg type-expr))) "]")
      (node RecordType "{"
            (optional (seq (field field-decl type-field)
                           (repeat (seq "," (field field-decl type-field)))))
            "}")
      (node NamedType (field name identifier))))
    (type-field
     (node TypeField (field name identifier) ":" (field type type-expr)))

    ;; Stratified unambiguous expression grammar:
    (expr
     (choice
      if-expr
      lambda-expr
      assign-expr
      or-expr))
    (if-expr
     (node IfExpr "if" "(" (field cond expr) ")"
           (field then-branch expr) "else" (field else-branch expr)))
    (lambda-expr
     (node LambdaExpr (field param identifier) "=>" (field body expr)))
    (assign-expr
     (node AssignExpr (field target identifier) "'" "=" (field value expr)))
    (or-expr
     (choice
      (node OrExpr (field left or-expr) "or" (field right and-expr))
      and-expr))
    (and-expr
     (choice
      (node AndExpr (field left and-expr) "and" (field right cmp-expr))
      cmp-expr))
    (cmp-expr
     (choice
      (node CmpExpr (field left add-expr)
            (field op (choice "==" "!=" "<" ">" "<=" ">="))
            (field right add-expr))
      add-expr))
    (add-expr
     (choice
      (node AddExpr (field left add-expr)
            (field op (choice "+" "-"))
            (field right mul-expr))
      mul-expr))
    (mul-expr
     (choice
      (node MulExpr (field left mul-expr)
            (field op (choice "*" "/"))
            (field right unary-expr))
      unary-expr))
    (unary-expr
     (choice
      (node UnaryNegExpr "-" (field operand unary-expr))
      postfix-expr))
    (postfix-expr
     (choice
      (node MethodCallExpr (field receiver postfix-expr) "." (field method identifier)
            "(" (optional (seq (field arg expr) (repeat (seq "," (field arg expr))))) ")")
      (node FieldAccessExpr (field receiver postfix-expr) "." (field field identifier))
      primary-expr))
    (primary-expr
     (choice
      (node CallExpr (field callee identifier)
            "(" (optional (seq (field arg expr) (repeat (seq "," (field arg expr))))) ")")
      any-expr
      all-expr
      nondet-block-expr
      record-expr
      (node GroupedExpr "(" (field inner expr) ")")
      (node BoolLiteral (field value (choice "true" "false")))
      (node NumberLiteral (field value number))
      (node StringLiteral (field value string))
      (node NameExpr (field name identifier))))
    (any-expr
     (node AnyExpr "any" "{"
           (optional (seq (field branch expr) (repeat (seq "," (field branch expr)))))
           "}"))
    (all-expr
     (node AllExpr "all" "{"
           (optional (seq (field item expr) (repeat (seq "," (field item expr)))))
           "}"))
    (nondet-block-expr
     (node NondetBlockExpr "{"
           (field first-nondet nondet-stmt)
           (repeat (field more-nondet nondet-stmt))
           (field body expr)
           "}"))
    (nondet-stmt
     (node NondetStmt "nondet" (field name identifier) "=" (field domain expr)))
    (record-expr
     (node RecordExpr "{"
           (field entry record-entry)
           (repeat (seq "," (field entry record-entry)))
           "}"))
    (record-entry
     (choice
      (node RecordSpread "..." (field base expr))
      (node RecordField (field name identifier) ":" (field value expr))))))

(deflanguage-parser-loader quint-core-language
  (grammar quint-core-syntax)
  (parse parse-quint-core)
  (slots metadata: (.o language: "quint" version: "0.33.0" contract: "quint.native-core.v1")))

(def quint-core-language-grammar
  (language-parser-entry-ref quint-core-language 'descriptor))

(def (quint-source-qualified? source)
  (def art (parse-quint-core source))
  (and (parse-artifact-success? art)
       (parse-artifact-valid? art)
       (parse-artifact-valid-for-source? art source)
       (equal? (parse-artifact-roundtrip art) source)))

(def (quint-verify-source-or-error next-src ctx-label)
  (def art (parse-quint-core next-src))
  (unless (and (parse-artifact-success? art)
               (parse-artifact-valid-for-source? art next-src))
    (error "gerbil-parser verification failed after SpanEdit" ctx-label))
  art)

(def (event-list-of art)
  (def events (parse-artifact-events art))
  (if (vector? events) (vector->list events) events))

(def (normalize-ws str)
  (def len (string-length str))
  (let loop ((i 0) (out '()) (in-ws? #t))
    (if (>= i len)
      (let ((chars (reverse out)))
        (list->string
          (if (and (pair? chars) (char=? (car (reverse chars)) #\space))
            (reverse (cdr (reverse chars)))
            chars)))
      (let ((ch (string-ref str i)))
        (if (or (char=? ch #\space) (char=? ch #\tab) (char=? ch #\newline) (char=? ch #\return))
          (if in-ws?
            (loop (+ i 1) out #t)
            (loop (+ i 1) (cons #\space out) #t))
          (loop (+ i 1) (cons ch out) #f))))))

;; Extracts the top-level Module's name, name byte span, and outer brace offsets.
(def (quint-cst-module-info source)
  (def art (parse-quint-core source))
  (unless (parse-artifact-success? art)
    (error "quint-cst-module-info: failed to parse Quint source"))
  (def events (event-list-of art))
  (def mod-name #f)
  (def name-start #f)
  (def name-end #f)
  (def open-brace #f)
  (def close-brace #f)
  (def in-mod? #f)
  (def in-mod-name? #f)
  (def mod-id #f)
  (def field-depth 0)
  (for-each
    (lambda (ev)
      (let ((k (event-kind ev)))
        (cond
         ((and (eq? k 'start-node) (not in-mod?) (eq? (vector-ref ev 2) 'Module))
          (set! in-mod? #t)
          (set! mod-id (vector-ref ev 1))
          (set! field-depth 0))
         ((and (eq? k 'finish-node) in-mod? (= (vector-ref ev 1) mod-id))
          (set! close-brace (- (event-end ev) 1))
          (set! in-mod? #f))
         ((and in-mod? (eq? k 'start-field))
          (when (and (= field-depth 0) (eq? (vector-ref ev 1) 'name))
            (set! in-mod-name? #t))
          (set! field-depth (+ field-depth 1)))
         ((and in-mod? (eq? k 'finish-field))
          (set! field-depth (- field-depth 1))
          (when (and (= field-depth 0) (eq? (vector-ref ev 1) 'name))
            (set! in-mod-name? #f)))
         ((and in-mod? (token-event? ev))
          (when (and in-mod-name? (not mod-name))
            (set! mod-name (token-event-lexeme ev))
            (set! name-start (event-start ev))
            (set! name-end (event-end ev)))
          (when (and (= field-depth 0) (not open-brace) (equal? (token-event-lexeme ev) "{"))
            (set! open-brace (event-start ev)))))))
    events)
  (unless (and mod-name name-start name-end open-brace close-brace)
    (error "quint-cst-module-info: no Module node found"))
  (list (cons 'name mod-name)
        (cons 'name-start name-start)
        (cons 'name-end name-end)
        (cons 'open-brace open-brace)
        (cons 'close-brace close-brace)))

;; Walks gerbil-parser's CST event stream (O(n)) to extract top-level Quint
;; declarations with exact UTF-8 byte spans: ((kind . sym) (qualifier . str/#f)
;; (name . str) (start . int) (end . int) (body-start . int) (body-end . int)
;; (body-kind . sym/#f)).
(def (quint-cst-declarations source)
  (def art (parse-quint-core source))
  (unless (parse-artifact-success? art)
    (error "quint-cst-declarations: failed to parse Quint source"))
  (def decl-kinds '(ImportDeclaration ConstDeclaration TypeDeclaration VarDeclaration OpDeclaration))
  (def results '())
  (def active-kind #f)
  (def active-id #f)
  (def active-start #f)
  (def active-name #f)
  (def active-qualifier #f)
  (def active-body-start #f)
  (def active-body-end #f)
  (def active-body-kind #f)
  (def active-source-start #f)
  (def active-source-end #f)
  (def active-source-lexeme #f)
  (def in-name-field? #f)
  (def in-qual-field? #f)
  (def in-body-field? #f)
  (def in-source-field? #f)
  (def field-depth 0)
  (for-each
    (lambda (ev)
      (let ((k (event-kind ev)))
        (cond
         ((and (eq? k 'start-node) (not active-kind) (memq (vector-ref ev 2) decl-kinds))
          (set! active-kind (vector-ref ev 2))
          (set! active-id (vector-ref ev 1))
          (set! active-start (event-start ev))
          (set! active-name #f)
          (set! active-qualifier #f)
          (set! active-body-start #f)
          (set! active-body-end #f)
          (set! active-body-kind #f)
          (set! active-source-start #f)
          (set! active-source-end #f)
          (set! active-source-lexeme #f)
          (set! in-name-field? #f)
          (set! in-qual-field? #f)
          (set! in-body-field? #f)
          (set! in-source-field? #f)
          (set! field-depth 0))
         ((and (eq? k 'finish-node) active-kind (= (vector-ref ev 1) active-id))
          (set! results
                (cons (list (cons 'kind active-kind)
                            (cons 'qualifier active-qualifier)
                            (cons 'name (or active-name ""))
                            (cons 'start active-start)
                            (cons 'end (event-end ev))
                            (cons 'body-start active-body-start)
                            (cons 'body-end active-body-end)
                            (cons 'body-kind active-body-kind)
                            (cons 'source-start active-source-start)
                            (cons 'source-end active-source-end)
                            (cons 'source-lexeme active-source-lexeme))
                      results))
          (set! active-kind #f)
          (set! active-id #f))
         ((and active-kind (eq? k 'start-node) in-body-field? (not active-body-kind))
          (set! active-body-kind (vector-ref ev 2)))
         ((and active-kind (eq? k 'start-field))
          (let ((fname (vector-ref ev 1)))
            (when (and (= field-depth 0) (or (eq? fname 'name) (eq? fname 'target)))
              (set! in-name-field? #t))
            (when (and (= field-depth 0) (eq? fname 'qualifier))
              (set! in-qual-field? #t))
            (when (and (= field-depth 0) (eq? fname 'source))
              (set! in-source-field? #t))
            (when (and (= field-depth 0) (or (eq? fname 'body) (eq? fname 'type)))
              (set! active-body-start (event-start ev))
              (set! in-body-field? #t))
            (set! field-depth (+ field-depth 1))))
         ((and active-kind (eq? k 'finish-field))
          (set! field-depth (- field-depth 1))
          (let ((fname (vector-ref ev 1)))
            (when (and (= field-depth 0) (or (eq? fname 'name) (eq? fname 'target)))
              (set! in-name-field? #f))
            (when (and (= field-depth 0) (eq? fname 'qualifier))
              (set! in-qual-field? #f))
            (when (and (= field-depth 0) (eq? fname 'source))
              (set! in-source-field? #f))
            (when (and (= field-depth 0) (or (eq? fname 'body) (eq? fname 'type)))
              (set! active-body-end (event-end ev))
              (set! in-body-field? #f))))
         ((and active-kind in-name-field? (token-event? ev) (not active-name))
          (set! active-name (token-event-lexeme ev)))
         ((and active-kind in-qual-field? (token-event? ev) (not active-qualifier))
          (set! active-qualifier (token-event-lexeme ev)))
         ((and active-kind in-source-field? (token-event? ev) (not active-source-lexeme))
          (set! active-source-lexeme (token-event-lexeme ev))
          (set! active-source-start (event-start ev))
          (set! active-source-end (event-end ev))))))
    (event-list-of art))
  (reverse results))

;; Structural CST extraction of direct TypeField entries inside a RecordType span.
(def (quint-cst-type-fields source bytes span-start span-end)
  (def art (parse-quint-core source))
  (def results '())
  (def rtype-depth 0)
  (def tf-id #f)
  (def tf-name #f)
  (def tf-tstart #f)
  (def tf-tend #f)
  (def in-name? #f)
  (def field-depth 0)
  (for-each
    (lambda (ev)
      (let* ((k (event-kind ev))
             (s (event-start ev))
             (e (event-end ev))
             (in-range?
              (if (or (eq? k 'finish-node) (eq? k 'finish-field))
                (and (integer? e) (> e span-start) (<= e span-end))
                (and (integer? s) (>= s span-start) (< s span-end)))))
        (when in-range?
          (cond
           ((and (eq? k 'start-node) (eq? (vector-ref ev 2) 'RecordType))
            (set! rtype-depth (+ rtype-depth 1)))
           ((and (eq? k 'finish-node) (eq? (vector-ref ev 2) 'RecordType))
            (set! rtype-depth (- rtype-depth 1)))
           ((and (= rtype-depth 1) (not tf-id) (eq? k 'start-node) (eq? (vector-ref ev 2) 'TypeField))
            (set! tf-id (vector-ref ev 1))
            (set! tf-name #f)
            (set! tf-tstart #f)
            (set! tf-tend #f)
            (set! in-name? #f)
            (set! field-depth 0))
           ((and tf-id (eq? k 'finish-node) (= (vector-ref ev 1) tf-id))
            (when (and tf-name tf-tstart tf-tend)
              (set! results (cons (list (cons 'name tf-name)
                                        (cons 'type (utf8-byte-slice bytes tf-tstart tf-tend)))
                                  results)))
            (set! tf-id #f))
           ((and tf-id (eq? k 'start-field))
            (let ((fn (vector-ref ev 1)))
              (when (and (= field-depth 0) (eq? fn 'name)) (set! in-name? #t))
              (when (and (= field-depth 0) (eq? fn 'type)) (set! tf-tstart s))
              (set! field-depth (+ field-depth 1))))
           ((and tf-id (eq? k 'finish-field))
            (set! field-depth (- field-depth 1))
            (let ((fn (vector-ref ev 1)))
              (when (and (= field-depth 0) (eq? fn 'name)) (set! in-name? #f))
              (when (and (= field-depth 0) (eq? fn 'type)) (set! tf-tend e))))
           ((and tf-id in-name? (token-event? ev) (not tf-name))
            (set! tf-name (token-event-lexeme ev)))))))
    (event-list-of art))
  (reverse results))

;; Structural CST extraction of direct RecordField entries inside a RecordExpr span.
(def (quint-cst-record-fields source bytes span-start span-end)
  (def art (parse-quint-core source))
  (def results '())
  (def rec-depth 0)
  (def rf-id #f)
  (def rf-name #f)
  (def rf-vstart #f)
  (def rf-vend #f)
  (def in-name? #f)
  (def field-depth 0)
  (for-each
    (lambda (ev)
      (let* ((k (event-kind ev))
             (s (event-start ev))
             (e (event-end ev))
             (in-range?
              (if (or (eq? k 'finish-node) (eq? k 'finish-field))
                (and (integer? e) (> e span-start) (<= e span-end))
                (and (integer? s) (>= s span-start) (< s span-end)))))
        (when in-range?
          (cond
           ((and (eq? k 'start-node) (eq? (vector-ref ev 2) 'RecordExpr))
            (set! rec-depth (+ rec-depth 1)))
           ((and (eq? k 'finish-node) (eq? (vector-ref ev 2) 'RecordExpr))
            (set! rec-depth (- rec-depth 1)))
           ((and (= rec-depth 1) (not rf-id) (eq? k 'start-node) (eq? (vector-ref ev 2) 'RecordField))
            (set! rf-id (vector-ref ev 1))
            (set! rf-name #f)
            (set! rf-vstart #f)
            (set! rf-vend #f)
            (set! in-name? #f)
            (set! field-depth 0))
           ((and rf-id (eq? k 'finish-node) (= (vector-ref ev 1) rf-id))
            (when (and rf-name rf-vstart rf-vend)
              (set! results (cons (list (cons 'name rf-name)
                                        (cons 'val-start rf-vstart)
                                        (cons 'val-end rf-vend)
                                        (cons 'value (utf8-byte-slice bytes rf-vstart rf-vend)))
                                  results)))
            (set! rf-id #f))
           ((and rf-id (eq? k 'start-field))
            (let ((fn (vector-ref ev 1)))
              (when (and (= field-depth 0) (eq? fn 'name)) (set! in-name? #t))
              (when (and (= field-depth 0) (eq? fn 'value)) (set! rf-vstart s))
              (set! field-depth (+ field-depth 1))))
           ((and rf-id (eq? k 'finish-field))
            (set! field-depth (- field-depth 1))
            (let ((fn (vector-ref ev 1)))
              (when (and (= field-depth 0) (eq? fn 'name)) (set! in-name? #f))
              (when (and (= field-depth 0) (eq? fn 'value)) (set! rf-vend e))))
           ((and rf-id in-name? (token-event? ev) (not rf-name))
            (set! rf-name (token-event-lexeme ev)))))))
    (event-list-of art))
  (reverse results))

(def (find-decl-by-name decls name)
  (let loop ((rest decls))
    (cond
     ((null? rest) #f)
     ((equal? (cdr (assq 'name (car rest))) name) (car rest))
     (else (loop (cdr rest))))))

(def (find-field-by-name fields name)
  (let loop ((rest fields))
    (cond
     ((null? rest) #f)
     ((equal? (cdr (assq 'name (car rest))) name) (car rest))
     (else (loop (cdr rest))))))

(def (join-str-list xs sep)
  (let loop ((rest xs) (acc ""))
    (cond
     ((null? rest) acc)
     ((equal? acc "") (loop (cdr rest) (car rest)))
     (else (loop (cdr rest) (string-append acc sep (car rest)))))))

;; Parser-verified structural rewriting via gerbil-parser's SpanEdit engine:
;; inserts a new Quint declaration before the closing brace (UTF-8 byte offset)
;; and re-parses the resulting source through parse-quint-core (failing closed on syntax error).
(def (quint-span-append-decl source decl-text)
  (def mod-info (quint-cst-module-info source))
  (def close-pos (cdr (assq 'close-brace mod-info)))
  (def edit (span-edit-insert close-pos (string-append "  " decl-text "\n") label: "append-decl"))
  (apply-span-edits/verified
    source
    (list edit)
    (lambda (next-src) (quint-verify-source-or-error next-src decl-text))))

;; Parser-verified monotonic safety strengthening via CST byte spans:
;; locates `val safety = <body>` via gerbil-parser CST events and rewrites it to
;; `val safety = (<body>) and (<extra-expr>)`.
(def (quint-span-strengthen-safety source extra-expr)
  (def decls (quint-cst-declarations source))
  (def safety-decl (find-decl-by-name decls "safety"))
  (unless safety-decl
    (error "quint-span-strengthen-safety: no 'safety' declaration found"))
  (def bs (cdr (assq 'body-start safety-decl)))
  (def be (cdr (assq 'body-end safety-decl)))
  (def old-body (utf8-byte-slice (string->utf8 source) bs be))
  (def edit (span-edit-replace bs be (string-append "(" old-body ") and (" extra-expr ")")
                               label: "strengthen-safety"))
  (apply-span-edits/verified
    source
    (list edit)
    (lambda (next-src) (quint-verify-source-or-error next-src extra-expr))))

;; Parser-verified step extension via CST byte spans:
;; locates `action step = ...` via gerbil-parser CST events and merges `<extra-branch>`.
(def (quint-span-extend-step source extra-branch)
  (def decls (quint-cst-declarations source))
  (def step-decl (find-decl-by-name decls "step"))
  (unless step-decl
    (error "quint-span-extend-step: no 'step' declaration found"))
  (def bytes (string->utf8 source))
  (def bs (cdr (assq 'body-start step-decl)))
  (def be (cdr (assq 'body-end step-decl)))
  (def edit
    (if (eq? (cdr (assq 'body-kind step-decl)) 'AnyExpr)
      (let ((bounds (find-brace-bounds bytes bs be)))
        (span-edit-insert (cdr bounds) (string-append ", " extra-branch " ") label: "extend-step"))
      (let ((old-body (utf8-byte-slice bytes bs be)))
        (span-edit-replace bs be (string-append "any { " old-body ", " extra-branch " }")
                           label: "extend-step"))))
  (apply-span-edits/verified
    source
    (list edit)
    (lambda (next-src) (quint-verify-source-or-error next-src extra-branch))))

;; Helper: find byte index of first '{' (123) and last '}' (125) inside [start, end).
(def (find-brace-bounds bytes start end)
  (def open-pos
    (let loop ((i start))
      (cond
       ((>= i end) #f)
       ((= (u8vector-ref bytes i) 123) i)
       (else (loop (+ i 1))))))
  (def close-pos
    (let loop ((i (- end 1)))
      (cond
       ((< i start) #f)
       ((= (u8vector-ref bytes i) 125) i)
       (else (loop (- i 1))))))
  (cons open-pos close-pos))

(def (decl-collision-key d)
  (def k (cdr (assq 'kind d)))
  (if (eq? k 'ImportDeclaration)
    #f
    (cons k (cdr (assq 'name d)))))

(def (mergeable-decl? d)
  (def k (cdr (assq 'kind d)))
  (def nm (cdr (assq 'name d)))
  (or (eq? k 'ImportDeclaration)
      (and (eq? k 'TypeDeclaration) (equal? nm "State"))
      (and (eq? k 'OpDeclaration) (member nm '("init" "step" "safety")))))

(def (unquote-quint-string s)
  (if (and (string? s) (>= (string-length s) 2)
           (char=? (string-ref s 0) #\")
           (char=? (string-ref s (- (string-length s) 1)) #\"))
    (substring s 1 (- (string-length s) 1))
    s))

;; Native Gerbil-Parser structural .qnt-to-.qnt overlay composition (zero Node/Bun, zero JSON IR):
;; semantic parity with packages/quint-modules-resolver/src/compose.ts:
;;  - adopts overlay module name
;;  - rewrites base relative imports via optional import-rewriter: and merges/deduplicates overlay imports
;;  - merges State fields with duplicate-skip and type-conflict refusal
;;  - merges/overrides init fields and refuses uninitialized added State fields
;;  - refuses non-mergeable symbol collisions
;;  - inserts non-run overlay declarations before step and run traces at module end
;;  - merges step (AnyExpr or single-action) and monotonically strengthens safety via conjunction
(def (quint-span-compose-overlay base-source overlay-source import-rewriter: (import-rewriter #f))
  (def base-mod (quint-cst-module-info base-source))
  (def ov-mod (quint-cst-module-info overlay-source))
  (def base-decls (quint-cst-declarations base-source))
  (def ov-decls (quint-cst-declarations overlay-source))
  (def base-bytes (string->utf8 base-source))
  (def ov-bytes (string->utf8 overlay-source))
  (def edits '())
  (def (add-edit! e) (set! edits (cons e edits)))

  ;; 0. Classify overlay declarations & reject non-mergeable symbol collisions.
  (def ov-imports '())
  (def ov-mid-texts '())
  (def ov-run-texts '())
  (def base-keys
    (let loop ((xs base-decls) (acc '()))
      (if (null? xs)
        acc
        (let ((k (decl-collision-key (car xs))))
          (loop (cdr xs) (if k (cons k acc) acc))))))
  (for-each
    (lambda (d)
      (let ((k (cdr (assq 'kind d)))
            (q (cdr (assq 'qualifier d)))
            (txt (utf8-byte-slice ov-bytes (cdr (assq 'start d)) (cdr (assq 'end d)))))
        (cond
         ((eq? k 'ImportDeclaration)
          (set! ov-imports (cons txt ov-imports)))
         ((mergeable-decl? d) #t)
         (else
          (let ((ck (decl-collision-key d)))
            (when (and ck (member ck base-keys))
              (error "Overlay redeclares non-mergeable symbol from base module"
                     (cdr (assq 'name d)) (cdr (assq 'name base-mod)))))
          (if (equal? q "run")
            (set! ov-run-texts (cons txt ov-run-texts))
            (set! ov-mid-texts (cons txt ov-mid-texts)))))))
    ov-decls)
  (set! ov-imports (reverse ov-imports))
  (set! ov-mid-texts (reverse ov-mid-texts))
  (set! ov-run-texts (reverse ov-run-texts))

  ;; 1. Adopt overlay module name when different from base.
  (unless (equal? (cdr (assq 'name base-mod)) (cdr (assq 'name ov-mod)))
    (add-edit!
      (span-edit-replace
        (cdr (assq 'name-start base-mod))
        (cdr (assq 'name-end base-mod))
        (cdr (assq 'name ov-mod))
        label: "compose-module-name")))

  ;; 2. Rewrite base relative imports (when import-rewriter is supplied) and merge overlay imports.
  (let* ((base-imports
          (filter (lambda (d) (eq? (cdr (assq 'kind d)) 'ImportDeclaration)) base-decls))
         (base-imp-norms
          (map (lambda (d)
                 (let ((lex (cdr (assq 'source-lexeme d)))
                       (ss (cdr (assq 'source-start d)))
                       (se (cdr (assq 'source-end d))))
                   (when (and import-rewriter lex ss se)
                     (let* ((raw (unquote-quint-string lex))
                            (rewritten (import-rewriter raw)))
                       (when (and (string? rewritten) (not (equal? rewritten raw)))
                         (add-edit!
                           (span-edit-replace ss se (string-append "\"" rewritten "\"")
                                              label: "compose-rewrite-import"))))))
                 (normalize-ws (utf8-byte-slice base-bytes (cdr (assq 'start d)) (cdr (assq 'end d)))))
               base-imports))
         (new-imports
          (filter (lambda (txt) (not (member (normalize-ws txt) base-imp-norms))) ov-imports)))
    (when (pair? new-imports)
      (let ((insert-pos
             (if (pair? base-imports)
               (cdr (assq 'end (car (reverse base-imports))))
               (+ (cdr (assq 'open-brace base-mod)) 1))))
        (add-edit!
          (span-edit-insert
            insert-pos
            (string-append "\n" (join-str-list (map (lambda (s) (string-append "  " s)) new-imports) "\n"))
            label: "compose-imports")))))

  ;; 3. Merge overlay State fields into base State record type (rejecting type conflicts).
  (def added-fields '())
  (let ((b-st (find-decl-by-name base-decls "State"))
        (o-st (find-decl-by-name ov-decls "State")))
    (when (and b-st o-st)
      (let* ((b-fields (quint-cst-type-fields base-source base-bytes
                                              (cdr (assq 'body-start b-st)) (cdr (assq 'body-end b-st))))
             (o-fields (quint-cst-type-fields overlay-source ov-bytes
                                              (cdr (assq 'body-start o-st)) (cdr (assq 'body-end o-st))))
             (new-decls '()))
        (for-each
          (lambda (of)
            (let* ((nm (cdr (assq 'name of)))
                   (ot (cdr (assq 'type of)))
                   (existing (find-field-by-name b-fields nm)))
              (if existing
                (unless (equal? (normalize-ws (cdr (assq 'type existing))) (normalize-ws ot))
                  (error "State field type conflict" nm (cdr (assq 'type existing)) ot))
                (begin
                  (set! added-fields (cons nm added-fields))
                  (set! new-decls (cons (string-append nm ": " ot) new-decls))))))
          o-fields)
        (set! added-fields (reverse added-fields))
        (set! new-decls (reverse new-decls))
        (when (pair? new-decls)
          (let ((b-bounds (find-brace-bounds base-bytes (cdr (assq 'body-start b-st)) (cdr (assq 'body-end b-st)))))
            (add-edit!
              (span-edit-insert
                (cdr b-bounds)
                (string-append (if (pair? b-fields) ", " " ") (join-str-list new-decls ", ") " ")
                label: "compose-state")))))))

  ;; 4. Merge/override overlay init record fields (requiring initializers for added State fields).
  (let ((b-init (find-decl-by-name base-decls "init"))
        (o-init (find-decl-by-name ov-decls "init")))
    (cond
     ((and (not o-init) (pair? added-fields))
      (error "Overlay adds State field(s) but defines no 'action init'" added-fields))
     ((and b-init o-init)
      (let* ((b-fields (quint-cst-record-fields base-source base-bytes
                                                (cdr (assq 'body-start b-init)) (cdr (assq 'body-end b-init))))
             (o-fields (quint-cst-record-fields overlay-source ov-bytes
                                                (cdr (assq 'body-start o-init)) (cdr (assq 'body-end o-init))))
             (o-names (map (lambda (f) (cdr (assq 'name f))) o-fields))
             (new-inits '()))
        (for-each
          (lambda (af)
            (unless (member af o-names)
              (error "Overlay adds State field without initializing it in 'action init'" af)))
          added-fields)
        (for-each
          (lambda (of)
            (let* ((nm (cdr (assq 'name of)))
                   (ov (cdr (assq 'value of)))
                   (existing (find-field-by-name b-fields nm)))
              (if existing
                (add-edit!
                  (span-edit-replace
                    (cdr (assq 'val-start existing))
                    (cdr (assq 'val-end existing))
                    ov
                    label: "compose-init-override"))
                (set! new-inits (cons (string-append nm ": " ov) new-inits)))))
          o-fields)
        (set! new-inits (reverse new-inits))
        (when (pair? new-inits)
          (let ((b-bounds (find-brace-bounds base-bytes (cdr (assq 'body-start b-init)) (cdr (assq 'body-end b-init)))))
            (add-edit!
              (span-edit-insert
                (cdr b-bounds)
                (string-append (if (pair? b-fields) ", " " ") (join-str-list new-inits ", ") " ")
                label: "compose-init"))))))))

  ;; 5. Insert non-run overlay declarations right before base step (if present) and merge step.
  (def b-step (find-decl-by-name base-decls "step"))
  (def o-step (find-decl-by-name ov-decls "step"))
  (def tail-texts '())
  (if b-step
    (begin
      (when (pair? ov-mid-texts)
        (add-edit!
          (span-edit-insert
            (cdr (assq 'start b-step))
            (string-append (join-str-list ov-mid-texts "\n  ") "\n  ")
            label: "compose-mid-decls")))
      (when o-step
        (let* ((b-bs (cdr (assq 'body-start b-step)))
               (b-be (cdr (assq 'body-end b-step)))
               (o-bs (cdr (assq 'body-start o-step)))
               (o-be (cdr (assq 'body-end o-step)))
               (ov-branches
                (if (eq? (cdr (assq 'body-kind o-step)) 'AnyExpr)
                  (let ((o-bounds (find-brace-bounds ov-bytes o-bs o-be)))
                    (utf8-byte-slice ov-bytes (+ (car o-bounds) 1) (cdr o-bounds)))
                  (utf8-byte-slice ov-bytes o-bs o-be))))
          (if (eq? (cdr (assq 'body-kind b-step)) 'AnyExpr)
            (let ((b-bounds (find-brace-bounds base-bytes b-bs b-be)))
              (add-edit!
                (span-edit-insert (cdr b-bounds) (string-append ", " ov-branches) label: "compose-step")))
            (let ((old-body (utf8-byte-slice base-bytes b-bs b-be)))
              (add-edit!
                (span-edit-replace b-bs b-be (string-append "any { " old-body ", " ov-branches " }")
                                   label: "compose-step")))))))
    (begin
      (set! tail-texts (append tail-texts ov-mid-texts))
      (when o-step
        (set! tail-texts
              (append tail-texts
                      (list (utf8-byte-slice ov-bytes (cdr (assq 'start o-step)) (cdr (assq 'end o-step)))))))))

  ;; 6. Monotonically strengthen base safety with overlay safety (or append if base lacked safety).
  (let ((b-safe (find-decl-by-name base-decls "safety"))
        (o-safe (find-decl-by-name ov-decls "safety")))
    (cond
     ((and b-safe o-safe)
      (let* ((bs (cdr (assq 'body-start b-safe)))
             (be (cdr (assq 'body-end b-safe)))
             (old-body (utf8-byte-slice base-bytes bs be))
             (ov-body (utf8-byte-slice ov-bytes (cdr (assq 'body-start o-safe)) (cdr (assq 'body-end o-safe)))))
        (add-edit! (span-edit-replace bs be (string-append "(" old-body ") and (" ov-body ")")
                                      label: "compose-safety"))))
     ((and (not b-safe) o-safe)
      (set! tail-texts
            (append tail-texts
                    (list (utf8-byte-slice ov-bytes (cdr (assq 'start o-safe)) (cdr (assq 'end o-safe)))))))))

  ;; 7. Append run declarations (and any tail declarations) before module closing '}'.
  (set! tail-texts (append tail-texts ov-run-texts))
  (when (pair? tail-texts)
    (add-edit!
      (span-edit-insert
        (cdr (assq 'close-brace base-mod))
        (string-append (join-str-list (map (lambda (s) (string-append "  " s)) tail-texts) "\n") "\n")
        label: "compose-tail")))

  (apply-span-edits/verified
    base-source
    (reverse edits)
    (lambda (next-src) (quint-verify-source-or-error next-src "compose-overlay"))))

;; ── Native .qnt SSOT Specification Parser (10.204) ──────────────────────────
;; Parses .qnt header directives (@quint-model, @verify, @countermodel, Limits)
;; together with the verified gerbil-parser LR CST so Scheme NEVER duplicates
;; state, guards, transitions, safety, traces, or countermodels.

(def (qnt-split-lines str)
  (def len (string-length str))
  (let loop ((i 0) (start 0) (acc '()))
    (cond
     ((>= i len)
      (reverse (cons (substring str start len) acc)))
     ((char=? (string-ref str i) #\newline)
      (let ((end (if (and (> i start) (char=? (string-ref str (- i 1)) #\return)) (- i 1) i)))
        (loop (+ i 1) (+ i 1) (cons (substring str start end) acc))))
     (else (loop (+ i 1) start acc)))))

(def (qnt-trim-ws s)
  (def len (string-length s))
  (def start
    (let loop ((i 0))
      (if (and (< i len) (or (char=? (string-ref s i) #\space) (char=? (string-ref s i) #\tab)))
        (loop (+ i 1))
        i)))
  (def end
    (let loop ((i len))
      (if (and (> i start) (or (char=? (string-ref s (- i 1)) #\space) (char=? (string-ref s (- i 1)) #\tab)))
        (loop (- i 1))
        i)))
  (substring s start end))

(def (qnt-prefix? s prefix)
  (and (>= (string-length s) (string-length prefix))
       (equal? (substring s 0 (string-length prefix)) prefix)))

(def (qnt-after-prefix s prefix)
  (substring s (string-length prefix) (string-length s)))

(def (qnt-find-substr hay needle (start 0))
  (def hlen (string-length hay))
  (def nlen (string-length needle))
  (let loop ((i start))
    (cond
     ((> (+ i nlen) hlen) #f)
     ((equal? (substring hay i (+ i nlen)) needle) i)
     (else (loop (+ i 1))))))

(def (qnt-extract-kv line key)
  (def marker (string-append key "="))
  (def pos (qnt-find-substr line marker))
  (if (not pos)
    #f
    (let* ((vstart (+ pos (string-length marker)))
           (len (string-length line)))
      (cond
       ((>= vstart len) #f)
       ((char=? (string-ref line vstart) #\")
        (let ((qend (qnt-find-substr line "\"" (+ vstart 1))))
          (if qend (substring line (+ vstart 1) qend) #f)))
       (else
        (let loop ((i vstart))
          (if (or (>= i len) (char=? (string-ref line i) #\space) (char=? (string-ref line i) #\tab))
            (substring line vstart i)
            (loop (+ i 1)))))))))

(def (qnt-first-token s)
  (def trimmed (qnt-trim-ws s))
  (def len (string-length trimmed))
  (let loop ((i 0))
    (if (or (>= i len) (char=? (string-ref trimmed i) #\space) (char=? (string-ref trimmed i) #\tab))
      (substring trimmed 0 i)
      (loop (+ i 1)))))

(def (parse-quint-model-spec source)
  (unless (quint-source-qualified? source)
    (error "parse-quint-model-spec: .qnt source failed gerbil-parser LR qualification"))
  (def mod-info (quint-cst-module-info source))
  (def decls (quint-cst-declarations source))
  (def bytes (string->utf8 source))
  (def mod-name (cdr (assq 'name mod-info)))
  (def parsed-has-state? (and (find-decl-by-name decls "State") #t))
  (def parsed-has-step? (and (find-decl-by-name decls "step") #t))
  (def safety-decl (find-decl-by-name decls "safety"))
  (def parsed-safety-source
    (if safety-decl
      (qnt-trim-ws (utf8-byte-slice bytes (cdr (assq 'body-start safety-decl)) (cdr (assq 'body-end safety-decl))))
      #f))
  (def all-op-names
    (map (lambda (d) (cdr (assq 'name d)))
         (filter (lambda (d) (eq? (cdr (assq 'kind d)) 'OpDeclaration)) decls)))
  (def all-run-traces
    (map (lambda (d) (cdr (assq 'name d)))
         (filter (lambda (d) (and (eq? (cdr (assq 'kind d)) 'OpDeclaration)
                                  (equal? (cdr (assq 'qualifier d)) "run")))
                 decls)))
  (def hdr-model-id #f)
  (def hdr-verify-depth #f)
  (def hdr-cm-depth #f)
  (def hdr-limits-text #f)
  (def parsed-cms '())
  (for-each
    (lambda (raw-line)
      (def line (qnt-trim-ws raw-line))
      (cond
       ((qnt-prefix? line "// @quint-model ")
        (set! hdr-model-id (string->symbol (qnt-first-token (qnt-after-prefix line "// @quint-model ")))))
       ((qnt-prefix? line "// @verify ")
        (let ((ms (qnt-extract-kv line "max-steps")))
          (when ms
            (let ((n (string->number ms)))
              (when (exact-integer? n) (set! hdr-verify-depth n))))))
       ((qnt-prefix? line "// @countermodel ")
        (let* ((rest (qnt-trim-ws (qnt-after-prefix line "// @countermodel ")))
               (guard-str (qnt-first-token rest))
               (step-str (qnt-extract-kv rest "step"))
               (ms-str (qnt-extract-kv rest "max-steps"))
               (itf-str (qnt-extract-kv rest "itf")))
          (unless (and (> (string-length guard-str) 0) step-str itf-str)
            (error "parse-quint-model-spec: malformed @countermodel directive" line))
          (unless (member step-str all-op-names)
            (error "parse-quint-model-spec: @countermodel step action not found in .qnt CST"
                   step-str mod-name))
          (when ms-str
            (let ((n (string->number ms-str)))
              (when (and (exact-integer? n) (not hdr-cm-depth))
                (set! hdr-cm-depth n))))
          (set! parsed-cms
                (cons (.o dropped-guard: (string->symbol guard-str)
                          step-action: step-str
                          max-steps: (if (and ms-str (exact-integer? (string->number ms-str)))
                                       (string->number ms-str)
                                       6)
                          expected-itf-predicate: itf-str)
                      parsed-cms))))
       ((qnt-prefix? line "// Limits: ")
        (set! hdr-limits-text (qnt-trim-ws (qnt-after-prefix line "// Limits: "))))))
    (qnt-split-lines source))
  (let ((final-vdepth (or hdr-verify-depth 12))
        (final-cmdepth (or hdr-cm-depth 6))
        (final-cms (reverse parsed-cms)))
    (.o module-name: mod-name
        model-identity: hdr-model-id
        has-state-record?: parsed-has-state?
        has-step?: parsed-has-step?
        safety-source: parsed-safety-source
        verify-depth: final-vdepth
        countermodel-depth: final-cmdepth
        op-names: all-op-names
        run-traces: all-run-traces
        countermodels: final-cms
        limits: hdr-limits-text)))

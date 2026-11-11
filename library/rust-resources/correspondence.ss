;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
;;; Single-job observation mapping; synthesized states are abstract witnesses.
(import
  :clan/poo/object
  :std/encoding/json
  "oracle.ss")
(export
  resource-trace-projections
  resource-trace-qnt
  resource-trace-sysml
  resource-slice-tool-scopes
  resource-mapping-value)

(def (resource-slice-tool-scopes usage mapping sysml quint)
  (list
   (list usage 'correspondence mapping)
   (list usage 'sysml-tool sysml)
   (list usage 'quint-tool quint)))
;; Projection of authored meaning, not descriptors/receivers or an issuer record.
(def (resource-mapping-value value)
  (cond
   ((object? value)
    (map
     (lambda (key) (list (symbol->string key) (resource-mapping-value (.ref value key))))
     (list-sort
      (lambda (a b) (string<? (symbol->string a) (symbol->string b)))
      (filter (lambda (key) (not (memq key '(contract declaration-contract)))) (.all-slots value)))))
   ((symbol? value) (symbol->string value))
   ((pair? value) (map resource-mapping-value value))
   ((string? value) (string-copy value))
   (else value)))
(def (state stage reserved)
  (hash ("stage" stage) ("reserved" reserved)))
(def (resource-trace-projections integration report)
  (def mapping (.get integration mapping))
  (def declared-cases (.get mapping cases))
  ;; The independent native oracle checks case-specific partial orders and cuts.
  (resource-native-oracle report)
  (unless (and
           (integer? (hash-ref report "payloadBytes"))
           (> (hash-ref report "payloadBytes") 0)
           (<= (hash-ref report "payloadBytes") 4096))
    (error "unsupported trace payload"))
  (unless (equal?
           (map (cut hash-ref <> "case") (hash-ref report "cases"))
           (map (cut .get <> name) declared-cases))
    (error "observation inventory differs from selected Integration"))
  (map
   (lambda (c)
     (def name (hash-ref c "case"))
     (def events (hash-ref c "events"))
     (def labels (map (cut hash-ref <> "event") events))
     (def case-definition (find (lambda (row) (equal? (.get row name) name)) declared-cases))
     (def expected (.get case-definition labels))
     (unless (and
              (= (length labels) (length expected))
              (andmap (lambda (label) (= (length (filter (cut equal? <> label) labels)) 1)) expected))
       (error "trace event inventory unknown, missing or duplicated" name))
     (def stage (symbol->string (.get mapping initial)))
     (def reserved #f)
     (def states (list (state stage reserved)))
     (def cuts '())
     (for-each
      (lambda (e)
        (def label (hash-ref e "event"))
        (def applicable
          (filter
           (lambda (row)
             (and
              (equal? label (.get row event))
              (or (null? (.get row cases)) (member name (.get row cases)))))
           (.get mapping transitions)))
        (when (> (length applicable) 1) (error "ambiguous selected transition" name label))
        (when (pair? applicable)
          (let (selected (car applicable))
            (unless (or (null? (.get selected from)) (memq (string->symbol stage) (.get selected from)))
              (error "event outside declared transition guard" name label stage))
            (unless (eq? (.get selected to) 'unchanged) (set! stage (symbol->string (.get selected to))))
            (case
                (.get selected reservation)
              ((reserve) (set! reserved #t))
              ((release) (set! reserved #f))
              ((keep) (void)))))
        (when (hash-key? e "live")
          (unless (member label (.get mapping cut-labels))
            (error "unsupported synchronized cut" name label))
          (unless (and
                   (= (hash-ref e "live") (if (equal? stage (symbol->string (.get mapping final))) 0 1))
                   (= (hash-ref e "available") (if reserved 0 1)))
            (error "observed cut disagrees with abstract witness" name label))
          (set!
           cuts
           (cons
            (hash
             ("label" label)
             ("live" (hash-ref e "live"))
             ("reserved" (- 1 (hash-ref e "available"))))
            cuts)))
        (set! states (cons (state stage reserved) states)))
      events)
     (hash
      ("case" name)
      ("nativeObligation" (symbol->string (car (.get case-definition obligations))))
      ("mapping" (.get mapping revision))
      ("mappingIdentity" (symbol->string (.get mapping identity)))
      ("states" (reverse states))
      ("cuts" (reverse cuts))
      ("steps" (length events))
      ("outcome" (if (andmap (lambda (c) (= (hash-ref c "live") (hash-ref c "reserved"))) cuts) "pass" "fail"))
      ("boundary" (.get mapping loss))))
   (hash-ref report "cases")))

(def (join xs separator)
  (if (null? xs) "" (foldl (lambda (s out) (string-append out separator s)) (car xs) (cdr xs))))
(def (qstate mapping s)
  (def stage (hash-ref s "stage"))
  (string-append
   "{limit:1, queueLimit:1, admitted:"
   (if (hash-ref s "reserved") "Set(0)" "Set()")
   (apply
    string-append
    (map
     (lambda (field)
       (string-append ", " field ":" (if (equal? stage field) "Set(0)" "Set()")))
     (map symbol->string (.get mapping qnt-stages))))
   "}"))
(def (resource-trace-qnt integration base projection)
  (def mapping (.get integration mapping))
  (def delta-value (.get mapping delta))
  (def action-name (symbol->string (.get delta-value identity)))
  (def from-name (symbol->string (.get delta-value from)))
  (def to-name (symbol->string (.get delta-value to)))
  (def subject-text (number->string (.get delta-value subject)))
  (def last
    (let loop
        ((i (- (string-length base) 1)))
      (cond
       ((< i 0) (error "empty base QNT"))
       ((memv (string-ref base i) '(#\space #\newline #\return #\tab)) (loop (- i 1)))
       (else i))))
  (unless (char=? (string-ref base last) #\}) (error "base QNT module terminator absent"))
  (string-append
   (substring base 0 last)
   "\n  // Selected Integration delta; all non-effect fields are framed.\n"
   "  action "
   action-name
   " = all { s."
   from-name
   ".contains("
   subject-text
   "), s' = { ...s, "
   from-name
   ":s."
   from-name
   ".exclude(Set("
   subject-text
   ")), "
   to-name
   ":s."
   to-name
   ".union(Set("
   subject-text
   ")) } }\n"
   "  val expected = List("
   (join (map (cut qstate mapping <>) (hash-ref projection "states")) ",\n")
   ")\n"
   "  var pc: int\n  action replayInit = all { "
   (symbol->string (.get mapping qnt-initializer))
   ", pc'=0 }\n"
   "  action replayStep = all { pc < expected.length()-1, s == expected.nth(pc), any { "
   (symbol->string (.get mapping qnt-step))
   ", "
   action-name
   " }, pc'=pc+1 }\n"
   "  val unfinished = pc < expected.length()-1 or s != expected.nth(pc)\n}\n"))

(def (resource-trace-sysml integration projection)
  (def catalog (.get integration catalog))
  (string-append
   "package BackpressureSlice {\n private import "
   (symbol->string (.get catalog package))
   "::*;\n"
   " part "
   (hash-ref projection "case")
   " {\n"
   (apply
    string-append
    (map
     (lambda (c)
       (string-append
        " part cut_"
        (hash-ref c "label")
        " : "
        (symbol->string (.get catalog definition))
        " { :>> "
        (symbol->string (.get catalog live-attribute))
        " = "
        (number->string (hash-ref c "live"))
        "; :>> "
        (symbol->string (.get catalog reservation-attribute))
        " = "
        (number->string (hash-ref c "reserved"))
        "; }\n"))
     (hash-ref projection "cuts")))
   " }\n}\n"))

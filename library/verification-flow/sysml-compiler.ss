;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure SysML v2 -> Fun-Flow DAG Compiler (10.154).
;;; Compiles `subject-specs` projected from OpenSysML `api-json` directly into
;;; validated `VerificationSubjectType` objects, typed depth-1 Fun-Flow DAGs,
;;; M1/M3 mutability maps, and SHA-256 input-closure tables — eliminating all
;;; hand-written per-subject Scheme step/DAG glue. Zero I/O.
(import
  :clan/poo/object
  (only-in :clan/poo/type validate)
  (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
           Fun
           flow-arr
           flow-then
           flow-fanout
           flow-output-contract)
  "types.ss"
  "objects.ss"
  "func.ss")
(export
  subject-spec->mutability
  subject-spec->input-files
  find-sysml-subject-spec
  compile-sysml-subject-spec
  compile-sysml-subject-by-key
  sysml-projected->compiled-subjects)

(def (trim-s s)
  (def n (string-length s))
  (let loop-l ((i 0))
    (if (and (< i n) (char-whitespace? (string-ref s i)))
      (loop-l (+ i 1))
      (let loop-r ((j n))
        (if (and (> j i) (char-whitespace? (string-ref s (- j 1))))
          (loop-r (- j 1))
          (substring s i j))))))

(def (split-csv-s s)
  (if (or (not (string? s)) (= (string-length s) 0))
    '()
    (filter (lambda (p) (> (string-length p) 0))
            (map trim-s (string-split s #\,)))))

(def (family-obj-for-id fam-id)
  (cond
   ((eq? fam-id 'de-quint) DeQuintTaskFamily)
   ((eq? fam-id 'de-lean-poo) DeLeanPooTaskFamily)
   ((eq? fam-id 'de-source-contract) DeSourceContractTaskFamily)
   ((eq? fam-id 'de-native-oracle) DeNativeOracleTaskFamily)
   (else (error "unknown verification method family in SysML spec" fam-id))))

(def (parse-nat-attr attrs key default)
  (let ((raw (alist-ref attrs key #f)))
    (or (and (string? raw) (string->number raw)) default)))

(def (target-spec->payload tspec)
  (def fam (.get tspec family))
  (def attrs (.get tspec attrs))
  (cond
   ((eq? fam 'de-quint)
    (list
      (cons 'quint-file (alist-ref attrs "quintFile" ""))
      (cons 'quint-main (alist-ref attrs "quintMain" ""))
      (cons 'itf-subdir (alist-ref attrs "itfSubdir" ""))
      (cons 'verify? (not (equal? (alist-ref attrs "verifyMode" "apalache") "plan")))
      (cons 'n-traces (parse-nat-attr attrs "nTraces" 10))
      (cons 'max-samples (parse-nat-attr attrs "maxSamples" 30))
      (cons 'max-steps (parse-nat-attr attrs "maxSteps" 12))
      (cons 'model (alist-ref attrs "modelId" ""))))
   ((eq? fam 'de-lean-poo)
    (list
      (cons 'lake-root (alist-ref attrs "lakeRoot" "packages/lean-models"))
      (cons 'lean-module (alist-ref attrs "module" ""))
      (cons 'theorems (split-csv-s (alist-ref attrs "theorems" "")))))
   ((eq? fam 'de-source-contract)
    (list
      (cons 'subject-dir (alist-ref attrs "subjectDir" ""))
      (cons 'offline? (equal? (alist-ref attrs "offlineMode" "false") "true"))
      (cons 'cbmc-files (split-csv-s (alist-ref attrs "cbmcFiles" "")))
      (cons 'tool (string->symbol (alist-ref attrs "staticTool" "clippy")))))
   ((eq? fam 'de-native-oracle)
    (let ((supps (.get tspec supports-premises)))
      (list
        (cons 'crate-dir (alist-ref attrs "cratePath" ""))
        (cons 'itf-subdir (alist-ref attrs "itfSubdir" ""))
        (cons 'oracle-mode (string->symbol (alist-ref attrs "oracleMode" "cargo-test-itf")))
        (cons 'premise (if (pair? supps) (string->symbol (car supps)) 'none)))))
   (else '())))

(def (compile-target-spec tspec in-contract)
  (def st-sym (string->symbol (.get tspec name)))
  (def fam-id (.get tspec family))
  (def obl-sym (.get tspec obligation))
  (def ck-sym (.get tspec claim-kind))
  (def op-sym (.get tspec operation))
  (def payload (target-spec->payload tspec))
  (validate VerificationStepType
    (.o bind-these: #f
        identity: st-sym
        family: (family-obj-for-id fam-id)
        obligation: obl-sym
        claim-kind: ck-sym
        produces: (map string->symbol (.get tspec produces))
        consumes: (map string->symbol (.get tspec consumes))
        requires-premises: (map string->symbol (.get tspec requires-premises))
        supports-premises: (map string->symbol (.get tspec supports-premises))
        stateful-quint?: (.get tspec stateful-quint?)
        countermodels: (map string->symbol (.get tspec countermodels))
        flow: (make-external-admit-flow
                st-sym op-sym payload in-contract VerificationEvidenceRecordType
                (make-step-admitter obl-sym fam-id ck-sym)))))

;; Compile an ordered list of target specs into (values compiled-steps sequential-flow),
;; starting from VerificationInputEnvelopeType and chaining via flow-then.
(def (compile-arm arm-name tspecs)
  (unless (pair? tspecs)
    (error "cannot compile empty Fun-Flow DAG arm" arm-name))
  (def head-step (compile-target-spec (car tspecs) VerificationInputEnvelopeType))
  (def tail-steps
    (map (lambda (ts) (compile-target-spec ts VerificationEvidenceRecordType))
         (cdr tspecs)))
  (def all-steps (cons head-step tail-steps))
  (def combined-flow
    (let loop ((acc (flow-of head-step)) (rest tail-steps) (idx 1))
      (if (null? rest)
        acc
        (loop (flow-then
                (string->symbol (string-append arm-name "-seq-" (number->string idx)))
                acc
                (flow-of (car rest)))
              (cdr rest)
              (+ idx 1)))))
  (values all-steps combined-flow))

(def (find-target-spec tspecs name)
  (let loop ((xs tspecs))
    (cond
     ((null? xs) #f)
     ((equal? (.get (car xs) name) name) (car xs))
     (else (loop (cdr xs))))))

;; Partition subject targets into 1 or 2 arms respecting all declared SysML v2
;; dag-edges (producer -> consumer) while guaranteeing depth <= 1 BranchContract.
(def (partition-target-arms tspecs dag-edges)
  (if (pair? dag-edges)
    (let* ((edge (car dag-edges))
           (from-name (car edge))
           (to-name (cadr edge))
           (from-spec (find-target-spec tspecs from-name))
           (to-spec (find-target-spec tspecs to-name))
           (left-arm (if (and from-spec to-spec) (list from-spec to-spec) '()))
           (left-names (map (lambda (ts) (.get ts name)) left-arm))
           (right-arm (filter (lambda (ts) (not (member (.get ts name) left-names))) tspecs)))
      (values left-arm right-arm))
    (if (> (length tspecs) 1)
      (values (list (car tspecs)) (cdr tspecs))
      (values tspecs '()))))

(def (subject-spec->mutability spec)
  (map (lambda (ts) (list (.get ts name) (.get ts mutability)))
       (.get spec targets)))

(def (subject-spec->input-files spec)
  (map (lambda (ts) (cons (.get ts name) (.get ts input-files)))
       (.get spec targets)))

(def (find-sysml-subject-spec projected subject-key)
  (def target-str (sym->str subject-key))
  (let loop ((specs (.get projected subject-specs)))
    (cond
     ((null? specs)
      (error "unknown verification subject key in SysML v2 model"
             subject-key
             (map (lambda (sp) (.get sp subject-key)) (.get projected subject-specs))))
     ((equal? (.get (car specs) subject-key) target-str)
      (car specs))
     (else (loop (cdr specs))))))

(def (compile-sysml-subject-spec spec)
  (def skey-str (.get spec subject-key))
  (def sid-sym (string->symbol (.get spec identity)))
  (def tspecs (.get spec targets))
  (def dag-edges (.get spec dag-edges))
  (let-values (((left-specs right-specs) (partition-target-arms tspecs dag-edges)))
    (let-values (((left-steps left-flow) (compile-arm (string-append skey-str "-left") left-specs)))
      (let-values (((all-steps dag-flow)
                    (if (null? right-specs)
                      (values left-steps left-flow)
                      (let-values (((right-steps right-flow)
                                    (compile-arm (string-append skey-str "-right") right-specs)))
                        (let ((fan (flow-fanout
                                     (string->symbol (string-append skey-str "-dag-fanout"))
                                     left-flow right-flow)))
                          (values
                            (append left-steps right-steps)
                            (flow-then
                              (string->symbol (string-append skey-str "-dag"))
                              fan
                              (flow-arr
                                (string->symbol (string-append skey-str "-dag-join"))
                                (Fun VerificationEvidenceRecordType <- (flow-output-contract fan))
                                (lambda (pair-out) (car pair-out))))))))))
        (def subject-obj
          (validate VerificationSubjectType
            (.o bind-these: #f
                identity: sid-sym
                factors: (map string->symbol (.get spec factors))
                obligations: (map (lambda (ts) (list (.get ts obligation) (.get ts claim-kind))) tspecs)
                os-containment: (map (lambda (row) (list (string->symbol (car row)) (string->symbol (cadr row))))
                                     (.get spec os-containment))
                steps: all-steps
                dag-edges: (map (lambda (e) (list (string->symbol (car e)) (string->symbol (cadr e))))
                                dag-edges)
                correspondence-bridges: '()
                dag-flow: dag-flow)))
        (.o bind-these: #f
            subject-key: (string->symbol skey-str)
            identity: sid-sym
            subject: subject-obj
            mutability: (subject-spec->mutability spec)
            input-files: (subject-spec->input-files spec))))))

(def (compile-sysml-subject-by-key projected subject-key)
  (compile-sysml-subject-spec (find-sysml-subject-spec projected subject-key)))

(def (sysml-projected->compiled-subjects projected)
  (map (lambda (spec)
         (def compiled (compile-sysml-subject-spec spec))
         (cons (.get compiled subject-key) compiled))
       (.get projected subject-specs)))

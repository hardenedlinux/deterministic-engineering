;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure SysML v2 (OpenSysML api-json) -> ASCENT fact projector (10.154).
;;; Zero filesystem I/O: consumes parsed JSON element list emitted by
;;; `sysml -convert api-json` so SysML v2 remains the single source of truth.
(import
  :clan/poo/object
  :std/list/list
  "objects.ss")
(export
  default-method-allows-claim-rows
  sysml-api-json->governance-facts)

(def (default-method-allows-claim-rows)
  (apply append
    (map (lambda (fam)
           (def m (symbol->string (.get fam identity)))
           (map (lambda (ck) (list m (symbol->string ck)))
                (.get fam claim-kinds)))
         (list DeQuintTaskFamily
               DeLeanPooTaskFamily
               DeSourceContractTaskFamily
               DeNativeOracleTaskFamily))))

(def (trim-ws s)
  (def n (string-length s))
  (let loop-l ((i 0))
    (if (and (< i n) (char-whitespace? (string-ref s i)))
      (loop-l (+ i 1))
      (let loop-r ((j n))
        (if (and (> j i) (char-whitespace? (string-ref s (- j 1))))
          (loop-r (- j 1))
          (substring s i j))))))

(def (split-csv s)
  (if (or (not (string? s)) (= (string-length s) 0))
    '()
    (filter (lambda (part) (> (string-length part) 0))
            (map trim-ws (string-split s #\,)))))

(def (ref-id obj)
  (and (hash-table? obj) (hash-get obj "@id")))

(def (first-ref-id lst)
  (and (pair? lst) (ref-id (car lst))))

(def (sysml-api-json->governance-facts elements)
  (unless (list? elements)
    (error "sysml-api-json->governance-facts expects parsed JSON element list"))
  ;; Index elements by @id, plus reverse maps for Redefinition and LiteralString values.
  (def by-id (make-hash-table))
  (def redef-target (make-hash-table))
  (def lit-by-owner (make-hash-table))
  (for-each
    (lambda (el)
      (when (hash-table? el)
        (let ((id (hash-get el "@id"))
              (ty (hash-get el "@type")))
          (when (string? id) (hash-put! by-id id el))
          (when (equal? ty "Redefinition")
            (let ((own (ref-id (hash-get el "owner")))
                  (gen (ref-id (hash-get el "general"))))
              (when (and own gen) (hash-put! redef-target own gen))))
          (when (equal? ty "LiteralString")
            (let ((own (ref-id (hash-get el "owner")))
                  (val (hash-get el "value")))
              (when (and own (string? val)) (hash-put! lit-by-owner own val)))))))
    elements)

  ;; Resolve AttributeUsage name (direct declaredName or redefined attribute's declaredName).
  (def (attr-name attr-el)
    (or (hash-get attr-el "declaredName")
        (let* ((aid (hash-get attr-el "@id"))
               (gen-id (and aid (hash-get redef-target aid)))
               (gen-el (and gen-id (hash-get by-id gen-id))))
          (and gen-el (hash-get gen-el "declaredName")))))

  ;; Build owner-id -> alist of (attr-name . string-value).
  (def attrs-by-owner (make-hash-table))
  (for-each
    (lambda (el)
      (when (and (hash-table? el) (equal? (hash-get el "@type") "AttributeUsage"))
        (let ((own (ref-id (hash-get el "owner")))
              (aid (hash-get el "@id"))
              (nm (attr-name el)))
          (when (and own aid nm (hash-key? lit-by-owner aid))
            (hash-put! attrs-by-owner own
                       (cons (cons nm (hash-get lit-by-owner aid))
                             (or (hash-get attrs-by-owner own) '())))))))
    elements)

  (def (part-attr part-id key)
    (def pairs (or (hash-get attrs-by-owner part-id) '()))
    (def hit (assoc key pairs))
    (and hit (cdr hit)))

  (def (part-type-name part-el)
    (def tid (first-ref-id (hash-get part-el "type")))
    (def tel (and tid (hash-get by-id tid)))
    (and tel (hash-get tel "declaredName")))

  ;; 1. Extract Distribution Packages (QuintModelPackage / LeanPooModelPackage).
  (def pkg-rows
    (filter-map
      (lambda (el)
        (and (hash-table? el)
             (equal? (hash-get el "@type") "PartUsage")
             (let ((tname (part-type-name el))
                   (pid (hash-get el "@id")))
               (and (member tname '("QuintModelPackage" "LeanPooModelPackage"))
                    (list (or (hash-get el "declaredName") pid)
                          (or (part-attr pid "family") "")
                          (or (part-attr pid "pathPattern") "")
                          (or (part-attr pid "ecosystem") "")
                          (or (part-attr pid "mirror") ""))))))
      elements))

  ;; 2. Extract MethodTaskFamilies and authorized claim-kind rows directly from SysML v2.
  (def method-allows-rows '())
  (for-each
    (lambda (el)
      (when (and (hash-table? el) (equal? (hash-get el "@type") "PartUsage"))
        (let ((tname (part-type-name el))
              (pid (hash-get el "@id")))
          (when (member tname '("QuintTaskFamily" "LeanPooTaskFamily"
                                "SourceContractTaskFamily" "NativeFaultOracleTaskFamily"))
            (let ((fname (part-attr pid "familyName"))
                  (claims (split-csv (part-attr pid "authorizedClaimKinds"))))
              (when fname
                (for-each
                  (lambda (ck)
                    (set! method-allows-rows (cons (list fname ck) method-allows-rows)))
                  claims)))))))
    elements)

  ;; 3. Extract SuccessionAsUsage edges (SysML v2 action workflow DAG).
  (def wf-edges
    (filter-map
      (lambda (el)
        (and (hash-table? el)
             (equal? (hash-get el "@type") "SuccessionAsUsage")
             (let* ((src-id (ref-id (hash-get el "sourceFeature")))
                    (dst-id (first-ref-id (hash-get el "targetFeature")))
                    (src-el (and src-id (hash-get by-id src-id)))
                    (dst-el (and dst-id (hash-get by-id dst-id))))
               (and src-el dst-el
                    (list (or (hash-get src-el "declaredName") src-id)
                          (or (hash-get dst-el "declaredName") dst-id))))))
      elements))

  ;; 4. Extract Dependency edges.
  (def dep-rows
    (filter-map
      (lambda (el)
        (and (hash-table? el)
             (equal? (hash-get el "@type") "Dependency")
             (let ((nm (or (hash-get el "declaredName") ""))
                   (cli (first-ref-id (hash-get el "client")))
                   (sup (first-ref-id (hash-get el "supplier"))))
               (and cli sup (list nm cli sup)))))
      elements))

  ;; 5. Extract Requirements & VerificationCaseUsages.
  (def req-rows
    (filter-map
      (lambda (el)
        (and (hash-table? el)
             (equal? (hash-get el "@type") "RequirementUsage")
             (hash-get el "declaredName")
             (list (hash-get el "declaredName") (or (hash-get el "qualifiedName") ""))))
      elements))

  (def ver-rows
    (filter-map
      (lambda (el)
        (and (hash-table? el)
             (equal? (hash-get el "@type") "VerificationCaseUsage")
             (hash-get el "declaredName")
             (list (hash-get el "declaredName") (or (hash-get el "qualifiedName") ""))))
      elements))

  ;; 6. Project any Engineering Subject part (carries `identity` + `factors` attributes)
  ;;    and its child target parts directly into ASCENT MR01-MR06 source relations.
  (def subj-obls '())
  (def subj-factors '())
  (def fsteps '())
  (def fedges '())
  (def sproduces '())
  (def sconsumes '())
  (def sreq-prem '())
  (def ssup-prem '())
  (def sq-steps '())
  (def scm-rows '())
  (def os-rows '())

  (for-each
    (lambda (el)
      (when (and (hash-table? el) (equal? (hash-get el "@type") "PartUsage"))
        (let* ((pid (hash-get el "@id"))
               (sid (part-attr pid "identity"))
               (facs (part-attr pid "factors")))
          (when (and sid facs)
            (for-each (lambda (f) (set! subj-factors (cons (list sid f) subj-factors)))
                      (split-csv facs))
            (let ((child-ids '()))
              (for-each
                (lambda (child)
                  (when (and (hash-table? child)
                             (equal? (hash-get child "@type") "PartUsage")
                             (equal? (ref-id (hash-get child "owner")) pid))
                    (let* ((cid (hash-get child "@id"))
                           (cname (or (hash-get child "declaredName") cid))
                           (model-id (part-attr cid "modelId"))
                           (lean-mod (part-attr cid "module"))
                           (subj-dir (part-attr cid "subjectDir"))
                           (crate-p (part-attr cid "cratePath"))
                           (cms (split-csv (part-attr cid "countermodels")))
                           (prods (split-csv (part-attr cid "producesArtifact")))
                           (conss (split-csv (part-attr cid "consumesArtifact")))
                           (reqp (split-csv (part-attr cid "requiresPremise")))
                           (supp (split-csv (part-attr cid "supportsPremise")))
                           (plats (split-csv (part-attr cid "platformSpecializations"))))
                      (set! child-ids (cons (cons cid cname) child-ids))
                      (cond
                       (model-id
                        (set! subj-obls (cons (list sid "quint-bounded-safety" "bounded-interleaving") subj-obls))
                        (set! fsteps (cons (list cname sid "quint-bounded-safety" "de-quint" "bounded-interleaving") fsteps))
                        (set! sq-steps (cons (list cname) sq-steps))
                        (for-each (lambda (cm) (set! scm-rows (cons (list cname cm) scm-rows))) cms))
                       (lean-mod
                        (set! subj-obls (cons (list sid "lean-unbounded-closure" "unbounded-invariant") subj-obls))
                        (set! fsteps (cons (list cname sid "lean-unbounded-closure" "de-lean-poo" "unbounded-invariant") fsteps))
                        (for-each (lambda (pl) (set! os-rows (cons (list sid pl pl) os-rows))) plats))
                       (subj-dir
                        (set! subj-obls (cons (list sid "source-api-ban-lint" "api-ban-lint") subj-obls))
                        (set! fsteps (cons (list cname sid "source-api-ban-lint" "de-source-contract" "api-ban-lint") fsteps)))
                       (crate-p
                        (set! subj-obls (cons (list sid "os-sigkill-leak-oracle" "os-sigkill-oracle") subj-obls))
                        (set! fsteps (cons (list cname sid "os-sigkill-leak-oracle" "de-native-oracle" "os-sigkill-oracle") fsteps))))
                      (for-each (lambda (a) (set! sproduces (cons (list cname a) sproduces))) prods)
                      (for-each (lambda (a) (set! sconsumes (cons (list cname a) sconsumes))) conss)
                      (for-each (lambda (p) (set! sreq-prem (cons (list cname p) sreq-prem))) reqp)
                      (for-each (lambda (p) (set! ssup-prem (cons (list cname p) ssup-prem))) supp))))
                elements)
              ;; Map SysML v2 mbt-itf-edge Dependency (consumer -> producer) to Fun-Flow DAG edge (producer -> consumer).
              (for-each
                (lambda (dep)
                  (def dep-name (car dep))
                  (def cli-id (cadr dep))
                  (def sup-id (caddr dep))
                  (when (equal? dep-name "mbt-itf-edge")
                    (let* ((cli-el (hash-get by-id cli-id))
                           (sup-el (hash-get by-id sup-id))
                           (cli-own (and cli-el (ref-id (hash-get cli-el "owner"))))
                           (sup-own (and sup-el (ref-id (hash-get sup-el "owner"))))
                           (to-pair (or (assoc cli-id child-ids) (and cli-own (assoc cli-own child-ids))))
                           (from-pair (or (assoc sup-id child-ids) (and sup-own (assoc sup-own child-ids)))))
                      (when (and from-pair to-pair)
                        (set! fedges (cons (list (cdr from-pair) (cdr to-pair)) fedges))))))
                dep-rows))))))
    elements)

  (.o packages: (reverse pkg-rows)
      workflow-edges: (reverse wf-edges)
      dependencies: (reverse dep-rows)
      requirements: (reverse req-rows)
      verifications: (reverse ver-rows)
      governance-sources:
      (list
        (cons 'subject_obligation (reverse subj-obls))
        (cons 'subject_factor (reverse subj-factors))
        (cons 'method_allows_claim
              (if (pair? method-allows-rows)
                (reverse method-allows-rows)
                (default-method-allows-claim-rows)))
        (cons 'flow_step (reverse fsteps))
        (cons 'flow_dag_edge (reverse fedges))
        (cons 'step_produces (reverse sproduces))
        (cons 'step_consumes (reverse sconsumes))
        (cons 'step_requires_premise (reverse sreq-prem))
        (cons 'step_supports_premise (reverse ssup-prem))
        (cons 'correspondence_bridge '())
        (cons 'stateful_quint_step (reverse sq-steps))
        (cons 'step_countermodel (reverse scm-rows))
        (cons 'declared_os_containment (reverse os-rows)))))

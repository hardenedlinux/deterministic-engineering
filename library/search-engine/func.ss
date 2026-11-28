;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Pure functional Quality-Diversity (MAP-Elites / MMR), mode-collapse metrics,
;;; and neuro-symbolic tier routing operators for deterministic AI search engines.
(import :clan/poo/object)
(export select-niche-diverse-rows
        select-mmr-diverse-items
        compute-diversity-coverage-report
        compute-hybrid-impact-coverage
        decompose-zero-hit-stems
        classify-search-tier-intent)

;;; Niche-preserving round-robin selector (MAP-Elites / anti-mode-collapse):
;;; Partitions `rows` by `(niche-key-fn row)` (preserving deterministic first-seen
;;; niche order) and draws round-robin across niches up to `limit`, preventing a
;;; single high-frequency niche from starving minority niches in bounded windows.
(def (select-niche-diverse-rows rows limit (niche-key-fn car))
  (cond
    ((or (not limit) (<= limit 0) (null? rows))
     (if (and limit (<= limit 0)) '() rows))
    ((<= (length rows) limit) rows)
    (else
     (let ((buckets (make-hash-table))
           (order '()))
       (for-each
         (lambda (row)
           (let* ((k (niche-key-fn row))
                  (prev (hash-get buckets k)))
             (if prev
               (hash-put! buckets k (cons row prev))
               (begin
                 (hash-put! buckets k (list row))
                 (set! order (cons k order))))))
         rows)
       (let ((queues (map (lambda (k) (reverse (hash-ref buckets k))) (reverse order))))
         (let loop ((cur queues) (next '()) (rem limit) (acc '()))
           (cond
             ((<= rem 0) (reverse acc))
             ((null? cur)
              (if (null? next)
                (reverse acc)
                (loop (reverse next) '() rem acc)))
             (else
              (let ((q (car cur)))
                (loop (cdr cur)
                      (if (pair? (cdr q)) (cons (cdr q) next) next)
                      (- rem 1)
                      (cons (car q) acc)))))))))))

;;; Greedy Maximal Marginal Relevance (MMR) selector (Carbonell & Goldstein 1998):
;;; Selects up to `limit` items maximizing:
;;;   MMR(d) = lambda * rel(d) - (1 - lambda) * max_{s in S} sim(d, s)
;;; All inputs are pure functions:
;;;   - `items`: candidate list
;;;   - `limit`: positive integer budget
;;;   - `lambda-weight`: real in [0.0, 1.0] (1.0 = pure relevance, 0.0 = pure novelty)
;;;   - `relevance-fn`: `(item -> real)`
;;;   - `similarity-fn`: `(item item -> real)`
(def (select-mmr-diverse-items items limit lambda-weight relevance-fn similarity-fn)
  (let ((lam (max 0.0 (min 1.0 (exact->inexact lambda-weight)))))
    (let loop ((remaining items) (selected '()) (n limit))
      (if (or (<= n 0) (null? remaining))
        (reverse selected)
        (let* ((score-item
                 (lambda (cand)
                   (let* ((rel (exact->inexact (relevance-fn cand)))
                          (max-sim
                            (if (null? selected)
                              0.0
                              (apply max
                                (map (lambda (s) (exact->inexact (similarity-fn cand s)))
                                     selected)))))
                     (- (* lam rel) (* (- 1.0 lam) max-sim)))))
               (best
                 (let pick ((rest (cdr remaining))
                            (cur-best (car remaining))
                            (cur-score (score-item (car remaining))))
                   (if (null? rest)
                     cur-best
                     (let ((sc (score-item (car rest))))
                       (if (> sc cur-score)
                         (pick (cdr rest) (car rest) sc)
                         (pick (cdr rest) cur-best cur-score))))))
               (next-rem
                 (let drop-one ((rest remaining) (dropped? #f) (acc '()))
                   (cond
                     ((null? rest) (reverse acc))
                     ((and (not dropped?) (eq? (car rest) best))
                      (drop-one (cdr rest) #t acc))
                     (else (drop-one (cdr rest) dropped? (cons (car rest) acc)))))))
          (loop next-rem (cons best selected) (- n 1)))))))

;;; Quantify niche diversity & mode-collapse exposure for a selected result set.
;;; Returns a POO report object with:
;;;   - `total-items`: number of rows in the window
;;;   - `unique-niches`: count of distinct niches covered
;;;   - `max-niche-count`: highest count in any single niche
;;;   - `max-niche-share`: ratio `max-niche-count / total-items` (1.0 = total collapse)
;;;   - `mode-collapsed?`: #t when `total-items >= 2` and `unique-niches == 1`
(def (compute-diversity-coverage-report rows (niche-key-fn car))
  (let ((total (length rows)))
    (if (= total 0)
      (.o total-items: 0
          unique-niches: 0
          max-niche-count: 0
          max-niche-share: 0.0
          mode-collapsed?: #f)
      (let ((counts (make-hash-table)))
        (for-each
          (lambda (row)
            (let ((k (niche-key-fn row)))
              (hash-put! counts k (+ 1 (hash-ref counts k 0)))))
          rows)
        (let ((unique 0)
              (max-c 0))
          (hash-for-each
            (lambda (_k v)
              (set! unique (+ unique 1))
              (when (> v max-c) (set! max-c v)))
            counts)
          (.o total-items: total
              unique-niches: unique
              max-niche-count: max-c
              max-niche-share: (/ (exact->inexact max-c) (exact->inexact total))
              mode-collapsed?: (and (>= total 2) (= unique 1))))))))

;;; Coverage-aware hybrid impact audit: determines whether native AST coverage
;;; alone suffices or whether RAM lexical `symbol_ref` hydration is mandatory
;;; to guarantee 100% file coverage across scoped candidates (eliminating silent
;;; type/constructor blind spots when `native-ast-files < scoped-files`).
(def (compute-hybrid-impact-coverage scoped-files native-ast-files lexical-ref-files)
  (let* ((scoped (max 0 scoped-files))
         (native (min scoped (max 0 native-ast-files)))
         (lex (min scoped (max 0 lexical-ref-files)))
         (ast-pct (if (= scoped 0) 100 (quotient (* native 100) scoped)))
         (hybrid-pct (if (= scoped 0) 100 (quotient (* (max native lex) 100) scoped))))
    (.o scoped-files: scoped
        native-ast-files: native
        lexical-ref-files: lex
        ast-coverage-pct: ast-pct
        hybrid-coverage-pct: hybrid-pct
        requires-lexical-fallback?: (< native scoped)
        complete-coverage?: (= (max native lex) scoped))))

;;; Pure identifier stem decomposition for zero-hit L0 search recovery:
;;; splits compound snake_case / kebab-case / CamelCase / alternation patterns
;;; into unique lowercase identifier stems of length >= 4 for live RAM probing.
(def (decompose-zero-hit-stems raw-pattern)
  (let ((len (string-length raw-pattern))
        (seen (make-hash-table))
        (stems '()))
    (def (record! buf)
      (when (>= (length buf) 4)
        (let ((s (string-downcase (list->string (reverse buf)))))
          (unless (or (member s '("error" "tests" "test" "from" "with" "this" "that" "true" "false"))
                      (hash-get seen s))
            (hash-put! seen s #t)
            (set! stems (cons s stems))))))
    (let loop ((i 0) (cur '()) (prev-lower? #f))
      (if (>= i len)
        (begin
          (record! cur)
          (reverse stems))
        (let ((ch (string-ref raw-pattern i)))
          (cond
            ((char-alphabetic? ch)
             (if (and (char-upper-case? ch) prev-lower? (pair? cur))
               (begin
                 (record! cur)
                 (loop (+ i 1) (list ch) #f))
               (loop (+ i 1) (cons ch cur) (char-lower-case? ch))))
            (else
             (record! cur)
             (loop (+ i 1) '() #f))))))))

;;; Deterministic intent router mapping structured search requirements to the
;;; narrowest sound execution tier (`l0-fast-ram`, `l1-relational-ascent`, or
;;; `l2-dusa-choice`).
(def (classify-search-tier-intent intent)
  (cond
    ((memq intent '(placement-solving disambiguation constraint-satisfaction multi-world))
     'l2-dusa-choice)
    ((memq intent '(impact-analysis collision-detection call-graph trait-impls structural-join))
     'l1-relational-ascent)
    ((memq intent '(text-search regex-search file-outline line-read))
     'l0-fast-ram)
    (else
     (error "unknown search tier intent" intent))))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Development projection script: dynamically discovers all co-located Quint
;;; models via Yuanxu's multi-window init.ss + Design 165 3-axis profile
;;; convergence, validates sealed plans in memory, and projects self-contained
;;; pure .qnt files and README.org files into packages/quint-models/.
;;; Consumes quint-methods and quint-profiles directly from the same Yuanxu
;;; selected-graph epoch so prototype identity is 100% coherent.
;;; All filesystem I/O lives here; library/quint-methods/ remains pure.
(import :clan/poo/object
        :std/misc/ports
        (only-in :tao3k/yuanxu/module-system/interface yuanxu-load-modules))
(export project-all-quint-models!)

(def (ensure-qnt-header text identity)
  (if (string-contains text "// @quint-model ")
    text
    (let ((lines (string-split text #\newline)))
      (let loop ((rest lines) (acc '()) (inserted? #f))
        (cond
          ((null? rest) (string-join (reverse acc) "\n"))
          ((and (not inserted?)
                (not (string-prefix? "//" (car rest))))
           (loop rest
                 (append (list "// @quint-version 0.33.0"
                               (string-append "// @quint-model " identity))
                         acc)
                 #t))
          (else
           (loop (cdr rest) (cons (car rest) acc) inserted?)))))))

(def (find-module-exports graph mod-identity)
  (def node
    (find (lambda (n)
            (and (eq? (.ref n 'kind) 'module-core)
                 (let ((pub (.ref n 'publication)))
                   (and (object? pub)
                        (.slot? pub 'identity)
                        (eq? (.ref pub 'identity) mod-identity)))))
          (.ref graph 'nodes)))
  (unless node
    (error "Required module missing from Yuanxu selected-graph" mod-identity))
  (.get (.ref node 'publication) core exports))

(def (quint-model-node? node)
  (and (eq? (.ref node 'kind) 'module-core)
       (let ((pub (.ref node 'publication)))
         (and (object? pub)
              (.slot? pub 'tags)
              (list? (.ref pub 'tags))
              (memq 'quint.model (.ref pub 'tags))
              #t))))

(def (project-all-quint-models! repo-root)
  (def init-path (path-expand "init.ss" repo-root))
  (def pkg-root (path-expand "packages/quint-models" repo-root))
  (def view (yuanxu-load-modules init-path))
  (def graph (.ref view 'selected-graph))
  (def methods-exp (find-module-exports graph 'quint-methods))
  (def profiles-exp (find-module-exports graph 'quint-profiles))
  (def converge-graph (.get profiles-exp converge))
  (def model->profile (.get profiles-exp model->profile))
  (def project-module (.get methods-exp project-module))
  (def project-readme (.get methods-exp project-readme))
  (def plan-fn (.get methods-exp plan))
  (def policy (.get methods-exp config))
  (def converged (converge-graph graph))
  (unless (eq? (.ref converged 'status) 'ready)
    (error "Quint Design 165 convergence rejected graph" (.ref converged 'diagnostics)))
  (def eff-configs (.ref converged 'effective-configs))
  (def model-nodes (filter quint-model-node? (.ref graph 'nodes)))
  (for-each
    (lambda (node)
      (def mid (.ref node 'identity))
      (def pub (.ref node 'publication))
      (def model (.get pub core exports entry))
      (def slots (.ref eff-configs mid))
      (def profile (model->profile model slots))
      (def out-dir (path-expand (.get model domain-dir) pkg-root))
      (create-directory* out-dir)
      ;; Validate sealed profile + plan contract in memory without emitting JSON sidecars.
      (plan-fn model profile policy)
      (def qnt-text (project-module model))
      (def qnt-path (path-expand (.get model quint-file) out-dir))
      (call-with-output-file qnt-path (lambda (p) (display qnt-text p)))
      (when (.slot? model 'title)
        (let ((readme-text (project-readme model))
              (readme-path (path-expand "README.org" out-dir)))
          (call-with-output-file readme-path (lambda (p) (display readme-text p))))))
    model-nodes)
  ;; Also publish the maintained engineering/concurrency/backpressure-memory Quint model (D3).
  (def bp-src
    (path-expand "languages-engineering/quint/concurrency/backpressure-memory/model.qnt" repo-root))
  (when (file-exists? bp-src)
    (let ()
      (def bp-dir (path-expand "engineering/concurrency/backpressure-memory" pkg-root))
      (create-directory* bp-dir)
      (def bp-text
        (ensure-qnt-header (read-file-string bp-src)
                           "engineering.concurrency.backpressure-memory"))
      (def bp-qnt (path-expand "BackpressureOwners.qnt" bp-dir))
      (call-with-output-file bp-qnt (lambda (p) (display bp-text p)))))
  (length model-nodes))

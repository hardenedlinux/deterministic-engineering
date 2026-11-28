#!/usr/bin/env gxi
;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero-hardcoding product construction via native Yuanxu .compile-selection.
;;; Mounts are discovered directly from `init.ss` (`:load-modules ... mount: <M>`)
;;; so adding new mounts requires ZERO edits here. Supports full builds as well as
;;; fast incremental single-mount (`--mount=M1,M2`) and single-file (`--file=<mod>`)
;;; compilation.
(import (only-in :clan/poo/object .call .get)
        (only-in :std/build-script defbuild-script)
        (only-in :std/make make make-clean)
        (only-in :std/source this-source-file)
        (only-in "./init.ss" deterministic-engineering.init.exports))

(def (discover-init-mounts)
  (def init-path (path-expand "init.ss" (path-directory (this-source-file))))
  (def forms
    (call-with-input-file init-path
      (lambda (port)
        (let loop ((acc '()))
          (let ((f (read port)))
            (if (eof-object? f) (reverse acc) (loop (cons f acc))))))))
  (def yuanxu-form (find (lambda (f) (and (pair? f) (eq? (car f) 'yuanxu!))) forms))
  (if (not yuanxu-form)
    (error "No (yuanxu! ...) declaration found in init.ss")
    (let loop ((rest (cdr yuanxu-form)) (acc '()))
      (cond
       ((null? rest) (reverse acc))
       ((and (keyword? (car rest))
             (equal? (keyword->string (car rest)) "mount")
             (pair? (cdr rest))
             (symbol? (cadr rest)))
        (let ((m (cadr rest)))
          (loop (cddr rest) (if (memq m acc) acc (cons m acc)))))
       (else (loop (cdr rest) acc))))))

(def (parse-compile-args flags)
  (def options '())
  (def selected-mounts '())
  (def selected-files '())
  (for-each
    (lambda (flag)
      (cond
       ((equal? flag "--release") (set! options (cons* build-release: #t options)))
       ((equal? flag "--optimized") (set! options (cons* build-optimized: #t options)))
       ((equal? flag "--debug") (set! options (cons* debug: #t options)))
       ((string-prefix? "--mount=" flag)
        (let ((names (filter (lambda (s) (> (string-length s) 0))
                             (string-split (substring flag 8 (string-length flag)) #\,))))
          (set! selected-mounts (append selected-mounts (map string->symbol names)))))
       ((string-prefix? "--file=" flag)
        (let ((paths (filter (lambda (s) (> (string-length s) 0))
                             (string-split (substring flag 7 (string-length flag)) #\,))))
          (set! selected-files (append selected-files paths))))
       (else (error "Unexpected build option" flag))))
    flags)
  (values options selected-mounts selected-files))

(def (compile flags)
  (let-values (((options selected-mounts selected-files) (parse-compile-args flags)))
    (if (pair? selected-files)
      (apply make selected-files srcdir: (path-directory (this-source-file)) options)
      (let ((mounts (if (pair? selected-mounts) selected-mounts (discover-init-mounts))))
        (.call deterministic-engineering.init.exports .compile-selection '() mounts
          (lambda (targets root) (apply make targets srcdir: root options))
          package-roots?: #t)))))

(def (main . arguments)
  (match arguments
    ([] (compile '()))
    (["compile" . flags] (compile flags))
    (["clean"]
     (.call deterministic-engineering.init.exports .clean-selection '() (discover-init-mounts)
       (lambda (targets root) (make-clean targets srcdir: root))
       package-roots?: #t))
    (else
     (let ()
       (defbuild-script (.get deterministic-engineering.init.exports std-make-spec))
       (apply main arguments)))))

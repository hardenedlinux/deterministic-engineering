;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; CLI bridge for invoking the pure-Scheme gerbil-parser structural composer
;;; (quint-span-compose-overlay) in cross-engine differential tests against
;;; packages/quint-modules-resolver/src/compose.ts. All I/O stays here;
;;; library/quint-methods/grammar.ss remains pure.
(import :clan/poo/object
        :std/misc/ports
        "../../library/quint-methods/grammar.ss")
(export main)

(def (strip-qnt-ext p)
  (if (string-suffix? ".qnt" p)
    (substring p 0 (- (string-length p) 4))
    p))

(def (split-path-parts p)
  (filter (lambda (s) (not (equal? s ""))) (string-split p #\/)))

(def (compute-relative-path from-dir target-path)
  (def from-parts (split-path-parts from-dir))
  (def target-parts (split-path-parts target-path))
  (let loop ((a from-parts) (b target-parts))
    (if (and (pair? a) (pair? b) (equal? (car a) (car b)))
      (loop (cdr a) (cdr b))
      (let* ((ups (map (lambda (_) "..") a))
             (joined (append ups b)))
        (if (null? joined)
          "."
          (let ((rel (string-join joined "/")))
            (if (or (string-prefix? "./" rel) (string-prefix? "../" rel))
              rel
              (string-append "./" rel))))))))

(def (make-relative-import-rewriter base-dir out-dir)
  (lambda (src)
    (if (or (string-prefix? "./" src) (string-prefix? "../" src))
      (let ((target-abs (strip-qnt-ext (path-normalize (path-expand src base-dir)))))
        (compute-relative-path out-dir target-abs))
      src)))

(def (main base-path overlay-path out-path)
  (def base-abs (path-normalize (path-expand base-path)))
  (def out-abs (path-normalize (path-expand out-path)))
  (def base-src (read-file-string base-abs))
  (def overlay-src (read-file-string overlay-path))
  (def res (quint-span-compose-overlay
             base-src overlay-src
             import-rewriter: (make-relative-import-rewriter
                                (path-directory base-abs)
                                (path-directory out-abs))))
  (unless (and (.get res verified?) (quint-source-qualified? (.get res source)))
    (error "Scheme gerbil-parser compose failed post-edit qualification"))
  (call-with-output-file out-abs (lambda (p) (display (.get res source) p)))
  (displayln "SCHEME-COMPOSE-OK " out-abs))

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Development-side tree and manifest fact capture for OR01-OR06 (10.150).
;;; All filesystem I/O stays here; Library rules remain pure.
(import
  :clan/poo/object
  :std/encoding/json
  :std/misc/ports
  :std/list/list)
(export
  capture-repository-organization-facts
  extract-rendered-placements)

(def ignored-top-entries
  '(".git" ".github" ".gitignore" ".gerbil" ".data" ".cache" "node_modules"
    "LICENSE" "LICENSES" "LICENSING.org" "README.org" "bun.lock" "bun.lock.license"
    "package.json.license" "project.sysml"))

(def infrastructure-files
  '("gerbil.pkg" "init.ss" "build.ss" "types.ss" "config.ss" "manifest.ss" "Justfile" "package.json"))

(def (classify-top-entry name)
  (cond
   ((equal? name "library") '("SchemeModule"))
   ((equal? name "languages-engineering") '("LanguageAssets"))
   ((equal? name "packages") '("DistributionPackage"))
   ((equal? name "projects") '("ProjectEntry"))
   ((equal? name "examples") '("UserExample"))
   ((equal? name "t") '("DevelopmentVerification"))
   ((equal? name "docs") '("DocumentItem"))
   ((member name infrastructure-files) '("PackageInfrastructure"))
   (else '())))

(def (list-dir-sorted dir)
  (if (file-exists? dir)
    (list-sort string<? (directory-files dir))
    '()))

(def (read-json-file path)
  (call-with-input-file path (cut read-json <> object-as-hash: #t)))

(def (infer-export-family dir target)
  (cond
   ((or (string-contains target "quint-models") (string-contains target ".qnt") (string-contains target "/quint/"))
    "quint-model-content")
   ((string-contains target "quint-modules-resolver") "verification-tooling")
   ((or (string-contains target "render") (string-contains target "presentation")
        (equal? dir "packages/render"))
    "presentation")
   ((equal? dir "packages/quint-models") "quint-model-content")
   ((equal? dir "packages/quint-modules-resolver") "verification-tooling")
   (else "unknown")))

(def (extract-rendered-placements sysml-text placement-names)
  (filter (lambda (name)
            (or (string-contains sysml-text (string-append "::'" name "';"))
                (string-contains sysml-text (string-append "::" name ";"))
                (string-contains sysml-text (string-append "': " name ";"))
                (string-contains sysml-text (string-append ": " name ";"))))
          placement-names))

(def (parse-project-init-modules init-path)
  ;; Read (yuanxu! ...) forms and extract (@ "...") targets.
  (def forms
    (call-with-input-file init-path
      (lambda (port)
        (let loop ((acc '()))
          (let (form (read port))
            (if (eof-object? form) (reverse acc) (loop (cons form acc))))))))
  (def yuanxu-form (find (lambda (f) (and (pair? f) (eq? (car f) 'yuanxu!))) forms))
  (if (not yuanxu-form)
    '()
    (filter-map
      (lambda (item)
        (and (pair? item)
             (>= (length item) 3)
             (eq? (cadr item) '@)
             (string? (caddr item))
             (cons (symbol->string (car item)) (caddr item))))
      (cdr yuanxu-form))))

(def (capture-repository-organization-facts repo-root organization (sysml-override #f))
  (def placements (.get organization placements))
  (def placement-names (map car placements))
  (def top-entries
    (filter (lambda (name) (not (member name ignored-top-entries)))
            (list-dir-sorted repo-root)))
  (def managed-paths (map list top-entries))
  (def path-placements
    (apply append
      (map (lambda (name)
             (map (lambda (pl) (list name pl)) (classify-top-entry name)))
           top-entries)))
  ;; Check library/<mod>/ for forbidden other-language sources (.qnt, .lean, .ts, .js).
  (def library-dir (path-expand "library" repo-root))
  (def library-forbidden
    (apply append
      (map (lambda (mod)
             (def mod-dir (path-expand mod library-dir))
             (if (eq? (file-type mod-dir) 'directory)
               (filter-map
                 (lambda (fname)
                   (cond
                    ((or (string-suffix? ".qnt" fname) (string-suffix? ".lean" fname)
                         (string-suffix? ".ts" fname) (string-suffix? ".js" fname))
                     (list (string-append "library/" mod "/" fname)
                           "SchemeModule"
                           "other-language-sources"
                           (string-append "other-language-source-in-scheme-module:" fname)))
                    (else #f)))
                 (list-dir-sorted mod-dir))
               '()))
           (list-dir-sorted library-dir))))
  ;; Inspect root package.json and packages/*/package.json.
  (def pkg-dirs
    (cons "."
          (filter-map
            (lambda (sub)
              (def p (path-expand (string-append "packages/" sub "/package.json") repo-root))
              (and (file-exists? p) (string-append "packages/" sub)))
            (list-dir-sorted (path-expand "packages" repo-root)))))
  (def pkg-manifests '())
  (def pkg-export-families '())
  (def pkg-references '())
  (def file-refs '())
  (def root-forbidden '())
  (for-each
    (lambda (dir)
      (def manifest-path
        (if (equal? dir ".")
          (path-expand "package.json" repo-root)
          (path-expand "package.json" (path-expand dir repo-root))))
      (when (file-exists? manifest-path)
        (let ()
          (def json (read-json-file manifest-path))
          (def pkg-name (or (hash-get json "name") "unnamed"))
          (def is-ws (if (hash-get json "workspaces") "yes" "no"))
          (set! pkg-manifests (cons (list dir pkg-name is-ws) pkg-manifests))
          ;; Root package.json carrying a concrete package (not private workspace) violates OR02.
          (when (and (equal? dir ".") (equal? is-ws "no"))
            (set! root-forbidden
                  (cons (list "package.json" "PackageInfrastructure"
                              "package-implementation"
                              (string-append "root-is-package:" pkg-name))
                        root-forbidden)))
          ;; Inspect exports for family and directory closure.
          (def exports-obj (hash-get json "exports"))
          (when (hash-table? exports-obj)
            (hash-for-each
              (lambda (k v)
                (when (string? v)
                  (unless (equal? k "./package.json")
                    (set! pkg-export-families
                          (cons (list dir pkg-name v (infer-export-family dir v))
                                pkg-export-families)))
                  ;; If root package exports ./packages/<subpkg>/..., that crosses into another package dir.
                  (when (or (string-prefix? "../" v)
                            (and (equal? dir ".") (string-prefix? "./packages/" v)))
                    (set! pkg-references
                          (cons (list dir pkg-name v "outside")
                                pkg-references)))))
              exports-obj))
          ;; Inspect files list for absent paths (OR05).
          (def files-list (hash-get json "files"))
          (when (list? files-list)
            (for-each
              (lambda (entry)
                (when (string? entry)
                  (let ((full (if (equal? dir ".")
                                (path-expand entry repo-root)
                                (path-expand entry (path-expand dir repo-root)))))
                    (set! file-refs
                          (cons (list (if (equal? dir ".") "package.json" (string-append dir "/package.json"))
                                      entry
                                      (if (file-exists? full) "present" "absent"))
                                file-refs)))))
              files-list)))))
    pkg-dirs)
  ;; Inspect projects/*/init.ss for absent Module references (OR05).
  (def projects-dir (path-expand "projects" repo-root))
  (for-each
    (lambda (proj)
      (def init-file (path-expand (string-append proj "/init.ss") projects-dir))
      (when (file-exists? init-file)
        (for-each
          (lambda (pair)
            (def mod-name (car pair))
            (def rel-target (cdr pair))
            (def resolved (path-expand rel-target (path-directory init-file)))
            (set! file-refs
                  (cons (list (string-append "projects/" proj "/init.ss")
                              mod-name
                              (if (file-exists? resolved) "present" "absent"))
                        file-refs)))
          (parse-project-init-modules init-file))))
    (list-dir-sorted projects-dir))
  ;; Inspect project.sysml (or override) for rendered placements (OR06).
  (def sysml-text
    (or sysml-override
        (let (p (path-expand "project.sysml" repo-root))
          (if (file-exists? p) (read-file-string p) ""))))
  (def rendered (map list (extract-rendered-placements sysml-text placement-names)))
  (list
    (cons 'declared_placement (map (lambda (r) (list (car r) (cadr r))) placements))
    (cons 'declared_placement_role (.get organization placement-roles))
    (cons 'required_role (map (lambda (r) (list (car r))) (.get organization roles)))
    (cons 'declared_package_family
          (map (lambda (r) (list (car r) (cadr r))) (.get organization package-families)))
    (cons 'declared_package_dir
          (map (lambda (r) (list (car r) (caddr r))) (.get organization package-families)))
    (cons 'managed_path managed-paths)
    (cons 'path_placement path-placements)
    (cons 'forbidden_item (append library-forbidden root-forbidden))
    (cons 'package_manifest pkg-manifests)
    (cons 'package_export_family pkg-export-families)
    (cons 'package_reference pkg-references)
    (cons 'declared_file_ref file-refs)
    (cons 'rendered_placement rendered)))

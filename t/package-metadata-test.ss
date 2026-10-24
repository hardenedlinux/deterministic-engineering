;;; -*- Gerbil -*-
;;; Validate native package metadata against the registered local Git sources.
(import :std/test (only-in :gerbil/tools/gxpkg pkg-root-dir pkg-plist)
        (only-in :std/misc/process run-process))

(def packages
  (map (lambda (dependency) (car (string-split dependency #\@)))
       (pgetq depend: (call-with-input-file "gerbil.pkg" read) '())))
(def (git-value package . args)
  (run-process (cons "git" args)
    directory: (path-expand package (pkg-root-dir)) coprocess: read-line))
(def (main . _args)
  (def versions
    (map (lambda (package)
           (def manifest (call-with-input-file
                           (path-expand (string-append package ".manifest") (pkg-root-dir)) read))
           (def version (assoc package manifest))
           (unless (and version (equal? (cdr version)
                                       (git-value package "describe" "--tags" "--always")))
             (error "native manifest differs from registered source" package version))
           (cons package (cdr version))) packages))
  (for-each
    (lambda (package)
      (for-each
        (lambda (dependency)
          (def parts (string-split dependency #\@))
          (when (pair? (cdr parts))
            (unless (equal? (cadr parts) (git-value (car parts) "rev-parse" "HEAD"))
              (error "declared dependency pin differs from registered source" package dependency))))
        (pgetq depend: (pkg-plist package) '()))) packages)
  (def form (call-with-input-file "manifest.ss" read))
  (unless (and (pair? form) (eq? (car form) 'def) (eq? (cadr form) 'version-manifest))
    (error "root manifest is not a native version declaration"))
  (def closure (cadr (caddr form)))
  (for-each (lambda (entry)
              (let (matches (filter (lambda (row) (equal? (car row) (car entry))) closure))
                (unless (equal? matches (list entry))
                  (error "root manifest has a missing or conflicting dependency" entry matches)))) versions)
  (for-each
    (lambda (namespace)
      (unless (eq? (file-info-type (file-info (path-expand namespace (path-expand "lib" (gerbil-path))) #f)) 'directory)
        (error "compiled namespace is not an ordinary local directory" namespace)))
    '("clan" "yuanxu" "gerbil-ascent"))
  (for-each
    (lambda (module)
      (for-each
        (lambda (suffix)
          (def artifact (path-expand (string-append module suffix) (path-expand "lib" (gerbil-path))))
          (unless (eq? (file-info-type (file-info artifact #f)) 'regular)
            (error "compiled import artifact is not a regular file" artifact)))
        '(".ssi" ".o1")))
    '("clan/poo/object" "yuanxu/module-system/selection/init-syntax"
      "gerbil-ascent/rules/interface"
      "deterministic-engineering/init"
      "deterministic-engineering/library/concurrency/resource-control/backpressure-memory/rust/interface"
      "deterministic-engineering/modules/resource-evidence/interface"
      "deterministic-engineering/scenarios/gateway-review/interface"
      "deterministic-engineering/profiles/gateway"))
  (displayln "NATIVE-PACKAGE-METADATA-OK"))

(export package-metadata-test)
(def package-metadata-test
  (test-suite "package-metadata-test"
    (test-case "native qualification" (main))))

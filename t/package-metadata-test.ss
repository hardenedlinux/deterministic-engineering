;;; -*- Gerbil -*-
;;; Validate native package metadata against the registered local Git sources.
(import :std/test (only-in :gerbil/tools/gxpkg pkg-root-dir pkg-plist pkg-list)
        (only-in :yuanxu/module-system/building/artifacts require-build-products!)
        (only-in :std/misc/process run-process))

(def root-metadata (call-with-input-file "gerbil.pkg" read))
;; Native registry owns the installed closure; this test does not resolve it.
(def packages (pkg-list))
(def (git-value package . args)
  (run-process (cons "git" args)
    directory: (path-expand package (pkg-root-dir)) coprocess: read-line))
(def (check-dependency-pins metadata)
  (for-each
    (lambda (dependency)
      (def parts (string-split dependency #\@))
      (when (pair? (cdr parts))
        (unless (equal? (cadr parts) (git-value (car parts) "rev-parse" "HEAD"))
          (error "declared dependency pin differs from registered source" dependency))
        (let (tag-file (path-expand (string-append (car parts) ".tag") (pkg-root-dir)))
          (unless (and (file-exists? tag-file)
                       (equal? (cadr parts) (call-with-input-file tag-file read)))
            (error "declared dependency pin differs from native registered tag" dependency)))))
    (pgetq depend: metadata '())))

;; The native registry may contain unrelated development tools. The SDK root
;; manifest records the root's declared dependency graph, not every cached tool.
(def (declared-packages metadata)
  (let loop ((todo (pgetq depend: metadata '())) (seen '()))
    (if (null? todo) seen
      (let (package (car (string-split (car todo) #\@)))
        (if (member package seen)
          (loop (cdr todo) seen)
          (loop (append (pgetq depend: (pkg-plist package) '()) (cdr todo))
                (cons package seen)))))))
(def (check-root-closure closure versions selected)
  (for-each (lambda (package)
              (unless (assoc package versions)
                (error "declared dependency has no registered native source" package))) selected)
  (for-each (lambda (entry)
              (let ((matches (filter (lambda (row) (equal? (car row) (car entry))) closure))
                    (expected (if (member (car entry) selected) (list entry) '())))
                (unless (equal? matches expected)
                  (error "root manifest has missing, duplicate, conflicting or unrelated dependency" entry matches)))) versions))
(def (main . _args)
  (def direct (pgetq depend: root-metadata '()))
  (unless (and (= (length direct) 2)
               (= (length (filter (cut string-prefix? "github.com/tao3k/agentic-ai-lab@" <>) direct)) 1)
               (= (length (filter (cut string-prefix? "github.com/tao3k/gebril-yuanxu@" <>) direct)) 1))
    (error "Root must directly pin its product and Yuanxu dependencies" direct))
  (for-each (lambda (path)
              (when (file-exists? path)
                (error "Nested metadata must not override the root package" path)))
    '("modules/gerbil.pkg" "library/gerbil.pkg" "profiles/gerbil.pkg"
      "scenarios/gerbil.pkg" "scenarios/resource-lifecycle/review/gerbil.pkg"))
  (check-dependency-pins root-metadata)
  ;; This published product cohort selects the same actual Core source.
  (def core-head (git-value "github.com/tao3k/gebril-yuanxu" "rev-parse" "HEAD"))
  (unless (and (equal? core-head
                        (git-value "github.com/tao3k/agentic-ai-lab" "rev-parse" "HEAD:core"))
               (equal? core-head
                        (git-value "github.com/tao3k/agentic-ai-lab" "-C" "core" "rev-parse" "HEAD")))
    (error "published product Core gitlink and native Yuanxu source disagree"))
  (def versions
    (map (lambda (package)
           (def manifest (call-with-input-file
                           (path-expand (string-append package ".manifest") (pkg-root-dir)) read))
           (def version (assoc package manifest))
           (unless (and version (equal? (cdr version)
                                       (git-value package "describe" "--tags" "--always")))
             (error "native manifest differs from registered source" package version))
           (cons package (cdr version))) packages))
  (for-each (lambda (package) (check-dependency-pins (pkg-plist package))) packages)
  (def form (call-with-input-file "manifest.ss" read))
  (unless (and (pair? form) (eq? (car form) 'def) (eq? (cadr form) 'version-manifest))
    (error "root manifest is not a native version declaration"))
  (def closure (cadr (caddr form)))
  (def selected (declared-packages root-metadata))
  (check-root-closure closure versions selected)
  ;; Negative controls mutate the actual native-generated data; no fixture
  ;; manifest can substitute for the real source/tag/artifact/import gate.
  (def required (assoc (car selected) versions))
  (check-exception (check-root-closure (filter (lambda (row) (not (equal? (car row) (car required)))) closure)
                                     versions selected) (lambda (_) #t))
  (check-exception (check-root-closure (cons required closure) versions selected) (lambda (_) #t))
  (check-exception (check-root-closure (cons (cons (car required) "wrong-revision") closure)
                                     versions selected) (lambda (_) #t))
  (for-each (lambda (entry)
              (unless (member (car entry) selected)
                (check-exception (check-root-closure (cons entry closure) versions selected) (lambda (_) #t)))) versions)
  (displayln "NATIVE-COHORT-CLOSURE-OK registered=" (length versions) " declared=" (length selected))
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
      "yuanxu/modules/funflow/control-plane/api"
      "yuanxu/modules/funflow/control-plane/runtime-command-descriptor"
      "agentic-ai-lab/services"
      "agentic-ai-lab/modules/workflow/contracts/runtime-v0-abi-schema"
      "agentic-ai-lab/modules/temporal-causality/trajectory/ascent-ledger"
      "gerbil-ascent/rules/interface"
      "deterministic-engineering/init"
      "deterministic-engineering/library/concurrency/resource-control/backpressure-memory/rust/interface"
      "deterministic-engineering/modules/resource-evidence/interface"
      "deterministic-engineering/scenarios/gateway-review/interface"
      "deterministic-engineering/profiles/gateway"))
  ;; Reuse the producer's phase-family check, including generated macro objects.
  (require-build-products!
    '(deterministic-engineering/modules/resource-evidence/interface)
    (path-expand "lib" (gerbil-path)))
  ;; Check products before importing: a missing object must not be hidden by
  ;; the loader's Scheme fallback. This runs in each fresh bounded test process.
  (eval '(begin
           (import (only-in :clan/poo/object object?)
                   (only-in :clan/poo/mop Type element?)
                   (only-in :agentic-ai-lab/services Services)
                   (only-in :deterministic-engineering/init
                            deterministic-engineering.init.exports))
           (unless (and (object? deterministic-engineering.init.exports)
                        (element? Type Services))
             (error "installed package and Type ABI failed to load"))
           (displayln "COMPILED-PACKAGE-LOAD-OK")))
  (displayln "NATIVE-PACKAGE-METADATA-OK"))

(export package-metadata-test)
(def package-metadata-test
  (test-suite "package-metadata-test"
    (test-case "native qualification" (main))))

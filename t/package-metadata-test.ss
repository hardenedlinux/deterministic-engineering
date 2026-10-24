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
          (error "declared dependency pin differs from registered source" dependency))))
    (pgetq depend: metadata '())))
(def (main . _args)
  (def direct (pgetq depend: root-metadata '()))
  (unless (and (= (length direct) 1)
               (string-prefix? "github.com/tao3k/agentic-ai-lab@" (car direct)))
    (error "Agentic AI Lab must own the root dependency closure" direct))
  (check-dependency-pins root-metadata)
  ;; Agentic's declared Module source must match the same inherited Core build.
  (def core-head (git-value "github.com/tao3k/gebril-yuanxu" "rev-parse" "HEAD"))
  (unless (and
            (equal? core-head
              (git-value "github.com/tao3k/agentic-ai-lab" "rev-parse" "HEAD:core"))
            (equal? core-head
              (git-value "github.com/tao3k/agentic-ai-lab" "-C" "core" "rev-parse" "HEAD")))
    (error "declared Core gitlink, Module source and inherited package disagree"))
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
      "yuanxu/modules/funflow/control-plane/api"
      "yuanxu/modules/funflow/control-plane/runtime-command-descriptor"
      "agentic-ai-lab/modules/services/types"
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
                   (only-in :agentic-ai-lab/modules/services/types Services)
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

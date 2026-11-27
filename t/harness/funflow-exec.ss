#!/usr/bin/env gxi
;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Canonical Yuanxu + Functional Fun-Flow Verification Execution Control Plane.
;;;
;;; Scales cleanly to 1,000-10,000+ modules with ZERO hardcoded test lists, domain
;;; switches, or Scheme scopes:
;;;   1. Projects every Yuanxu `:load-modules` mount from `init.ss` and every
;;;      `<mod>/interface.ss` (`identity:`, `tags:`) via fast S-expression `read`
;;;      (<50ms across 100+ modules; O(N) linear without cold-loading unused mounts).
;;;   2. Projects `t/integration/*`, `languages-engineering/<lang>/<domain>/...`,
;;;      `packages/lean-models/DeterministicEngineering/**/*.lean`, and `package.json`
;;;      workspace/root scripts into one uniform VerificationUnit graph.
;;;   3. Compiles any queried/impacted subset in O(N) linear time into a real
;;;      upstream Fun-Flow DAG (`:tao3k/agentic-ai-lab/modules/funflow/control-plane/api`).
;;;   4. Executes pending units in conflict-free parallel Gambit green-thread waves
;;;      (`--jobs=N`), reuses unchanged units via SHA-256 content-addressed cache
;;;      (`--cache=<dir>` + `make-cached-local-eager-strategy`), slices O(Delta)
;;;      work via `--impact` / `--changed=...`, and proves execution integrity via
;;;      Fun-Flow `validate-replay-report`.

(import
  :std/crypto/digest
  :std/encoding/hex
  :std/encoding/json
  :std/list/list
  :std/misc/ports
  :std/misc/process
  (only-in :std/source this-source-file)
  (only-in :clan/poo/object .o .get .ref .cc)
  (only-in :tao3k/agentic-ai-lab/modules/funflow/control-plane/api
           Type.
           Fun
           AdapterResult
           adapter-result-status
           adapter-result-value
           adapter-result-error
           make-external-task
           make-pure-task
           flow-compose
           flow->dag-receipt
           flow->dag-runtime-manifest
           execution-plan-flow-name
           execution-plan-node-ids
           make-runtime-adapter
           make-adapter-result
           execution-request-name
           execution-request-plan-id
           execution-request-node-id
           make-local-eager-strategy
           make-cached-local-eager-strategy
           make-runner
           runner-plan
           runner-run
           run-result-receipt
           validate-replay-report
           replay-report-valid?
           replay-report-status
           replay-report-reasons))

(export
  discover-all-units
  filter-units
  compile-units->funflow
  run-funflow-cli
  main)

;; ── 1. Filesystem, S-Expression & SHA-256 Utilities ──

(def skip-walk-dirs
  '("node_modules" "target" ".lake" ".devenv" "vendor" ".git" ".gerbil" ".data"))

(def auto-env-prefixes
  '("RESOURCE_CARGO" "RESOURCE_RUSTC" "SOURCE_CONTRACT_"))

(def (repo-root-dir)
  (path-normalize (path-expand "../.." (path-directory (this-source-file)))))

(def (dir-exists? p)
  (and (file-exists? p) (eq? (file-type p) 'directory)))

(def (regular-file? p)
  (and (file-exists? p) (eq? (file-type p) 'regular)))

(def (sort-strings xs)
  (list-sort string<? xs))

(def (list-take xs n)
  (if (or (<= n 0) (null? xs))
    '()
    (cons (car xs) (list-take (cdr xs) (- n 1)))))

(def (list-dir-sorted dir)
  (if (dir-exists? dir)
    (sort-strings (directory-files dir))
    '()))

(def (strip-trailing-slash p)
  (let ((n (string-length p)))
    (if (and (> n 1) (string-suffix? "/" p))
      (substring p 0 (- n 1))
      p)))

(def (strip-dot-slash p)
  (if (and (>= (string-length p) 2) (string-prefix? "./" p))
    (substring p 2 (string-length p))
    p))

(def (rel-path repo-root full)
  (def norm-root
    (if (string-suffix? "/" repo-root) repo-root (string-append repo-root "/")))
  (if (string-prefix? norm-root full)
    (substring full (string-length norm-root) (string-length full))
    full))

(def (path-join a b)
  (cond
   ((or (equal? a "") (equal? a ".")) b)
   ((string-suffix? "/" a) (string-append a b))
   (else (string-append a "/" b))))

(def (path-basename p)
  (path-strip-directory p))

(def (path-stem p suffix)
  (def b (path-basename p))
  (if (string-suffix? suffix b)
    (substring b 0 (- (string-length b) (string-length suffix)))
    b))

(def (find-files dir pred)
  (def acc '())
  (let walk ((cur dir))
    (for-each
      (lambda (name)
        (unless (member name skip-walk-dirs)
          (let ((full (path-join cur name)))
            (cond
             ((dir-exists? full) (walk full))
             ((pred full name) (set! acc (cons full acc)))))))
      (list-dir-sorted cur)))
  (sort-strings acc))

(def (collect-input-files repo-root rel-paths)
  (def seen (make-hash-table))
  (def acc '())
  (def (add-file! full)
    (def r (rel-path repo-root full))
    (unless (hash-key? seen r)
      (hash-put! seen r #t)
      (set! acc (cons r acc))))
  (for-each
    (lambda (rp)
      (def full (path-expand rp repo-root))
      (cond
       ((dir-exists? full)
        (for-each add-file! (find-files full (lambda (_ __) #t))))
       ((regular-file? full)
        (add-file! full))))
    rel-paths)
  (sort-strings acc))

(def (read-all-sexprs file-path)
  (with-catch
    (lambda (_) '())
    (lambda ()
      (call-with-input-file file-path
        (lambda (port)
          (let loop ((acc '()))
            (let ((form (read port)))
              (if (eof-object? form)
                (reverse acc)
                (loop (cons form acc))))))))))

(def (sym-or-str->string x)
  (cond
   ((symbol? x) (symbol->string x))
   ((keyword? x) (keyword->string x))
   ((string? x) x)
   (else #f)))

(def (str-join xs sep)
  (if (null? xs)
    ""
    (let loop ((rest (cdr xs)) (acc (list (car xs))))
      (if (null? rest)
        (apply string-append (reverse acc))
        (loop (cdr rest) (cons (car rest) (cons sep acc)))))))

(def (str-trim s)
  (def len (string-length s))
  (def (ws? c) (or (char=? c #\space) (char=? c #\tab) (char=? c #\newline) (char=? c #\return)))
  (def start
    (let loop ((i 0))
      (if (and (< i len) (ws? (string-ref s i))) (loop (+ i 1)) i)))
  (def end
    (let loop ((i len))
      (if (and (> i start) (ws? (string-ref s (- i 1)))) (loop (- i 1)) i)))
  (substring s start end))

(def (shell-quote s)
  (let loop ((i 0) (n (string-length s)) (acc (list "'")))
    (if (= i n)
      (apply string-append (reverse (cons "'" acc)))
      (let ((c (string-ref s i)))
        (if (char=? c #\')
          (loop (+ i 1) n (cons "'\"'\"'" acc))
          (loop (+ i 1) n (cons (string c) acc)))))))

(def (split-csv s)
  (filter (lambda (x) (> (string-length x) 0))
          (map str-trim (string-split s #\,))))

(def (string-downcase-ascii s)
  (list->string (map char-downcase (string->list s))))

(def (dedup-sorted-strings xs)
  (def seen (make-hash-table))
  (def acc '())
  (for-each
    (lambda (s)
      (when (and (string? s) (not (hash-key? seen s)))
        (hash-put! seen s #t)
        (set! acc (cons s acc))))
    xs)
  (sort-strings acc))

(def (sha256-of-unit repo-root unit)
  (def parts
    (list (string-append "unit:" (.get unit id) "\nkind:" (symbol->string (.get unit kind))
                         "\nscript:" (.get unit script) "\n")))
  (for-each
    (lambda (rp)
      (def full (path-expand rp repo-root))
      (set! parts (cons (string-append "file:" rp "\n") parts))
      (when (regular-file? full)
        (set! parts (cons (hex-encode (sha256 (read-file-u8vector full))) parts))
        (set! parts (cons "\n" parts))))
    (.get unit inputs))
  (hex-encode (sha256 (string->bytes (apply string-append (reverse parts))))))

;; ── 2. S-Expression Metadata & Dependency Extractors ──

(def (extract-quoted-symbol-list val)
  (def raw
    (cond
     ((and (pair? val) (eq? (car val) 'quote) (pair? (cdr val)) (list? (cadr val)))
      (cadr val))
     ((list? val) val)
     (else '())))
  (filter-map (lambda (x) (and (symbol? x) (symbol->string x))) raw))

(def (extract-interface-meta iface-path)
  (def forms (read-all-sexprs iface-path))
  (def identity-str #f)
  (def tags '())
  (let walk ((node forms))
    (when (pair? node)
      (let loop ((cur node))
        (when (pair? cur)
          (let ((head (car cur)))
            (cond
             ((and (keyword? head) (equal? (keyword->string head) "identity") (pair? (cdr cur)))
              (let ((v (cadr cur)))
                (cond
                 ((and (pair? v) (eq? (car v) 'quote) (pair? (cdr v)) (symbol? (cadr v)))
                  (set! identity-str (symbol->string (cadr v))))
                 ((symbol? v) (set! identity-str (symbol->string v)))
                 ((string? v) (set! identity-str v))))
              (loop (cddr cur)))
             ((and (keyword? head) (equal? (keyword->string head) "tags") (pair? (cdr cur)))
              (set! tags (append tags (extract-quoted-symbol-list (cadr cur))))
              (loop (cddr cur)))
             (else
              (when (pair? head) (walk head))
              (loop (cdr cur)))))))))
  (values identity-str (dedup-sorted-strings tags)))

(def (extract-library-imports-from-form form)
  (cond
   ((symbol? form)
    (let ((s (symbol->string form)))
      (if (string-prefix? ":deterministic-engineering/library/" s)
        (let* ((rest (substring s (string-length ":deterministic-engineering/library/") (string-length s)))
               (slash (string-index rest #\/)))
          (if slash (list (substring rest 0 slash)) '()))
        '())))
   ((string? form)
    (if (string-prefix? "../" form)
      (let* ((rest (substring form 3 (string-length form)))
             (slash (string-index rest #\/)))
        (if slash (list (substring rest 0 slash)) '()))
      '()))
   ((pair? form)
    (append (extract-library-imports-from-form (car form))
            (extract-library-imports-from-form (cdr form))))
   (else '())))

(def (build-library-dep-graph repo-root)
  (def lib-dir (path-expand "library" repo-root))
  (def graph (make-hash-table))
  (for-each
    (lambda (mod)
      (def mod-dir (path-join lib-dir mod))
      (when (dir-exists? mod-dir)
        (let ((deps '()))
          (for-each
            (lambda (fname)
              (when (string-suffix? ".ss" fname)
                (for-each
                  (lambda (f)
                    (when (and (pair? f) (eq? (car f) 'import))
                      (for-each
                        (lambda (d)
                          (when (and (not (equal? d mod))
                                     (dir-exists? (path-join lib-dir d))
                                     (not (member d deps)))
                            (set! deps (cons d deps))))
                        (extract-library-imports-from-form (cdr f)))))
                  (read-all-sexprs (path-join mod-dir fname)))))
            (list-dir-sorted mod-dir))
          (hash-put! graph mod (sort-strings deps)))))
    (list-dir-sorted lib-dir))
  graph)

(def (transitive-library-deps graph root-mod)
  (def visited (make-hash-table))
  (hash-put! visited root-mod #t)
  (let loop ((queue (list root-mod)))
    (unless (null? queue)
      (let* ((cur (car queue))
             (next-deps (filter (lambda (d) (and (hash-key? graph d) (not (hash-key? visited d))))
                                (or (hash-get graph cur) '()))))
        (for-each (lambda (d) (hash-put! visited d #t)) next-deps)
        (loop (append (cdr queue) next-deps)))))
  (sort-strings (hash-keys visited)))

(def (detect-mandatory-env-tags file-path)
  (def forms (read-all-sexprs file-path))
  (def needs-env? #f)
  (let walk ((node forms))
    (when (and (not needs-env?) (pair? node))
      (if (and (eq? (car node) 'getenv)
               (pair? (cdr node))
               (string? (cadr node))
               (null? (cddr node)))
        (let ((var-name (cadr node)))
          (unless (ormap (lambda (p) (string-prefix? p var-name)) auto-env-prefixes)
            (set! needs-env? #t)))
        (begin
          (walk (car node))
          (walk (cdr node))))))
  (if needs-env? '("requires:env") '()))

;; ── 3. Zero-Hardcoding Verification Unit Discovery ──

(def (make-unit id kind mount module domain tags inputs conflict-key timeout-sec script)
  (.o bind-these: #f
      id: id
      kind: kind
      mount: mount
      module: module
      domain: domain
      tags: (dedup-sorted-strings tags)
      inputs: inputs
      conflict-key: conflict-key
      timeout-sec: timeout-sec
      script: script))

(def (parse-init-mounts repo-root)
  (def init-path (path-expand "init.ss" repo-root))
  (def forms (if (regular-file? init-path) (read-all-sexprs init-path) '()))
  (def yuanxu-form (find (lambda (f) (and (pair? f) (eq? (car f) 'yuanxu!))) forms))
  (if (not yuanxu-form)
    '()
    (let loop ((rest (cdr yuanxu-form)) (acc '()))
      (cond
       ((null? rest) (reverse acc))
       ((eq? (car rest) ':load-modules)
        (let ((target (and (pair? (cdr rest)) (cadr rest))))
          (let scan ((cur (if (pair? (cdr rest)) (cddr rest) '()))
                     (mount #f)
                     (test-dir "./t")
                     (profiles '()))
            (cond
             ((or (null? cur) (eq? (car cur) ':load-modules))
              (loop cur
                    (if (and (string? target) mount)
                      (cons (.o bind-these: #f
                                rel-dir: (strip-dot-slash target)
                                mount: mount
                                test-dir: (strip-dot-slash test-dir)
                                profiles: profiles)
                            acc)
                      acc)))
             ((and (keyword? (car cur)) (equal? (keyword->string (car cur)) "mount") (pair? (cdr cur)))
              (scan (cddr cur) (sym-or-str->string (cadr cur)) test-dir profiles))
             ((and (eq? (car cur) ':test-dir) (pair? (cdr cur)) (string? (cadr cur)))
              (scan (cddr cur) mount (cadr cur) profiles))
             ((and (eq? (car cur) ':profiles) (pair? (cdr cur)) (list? (cadr cur)))
              (scan (cddr cur) mount test-dir (extract-quoted-symbol-list (cadr cur))))
             (else
              (scan (cdr cur) mount test-dir profiles))))))
       (else (loop (cdr rest) acc))))))

(def (derive-mount-domain mount tags)
  (def parts (string-split mount #\.))
  (cond
   ((>= (length parts) 3) (string-downcase-ascii (car (reverse parts))))
   ((or (member "defense" tags) (member "de.layer.defense" tags)) "defense")
   ((or (member "funflow" tags) (member "verification" tags)) "multi-method")
   (else (string-downcase-ascii mount))))

(def (discover-yuanxu-units repo-root)
  (def mounts (parse-init-mounts repo-root))
  (def lib-graph (build-library-dep-graph repo-root))
  (def acc '())
  (for-each
    (lambda (m)
      (def rel-dir (.get m rel-dir))
      (def mount (.get m mount))
      (def test-dir (.get m test-dir))
      (def profiles (.get m profiles))
      (def root-dir (path-expand rel-dir repo-root))
      (for-each
        (lambda (mod)
          (def mod-dir (path-join root-dir mod))
          (def iface-path (path-join mod-dir "interface.ss"))
          (when (and (dir-exists? mod-dir) (regular-file? iface-path))
            (let-values (((ident iface-tags) (extract-interface-meta iface-path)))
              (def mod-id (or ident mod))
              (def domain (derive-mount-domain mount iface-tags))
              (def owned-test-dir
                (path-expand (path-join test-dir (path-join "yanxu" (path-join mount mod)))
                             repo-root))
              (def test-files (find-files owned-test-dir (lambda (_ n) (string-suffix? "-test.ss" n))))
              (def dep-dirs
                (if (equal? mount "Library")
                  (map (lambda (d) (path-join "library" d)) (transitive-library-deps lib-graph mod))
                  (list (path-join rel-dir mod))))
              (for-each
                (lambda (tf)
                  (def rel-tf (rel-path repo-root tf))
                  (def stem (path-stem tf ".ss"))
                  (def env-tags (detect-mandatory-env-tags tf))
                  (def extra-defense
                    (if (or (member "de.layer.defense" iface-tags)
                            (member "quint.engineering.defense" iface-tags))
                      '("defense")
                      '()))
                  (def tags
                    (append iface-tags profiles env-tags extra-defense
                            (list "scheme" "lang:scheme"
                                  (string-append "mount:" mount)
                                  (string-append "module:" mod-id)
                                  (string-append "domain:" domain)
                                  domain
                                  (string-append "scheme:" domain))))
                  (def timeout-sec
                    (if (or (member "funflow" iface-tags) (string-contains stem "fleet")) 600 120))
                  (def inputs (collect-input-files repo-root (cons "init.ss" (cons rel-tf dep-dirs))))
                  (def script
                    (string-append "t/harness/run-gxtest.sh file "
                                   (shell-quote rel-tf) " '.*' "
                                   (number->string timeout-sec) "s"))
                  (set! acc
                    (cons (make-unit (string-append "scheme:" mount "/" mod "/" stem)
                                     'scheme mount mod-id domain tags inputs #f timeout-sec script)
                          acc)))
                test-files))))
        (list-dir-sorted root-dir)))
    mounts)

  ;; Auto-discover t/integration/<group>/*-test.ss
  (def int-root (path-expand "t/integration" repo-root))
  (for-each
    (lambda (group)
      (def group-dir (path-join int-root group))
      (when (dir-exists? group-dir)
        (for-each
          (lambda (tf)
            (def rel-tf (rel-path repo-root tf))
            (def stem (path-stem tf ".ss"))
            (def env-tags (detect-mandatory-env-tags tf))
            (def tags
              (append env-tags
                      (list "scheme" "lang:scheme" "integration"
                            (string-append "integration." group)
                            "mount:Integration"
                            (string-append "module:" group)
                            (string-append "domain:" group)
                            group)))
            (def inputs (collect-input-files repo-root (list "init.ss" rel-tf)))
            (def script
              (string-append "t/harness/run-gxtest.sh file " (shell-quote rel-tf) " '.*' 180s"))
            (set! acc
              (cons (make-unit (string-append "scheme:Integration/" group "/" stem)
                               'scheme "Integration" group group tags inputs #f 180 script)
                    acc)))
          (find-files group-dir (lambda (_ n) (string-suffix? "-test.ss" n))))))
    (list-dir-sorted int-root))
  (reverse acc))

(def (discover-polyglot-units repo-root)
  (def lang-root (path-expand "languages-engineering" repo-root))
  (def acc '())
  (for-each
    (lambda (lang)
      (def lang-dir (path-join lang-root lang))
      (when (dir-exists? lang-dir)
        (for-each
          (lambda (domain)
            (def domain-dir (path-join lang-dir domain))
            (when (dir-exists? domain-dir)
              (cond
               ((equal? lang "ts")
                (let* ((sub-dirs (filter dir-exists?
                                         (map (lambda (e) (path-join domain-dir e))
                                              (list-dir-sorted domain-dir))))
                       (candidates (if (pair? sub-dirs) sub-dirs (list domain-dir))))
                  (for-each
                    (lambda (sdir)
                      (def tests (find-files sdir (lambda (_ n) (string-suffix? ".test.ts" n))))
                      (when (pair? tests)
                        (let* ((mod (if (equal? sdir domain-dir) domain (path-basename sdir)))
                               (rel-dir (rel-path repo-root sdir))
                               (script
                                (string-append "export PATH=\"$HOME/.bun/bin:$PATH\"\nbun test " (shell-quote rel-dir))))
                          (set! acc
                            (cons (make-unit (string-append "ts:" domain "/" mod)
                                             'ts "Languages" mod domain
                                             (list "ts" "lang:ts" domain (string-append "domain:" domain)
                                                   (string-append "ts:" domain) "mount:Languages"
                                                   (string-append "module:" mod))
                                             (collect-input-files repo-root (list rel-dir))
                                             #f 600 script)
                                  acc)))))
                    candidates)))

               ((equal? lang "c")
                (for-each
                  (lambda (entry)
                    (def sdir (path-join domain-dir entry))
                    (when (dir-exists? sdir)
                      (let* ((c-files
                              (map (lambda (f) (path-join sdir f))
                                   (filter (lambda (f) (string-suffix? ".c" f)) (list-dir-sorted sdir))))
                             (driver (find (lambda (f)
                                             (let ((b (path-basename f)))
                                               (or (equal? b "contrast_test.c") (equal? b "native-test.c"))))
                                           c-files))
                             (proof (find (lambda (f) (equal? (path-basename f) "proof.c")) c-files))
                             (rel-dir (rel-path repo-root sdir))
                             (inputs (collect-input-files repo-root (list rel-dir))))
                        (when driver
                          (let* ((srcs (filter (lambda (f) (not (equal? (path-basename f) "proof.c"))) c-files))
                                 (bin (path-expand (string-append ".data/test-runs/funflow-exec/c_" domain "_" entry) repo-root))
                                 (script
                                  (string-append
                                    "mkdir -p " (shell-quote (path-directory bin)) "\n"
                                    "CC=\"$(command -v clang || command -v cc || command -v gcc)\"\n"
                                    "\"$CC\" -Wall -Wextra -Werror "
                                    (str-join (map shell-quote srcs) " ")
                                    " -o " (shell-quote bin) " && " (shell-quote bin))))
                            (set! acc
                              (cons (make-unit (string-append "c:" domain "/" entry)
                                               'c "Languages" entry domain
                                               (list "c" "lang:c" domain (string-append "domain:" domain)
                                                     (string-append "c:" domain) "mount:Languages"
                                                     (string-append "module:" entry))
                                               inputs #f 120 script)
                                    acc))))
                        (when proof
                          (let* ((impls (filter (lambda (f)
                                                  (let ((b (path-basename f)))
                                                    (and (not (equal? b "proof.c"))
                                                         (not (string-prefix? "bad_" b))
                                                         (not (string-suffix? "_test.c" b))
                                                         (not (equal? b "native-test.c")))))
                                                c-files))
                                 (script
                                  (string-append
                                    "export PATH=\"/opt/homebrew/bin:/usr/local/bin:$PATH\"\n"
                                    "cbmc " (str-join (map shell-quote (append impls (list proof))) " ")
                                    " --bounds-check --pointer-check --unsigned-overflow-check")))
                            (set! acc
                              (cons (make-unit (string-append "cbmc:" domain "/" entry)
                                               'cbmc "Languages" entry domain
                                               (list "cbmc" "lang:cbmc" domain (string-append "domain:" domain)
                                                     (string-append "cbmc:" domain) "mount:Languages"
                                                     (string-append "module:" entry))
                                               inputs #f 240 script)
                                    acc)))))))
                  (list-dir-sorted domain-dir)))

               ((equal? lang "cpp")
                (for-each
                  (lambda (entry)
                    (def sdir (path-join domain-dir entry))
                    (when (dir-exists? sdir)
                      (let ((driver
                             (or (let ((p (path-join sdir "contrast_test.cpp"))) (and (regular-file? p) p))
                                 (let ((p (path-join sdir "native-test.cpp"))) (and (regular-file? p) p)))))
                        (when driver
                          (let* ((rel-dir (rel-path repo-root sdir))
                                 (bin (path-expand (string-append ".data/test-runs/funflow-exec/cpp_" domain "_" entry) repo-root))
                                 (script
                                  (string-append
                                    "mkdir -p " (shell-quote (path-directory bin)) "\n"
                                    "CXX=\"$(command -v clang++ || command -v c++ || command -v g++)\"\n"
                                    "\"$CXX\" -std=c++20 -Wall -Wextra -Werror "
                                    (shell-quote driver) " -o " (shell-quote bin) " && " (shell-quote bin))))
                            (set! acc
                              (cons (make-unit (string-append "cpp:" domain "/" entry)
                                               'cpp "Languages" entry domain
                                               (list "cpp" "lang:cpp" domain (string-append "domain:" domain)
                                                     (string-append "cpp:" domain) "mount:Languages"
                                                     (string-append "module:" entry))
                                               (collect-input-files repo-root (list rel-dir))
                                               #f 120 script)
                                    acc)))))))
                  (list-dir-sorted domain-dir)))

               ((equal? lang "rust")
                (let* ((cargo-files (find-files domain-dir (lambda (_ n) (equal? n "Cargo.toml"))))
                       (crate-dirs (dedup-sorted-strings (map (lambda (f) (strip-trailing-slash (path-normalize (path-directory f)))) cargo-files)))
                       (standalone-files
                        (find-files domain-dir
                          (lambda (full n)
                            (and (equal? n "contrast.rs")
                                 (not (ormap (lambda (cd) (string-prefix? (string-append cd "/") full)) crate-dirs)))))))
                  (for-each
                    (lambda (cdir)
                      (def rel-dir (strip-trailing-slash (rel-path repo-root cdir)))
                      (def rel-sub (strip-trailing-slash (rel-path domain-dir cdir)))
                      (def mod (path-basename cdir))
                      (def script
                        (string-append
                          "export PATH=\"$HOME/.cargo/bin:$PATH\"\n"
                          "CARGO_BIN=\"${RESOURCE_CARGO:-$(\"$HOME/.cargo/bin/rustup\" which cargo 2>/dev/null || command -v cargo)}\"\n"
                          "export PATH=\"$(dirname \"$CARGO_BIN\"):$HOME/.cargo/bin:$PATH\"\n"
                          "cd " (shell-quote cdir) "\n"
                          "\"$CARGO_BIN\" clippy --all-targets -- -D warnings\n"
                          "\"$CARGO_BIN\" test --lib -- --nocapture\n"
                          "if [[ -d tests ]]; then for tf in tests/*.rs; do [[ -f \"$tf\" ]] || continue; stem=\"$(basename \"$tf\" .rs)\"; \"$CARGO_BIN\" test --test \"$stem\" -- --nocapture --test-threads=1; done; fi\n"))
                      (set! acc
                        (cons (make-unit (string-append "rust:" domain "/" rel-sub)
                                         'rust "Languages" mod domain
                                         (list "rust" "lang:rust" domain (string-append "domain:" domain)
                                               (string-append "rust:" domain) "mount:Languages"
                                               (string-append "module:" mod))
                                         (collect-input-files repo-root (list rel-dir))
                                         rel-dir 300 script)
                              acc)))
                    crate-dirs)
                  (for-each
                    (lambda (sfile)
                      (def sdir (strip-trailing-slash (path-normalize (path-directory sfile))))
                      (def rel-dir (strip-trailing-slash (rel-path repo-root sdir)))
                      (def rel-sub (strip-trailing-slash (rel-path domain-dir sdir)))
                      (def mod (path-basename sdir))
                      (def bin (path-expand (string-append ".data/test-runs/funflow-exec/rust_" domain "_" mod) repo-root))
                      (def script
                        (string-append
                          "mkdir -p " (shell-quote (path-directory bin)) "\n"
                          "RUSTC_BIN=\"${RESOURCE_RUSTC:-$(\"$HOME/.cargo/bin/rustup\" which rustc 2>/dev/null || command -v rustc)}\"\n"
                          "\"$RUSTC_BIN\" --test " (shell-quote sfile) " -o " (shell-quote bin) " && " (shell-quote bin)))
                      (set! acc
                        (cons (make-unit (string-append "rust:" domain "/" rel-sub)
                                         'rust "Languages" mod domain
                                         (list "rust" "lang:rust" domain (string-append "domain:" domain)
                                               (string-append "rust:" domain) "mount:Languages"
                                               (string-append "module:" mod))
                                         (collect-input-files repo-root (list rel-dir))
                                         #f 180 script)
                              acc)))
                    standalone-files)))

               ((equal? lang "go")
                (for-each
                  (lambda (mf)
                    (def mdir (strip-trailing-slash (path-normalize (path-directory mf))))
                    (def rel-dir (strip-trailing-slash (rel-path repo-root mdir)))
                    (def norm-domain (strip-trailing-slash (path-normalize domain-dir)))
                    (def rel-sub (if (equal? mdir norm-domain) "" (strip-trailing-slash (rel-path norm-domain mdir))))
                    (def id-suffix (if (> (string-length rel-sub) 0) (string-append domain "/" rel-sub) domain))
                    (def mod (if (> (string-length rel-sub) 0) (path-basename mdir) domain))
                    (def inner (string-append "cd " (shell-quote mdir) " && go vet ./... && go test -race -v ./..."))
                    (def script
                      (string-append
                        "if command -v go >/dev/null 2>&1; then " inner
                        "; elif command -v devenv >/dev/null 2>&1; then devenv shell -- bash -euo pipefail -c " (shell-quote inner)
                        "; elif [[ -x \"$HOME/.nix-profile/bin/devenv\" ]]; then \"$HOME/.nix-profile/bin/devenv\" shell -- bash -euo pipefail -c " (shell-quote inner)
                        "; elif command -v nix-shell >/dev/null 2>&1; then nix-shell -p go --run " (shell-quote inner)
                        "; else echo 'go/devenv/nix-shell not found' >&2; exit 1; fi"))
                    (set! acc
                      (cons (make-unit (string-append "go:" id-suffix)
                                       'go "Languages" mod domain
                                       (list "go" "lang:go" domain (string-append "domain:" domain)
                                             (string-append "go:" domain) "mount:Languages"
                                             (string-append "module:" mod))
                                       (collect-input-files repo-root (list rel-dir))
                                       rel-dir 240 script)
                            acc)))
                  (find-files domain-dir (lambda (_ n) (equal? n "go.mod"))))))))
          (list-dir-sorted lang-dir))))
    (list-dir-sorted lang-root))
  (reverse acc))

(def (discover-lean-units repo-root)
  (def lean-root (path-expand "packages/lean-models" repo-root))
  (def src-root (path-join lean-root "DeterministicEngineering"))
  (map
    (lambda (full)
      (def rel-from-lean (rel-path lean-root full))
      (def no-ext (substring rel-from-lean 0 (- (string-length rel-from-lean) 5)))
      (def mod-name (str-join (string-split no-ext #\/) "."))
      (def parts (map string-downcase-ascii (cdr (string-split mod-name #\.))))
      (def prefix-tags
        (let loop ((i 1) (res '()))
          (if (> i (length parts))
            res
            (loop (+ i 1)
                  (cons (string-append "lean." (str-join (list-take parts i) ".")) res)))))
      (def rel-file (rel-path repo-root full))
      (def script
        (string-append
          "export PATH=\"$HOME/.elan/bin:$HOME/.bun/bin:$PATH\"\n"
          "bun t/harness/verify-framework.ts run --lang=lean --module=" (shell-quote mod-name)))
      (make-unit (string-append "lean:" mod-name)
                 'lean "Lean" mod-name "lean"
                 (append (list "lean" "lang:lean" "mount:Lean" "domain:lean" (string-append "module:" mod-name))
                         prefix-tags)
                 (collect-input-files repo-root
                   (list rel-file
                         "packages/lean-models/lakefile.toml"
                         "packages/lean-models/lakefile.lean"
                         "packages/lean-models/lean-toolchain"))
                 "packages/lean-models" 600 script))
    (find-files src-root (lambda (_ n) (string-suffix? ".lean" n)))))

(def (discover-package-units repo-root)
  (def root-pkg-path (path-expand "package.json" repo-root))
  (def acc '())
  (when (regular-file? root-pkg-path)
    (let* ((root-pkg (call-with-input-file root-pkg-path (cut read-json <> object-as-hash: #t)))
           (root-scripts (or (and (hash-table? root-pkg) (hash-get root-pkg "scripts")) (make-hash-table)))
           (pkgs-dir (path-expand "packages" repo-root)))
      (for-each
        (lambda (pkg-name)
          (def pkg-dir (path-join pkgs-dir pkg-name))
          (def pkg-json-path (path-join pkg-dir "package.json"))
          (when (regular-file? pkg-json-path)
            (let* ((pj (call-with-input-file pkg-json-path (cut read-json <> object-as-hash: #t)))
                   (scripts (and (hash-table? pj) (hash-get pj "scripts"))))
              (when (hash-table? scripts)
                (let* ((quint? (string-prefix? "quint" pkg-name))
                       (domain (if quint? "quint" pkg-name))
                       (kind (if quint? 'quint 'pkg))
                       (kind-str (symbol->string kind))
                       (rel-pkg (rel-path repo-root pkg-dir))
                       (inputs (collect-input-files repo-root (list rel-pkg "package.json"))))
                  (for-each
                    (lambda (sname)
                      (def step-alias
                        (cond
                         ((equal? sname "test:export") "export")
                         ((equal? sname "test:examples") "examples-test")
                         (else sname)))
                      (def script
                        (string-append "export PATH=\"$HOME/.bun/bin:$PATH\"\nbun run --cwd "
                                       (shell-quote rel-pkg) " " (shell-quote sname)))
                      (set! acc
                        (cons (make-unit (string-append kind-str ":" domain "/" sname)
                                         kind "Packages" pkg-name domain
                                         (list kind-str (string-append "lang:" kind-str)
                                               domain (string-append "domain:" domain)
                                               (string-append kind-str ":" domain)
                                               "mount:Packages" (string-append "module:" pkg-name)
                                               (string-append "step:" sname) (string-append "step:" step-alias)
                                               sname step-alias)
                                         inputs rel-pkg 300 script)
                              acc)))
                    (sort-strings (hash-keys scripts))))))))
        (list-dir-sorted pkgs-dir))

      ;; Root package.json example:* and fleet:*/mbt:* scripts discovered dynamically.
      (for-each
        (lambda (sname)
          (cond
           ((string-prefix? "example:" sname)
            (let* ((owner "render")
                   (rel-owner (string-append "packages/" owner))
                   (script (string-append "export PATH=\"$HOME/.bun/bin:$PATH\"\nbun run " (shell-quote sname))))
              (set! acc
                (cons (make-unit (string-append "pkg:" owner "/" sname)
                                 'pkg "Packages" owner owner
                                 (list "pkg" "lang:pkg" owner (string-append "domain:" owner)
                                       (string-append "pkg:" owner) "mount:Packages"
                                       (string-append "module:" owner)
                                       "step:examples" "examples"
                                       (string-append "step:" sname) sname)
                                 (collect-input-files repo-root (list rel-owner "package.json"))
                                 rel-owner 180 script)
                      acc))))
           ((or (string-prefix? "fleet:" sname) (string-prefix? "mbt:" sname))
            (let* ((parts (string-split sname #\:))
                   (verb (car parts))
                   (target (cadr parts))
                   (kind (if (equal? target "quint") 'quint 'pkg))
                   (kind-str (symbol->string kind))
                   (script (string-append "export PATH=\"$HOME/.bun/bin:$PATH\"\nbun run " (shell-quote sname))))
              (set! acc
                (cons (make-unit (string-append kind-str ":" target "/" verb)
                                 kind "Packages" sname target
                                 (list kind-str (string-append "lang:" kind-str)
                                       target (string-append "domain:" target)
                                       (string-append kind-str ":" target)
                                       "mount:Packages" (string-append "step:" verb) verb sname)
                                 (collect-input-files repo-root
                                   '("packages/quint-models" "packages/quint-modules-resolver" "package.json"))
                                 (string-append "root:" target) 600 script)
                      acc))))))
        (sort-strings (hash-keys root-scripts)))))
  (reverse acc))

(def (discover-all-units repo-root)
  (append (discover-yuanxu-units repo-root)
          (discover-polyglot-units repo-root)
          (discover-lean-units repo-root)
          (discover-package-units repo-root)))

;; ── 4. Composable Query Algebra & O(Delta) Change-Impact Slicing ──

(def (git-changed-files repo-root)
  (def (lines-of cmd)
    (with-catch
      (lambda (_) '())
      (lambda ()
        (filter (lambda (s) (> (string-length s) 0))
                (map (lambda (s) (strip-dot-slash (str-trim s)))
                     (string-split (run-process cmd directory: repo-root) #\newline))))))
  (dedup-sorted-strings
    (append (lines-of '("git" "diff" "--name-only" "HEAD"))
            (lines-of '("git" "ls-files" "--others" "--exclude-standard")))))

(def (unit-matches-token? u tok)
  (or (equal? (symbol->string (.get u kind)) tok)
      (equal? (.get u domain) tok)
      (equal? (.get u mount) tok)
      (equal? (.get u module) tok)
      (equal? (.get u id) tok)
      (and (member tok (.get u tags)) #t)
      (and (member (string-append "step:" tok) (.get u tags)) #t)
      (and (member (string-append "lang:" tok) (.get u tags)) #t)))

(def (filter-units repo-root units opts)
  (def changed-files
    (if (.get opts impact?)
      (let ((explicit (.get opts changed-files)))
        (if (pair? explicit) explicit (git-changed-files repo-root)))
      #f))
  (def changed-tbl (make-hash-table))
  (when changed-files
    (for-each (lambda (p) (hash-put! changed-tbl p #t)) changed-files))

  (def matched
    (filter
      (lambda (u)
        (and (or (.get opts include-external?) (not (member "requires:env" (.get u tags))))
             (or (null? (.get opts mounts)) (and (member (.get u mount) (.get opts mounts)) #t))
             (or (null? (.get opts langs)) (and (member (symbol->string (.get u kind)) (.get opts langs)) #t))
             (or (null? (.get opts domains)) (and (member (.get u domain) (.get opts domains)) #t))
             (or (null? (.get opts modules)) (and (member (.get u module) (.get opts modules)) #t))
             (andmap (lambda (group) (ormap (lambda (t) (unit-matches-token? u t)) group))
                     (.get opts tag-groups))
             (andmap (lambda (t) (unit-matches-token? u t)) (.get opts all-tags))
             (or (null? (.get opts only)) (ormap (lambda (t) (unit-matches-token? u t)) (.get opts only)))
             (not (ormap (lambda (t) (unit-matches-token? u t)) (.get opts skip)))
             (or (not changed-files)
                 (ormap (lambda (inp) (hash-key? changed-tbl inp)) (.get u inputs)))))
      units))
  (def lim (.get opts limit))
  (if (and lim (>= lim 0) (< lim (length matched)))
    (list-take matched lim)
    matched))

;; ── 5. Race-Free Parallel Frontier Execution & Fun-Flow DAG Compilation ──

(def (exec-bash-captured cwd script (timeout-sec 300))
  ;; Hardened race-free subprocess runner (SM3 bounded timeout + pipe-detachment):
  ;; 1. Child-local `cd` keeps concurrent Gambit green-thread subprocess spawns 100% race-free.
  ;; 2. `</dev/null` + closed stdin prevents non-interactive TTY stalls.
  ;; 3. Output captured to an isolated regular temp file so background child daemons
  ;;    (e.g. Apalache/Bun/Lake workers) can never hold the Gambit pipe open past exit.
  ;; 4. Bounded wall-clock `timeout` prevents any runaway verification unit from hanging a wave.
  (def full-script
    (string-append
      "export PATH=\"$HOME/.bun/bin:$HOME/.elan/bin:$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH\"\n"
      "cd " (shell-quote cwd) "\n"
      script))
  (def wrapper
    (string-append
      "tmp_log=\"$(mktemp)\"\n"
      "trap 'rm -f \"$tmp_log\"' EXIT\n"
      "set +e\n"
      "if command -v timeout >/dev/null 2>&1; then\n"
      "  timeout --foreground --signal=TERM --kill-after=5s "
      (number->string timeout-sec) "s bash -euo pipefail -c "
      (shell-quote full-script) " </dev/null >\"$tmp_log\" 2>&1\n"
      "else\n"
      "  bash -euo pipefail -c " (shell-quote full-script) " </dev/null >\"$tmp_log\" 2>&1\n"
      "fi\n"
      "rc=$?\n"
      "cat \"$tmp_log\"\n"
      "exit $rc\n"))
  (def proc
    (open-process
      (list path: "/bin/bash"
            arguments: (list "-c" wrapper)
            stdin-redirection: #t
            stdout-redirection: #t
            stderr-redirection: #t)))
  (close-output-port proc)
  (def output (read-all-as-string proc))
  (def raw-status (process-status proc))
  (close-port proc)
  (def exit-code
    (if (= (bitwise-and raw-status #x7f) 0)
      (arithmetic-shift raw-status -8)
      (+ 128 (bitwise-and raw-status #x7f))))
  (values exit-code output))

(def (last-nonempty-line text fallback)
  (def lines
    (filter (lambda (ln) (> (string-length (str-trim ln)) 0))
            (string-split text #\newline)))
  (if (pair? lines) (car (reverse lines)) fallback))

(def (partition-conflict-free-waves units max-jobs)
  (let loop ((remaining units) (waves '()))
    (if (null? remaining)
      (reverse waves)
      (let ((used (make-hash-table)))
        (let pick ((rest remaining) (wave '()) (deferred '()))
          (if (null? rest)
            (loop (reverse deferred) (cons (reverse wave) waves))
            (let* ((u (car rest))
                   (ck (.get u conflict-key))
                   (conflict? (and ck (hash-key? used ck))))
              (if (and (not conflict?) (< (length wave) max-jobs))
                (begin
                  (when ck (hash-put! used ck #t))
                  (pick (cdr rest) (cons u wave) deferred))
                (pick (cdr rest) wave (cons u deferred))))))))))

(def FlowLedgerContract
  (.cc Type. sexp: 'FunflowVerificationLedger
    '.element? list?))

;; O(N) linear Fun-Flow DAG compilation: every adjacent edge matches by pointer `eq?`
;; (FlowLedgerContract -> AdapterResult -> FlowLedgerContract), scaling to 10,000+ units.
(def (compile-units->funflow flow-name units)
  (def steps '())
  (for-each
    (lambda (u)
      (def uid (.get u id))
      (def usym (string->symbol uid))
      (def admit-sym (string->symbol (string-append uid "::admit")))
      (def ext-task
        (make-external-task usym 'exec-verification-unit (list 'unit uid)
                            (Fun AdapterResult <- FlowLedgerContract)))
      (def admit-task
        (make-pure-task admit-sym (Fun FlowLedgerContract <- AdapterResult)
                        (lambda (res)
                          (list (list uid (adapter-result-status res) (adapter-result-value res))))))
      (set! steps (cons admit-task (cons ext-task steps))))
    units)
  (flow-compose flow-name (reverse steps) (Fun FlowLedgerContract <- FlowLedgerContract)))

(def (load-exec-cache repo-root cache-dir)
  (def tbl (make-hash-table))
  (when cache-dir
    (let ((cfile (path-expand "funflow-exec-cache.v1.json" (path-expand cache-dir repo-root))))
      (when (regular-file? cfile)
        (with-catch
          (lambda (_) (void))
          (lambda ()
            (let* ((doc (call-with-input-file cfile (cut read-json <> object-as-hash: #t)))
                   (entries (and (hash-table? doc) (hash-get doc "entries"))))
              (when (hash-table? entries)
                (hash-for-each (lambda (k v) (hash-put! tbl k v)) entries))))))))
  tbl)

(def (save-exec-cache! repo-root cache-dir cache-tbl)
  (when cache-dir
    (let* ((abs-dir (path-expand cache-dir repo-root))
           (cfile (path-expand "funflow-exec-cache.v1.json" abs-dir)))
      (create-directory* abs-dir)
      (call-with-output-file cfile
        (lambda (port)
          (write-json port
                      (hash ("schema" "deterministic-engineering.funflow-exec-cache.v1")
                            ("entries" cache-tbl)))
          (newline port))))))

;; ── 6. Inventory, CLI Parser & Main Execution Loop ──

(def (print-inventory units)
  (def by-mount (make-hash-table))
  (def by-kind (make-hash-table))
  (def by-domain (make-hash-table))
  (def (inc! tbl k) (hash-put! tbl k (+ 1 (or (hash-get tbl k) 0))))
  (for-each
    (lambda (u)
      (inc! by-mount (.get u mount))
      (inc! by-kind (symbol->string (.get u kind)))
      (inc! by-domain (.get u domain)))
    units)
  (displayln "=== Deterministic Engineering Yuanxu + Fun-Flow Verification Graph (" (length units) " units) ===")
  (displayln "\nBy Mount (discovered from init.ss + filesystem grammar):")
  (for-each (lambda (k) (displayln "  " k " : " (hash-get by-mount k)))
            (sort-strings (hash-keys by-mount)))
  (displayln "\nBy Language / Kind:")
  (for-each (lambda (k) (displayln "  " k " : " (hash-get by-kind k)))
            (sort-strings (hash-keys by-kind)))
  (displayln "\nBy Domain:")
  (for-each (lambda (k) (displayln "  " k " : " (hash-get by-domain k)))
            (sort-strings (hash-keys by-domain))))

(def (parse-cli-args args)
  (def list-only? #f)
  (def plan-only? #f)
  (def impact? #f)
  (def include-external? #f)
  (def tag-groups '())
  (def all-tags '())
  (def mounts '())
  (def langs '())
  (def domains '())
  (def modules '())
  (def only '())
  (def skip '())
  (def changed-files '())
  (def cache-dir #f)
  (def report-path #f)
  (def jobs 1)
  (def limit #f)
  (for-each
    (lambda (a)
      (cond
       ((or (equal? a "--list") (equal? a "list")) (set! list-only? #t))
       ((equal? a "--plan") (set! plan-only? #t))
       ((equal? a "--impact") (set! impact? #t))
       ((equal? a "--include-external") (set! include-external? #t))
       ((string-prefix? "--tag=" a)
        (set! tag-groups (cons (split-csv (substring a 6 (string-length a))) tag-groups)))
       ((string-prefix? "--all-tags=" a)
        (set! all-tags (append all-tags (split-csv (substring a 11 (string-length a))))))
       ((string-prefix? "--mount=" a)
        (set! mounts (append mounts (split-csv (substring a 8 (string-length a))))))
       ((string-prefix? "--lang=" a)
        (set! langs (append langs (split-csv (substring a 7 (string-length a))))))
       ((string-prefix? "--domain=" a)
        (set! domains (append domains (split-csv (substring a 9 (string-length a))))))
       ((string-prefix? "--module=" a)
        (set! modules (append modules (split-csv (substring a 9 (string-length a))))))
       ((string-prefix? "--only=" a)
        (set! only (append only (split-csv (substring a 7 (string-length a))))))
       ((string-prefix? "--skip=" a)
        (set! skip (append skip (split-csv (substring a 7 (string-length a))))))
       ((string-prefix? "--changed=" a)
        (set! impact? #t)
        (set! changed-files
          (append changed-files
                  (map strip-dot-slash (split-csv (substring a 10 (string-length a)))))))
       ((string-prefix? "--cache=" a)
        (set! cache-dir (substring a 8 (string-length a))))
       ((string-prefix? "--report=" a)
        (set! report-path (substring a 9 (string-length a))))
       ((string-prefix? "--jobs=" a)
        (let ((n (string->number (substring a 7 (string-length a)))))
          (when (and (exact-integer? n) (> n 0)) (set! jobs n))))
       ((string-prefix? "--limit=" a)
        (let ((n (string->number (substring a 8 (string-length a)))))
          (when (and (exact-integer? n) (>= n 0)) (set! limit n))))))
    args)
  (.o bind-these: #f
      list-only?: list-only?
      plan-only?: plan-only?
      impact?: impact?
      include-external?: include-external?
      tag-groups: (reverse tag-groups)
      all-tags: all-tags
      mounts: mounts
      langs: langs
      domains: domains
      modules: modules
      only: only
      skip: skip
      changed-files: changed-files
      cache-dir: cache-dir
      report-path: report-path
      jobs: jobs
      limit: limit))

(def (run-funflow-cli repo-root args)
  (def t0 (real-time))
  (def opts (parse-cli-args args))
  (def all-units (discover-all-units repo-root))

  (when (.get opts list-only?)
    (print-inventory all-units)
    (exit 0))

  (def selected (filter-units repo-root all-units opts))
  (when (null? selected)
    (if (.get opts impact?)
      (begin
        (displayln "FUNFLOW-IMPACT-OK affected=0 total=" (length all-units))
        (exit 0))
      (error "Fun-Flow query matched 0 verification units" args)))

  (def cache-dir (.get opts cache-dir))
  (def cache-tbl (load-exec-cache repo-root cache-dir))
  (def digests (make-hash-table))
  (def cached-units '())
  (def pending-units '())

  (for-each
    (lambda (u)
      (def uid (.get u id))
      (def dig (sha256-of-unit repo-root u))
      (hash-put! digests uid dig)
      (def hit (and cache-dir (hash-get cache-tbl uid)))
      (if (and (hash-table? hit) (equal? (hash-get hit "digest") dig))
        (set! cached-units (cons u cached-units))
        (set! pending-units (cons u pending-units))))
    selected)
  (set! cached-units (reverse cached-units))
  (set! pending-units (reverse pending-units))

  ;; Compile real Fun-Flow DAG & Execution Plan (upstream Fun-Flow control plane).
  (def dag-flow (compile-units->funflow 'de-verification-flow selected))
  (def dag-manifest (flow->dag-runtime-manifest dag-flow "funflow-exec-req"))
  (def strategy
    (if cache-dir (make-cached-local-eager-strategy) (make-local-eager-strategy)))
  (def waves (partition-conflict-free-waves pending-units (.get opts jobs)))

  (when (.get opts plan-only?)
    (let ()
      (def plan-runner
        (make-runner strategy
          (make-runtime-adapter 'de-funflow-planner '(external)
            (lambda (req) (make-adapter-result (list 'plan (execution-request-name req)) 'ok 'planned #f #f))
            (lambda (rid) (make-adapter-result rid 'ok #f #f #f))
            (lambda (req) (make-adapter-result (list 'put (execution-request-name req)) 'ok #f #f #f))
            (lambda (h) (make-adapter-result (list 'get h) 'ok #f h #f)))))
      (def plan (runner-plan plan-runner dag-flow))
      (def dt-ms (inexact->exact (round (* 1000.0 (- (real-time) t0)))))
      (displayln "=== Fun-Flow DAG Plan (schema=" (cdr (assoc 'schema dag-manifest))
                 " nodes=" (length (execution-plan-node-ids plan))
                 " selected=" (length selected) "/" (length all-units)
                 " cached=" (length cached-units)
                 " pending=" (length pending-units)
                 " waves=" (length waves)
                 " jobs=" (.get opts jobs) ") ===")
      (for-each
        (lambda (u)
          (displayln "  [CACHE-HIT] " (.get u id) " (" (substring (hash-get digests (.get u id)) 0 12) ")"))
        cached-units)
      (let loop ((ws waves) (idx 1))
        (unless (null? ws)
          (displayln "  [WAVE " idx "] (" (length (car ws)) " units): "
                     (str-join (map (lambda (u) (.get u id)) (car ws)) ", "))
          (loop (cdr ws) (+ idx 1))))
      (displayln "FUNFLOW-PLAN-OK (" dt-ms "ms)")
      (exit 0)))

  ;; Execute pending waves concurrently across Gambit green threads (conflict-free).
  (def precomputed (make-hash-table))
  (def any-failed? #f)
  (for-each
    (lambda (wave)
      (unless any-failed?
        (let ()
          (def (run-one u)
            (def uid (.get u id))
            (def ut0 (real-time))
            (displayln "▶ [funflow] " uid)
            (let-values (((code out) (exec-bash-captured repo-root (.get u script) (.get u timeout-sec))))
              (def dt (inexact->exact (round (* 1000.0 (- (real-time) ut0)))))
              (def ok? (= code 0))
              (def summary (last-nonempty-line out (if ok? "OK" (string-append "exit " (number->string code)))))
              (unless ok?
                (displayln "✗ [funflow] FAILED " uid " (exit=" code ", " dt "ms):\n" out))
              (list uid ok? code dt summary)))
          (def results
            (if (> (length wave) 1)
              (let ((threads (map (lambda (u) (spawn run-one u)) wave)))
                (map thread-join! threads))
              (map run-one wave)))
          (for-each
            (lambda (r)
              (hash-put! precomputed (car r) r)
              (unless (cadr r) (set! any-failed? #t)))
            results))))
    waves)

  ;; Drive the compiled Fun-Flow DAG through upstream `make-runner` / `runner-run`
  ;; and validate topological + frontier integrity via `validate-replay-report`.
  (def executed-ids '())
  (def cached-ids '())
  (def failed-ids '())
  (def outcome-hashes '())

  (def adapter
    (make-runtime-adapter 'de-funflow-exec '(external)
      (lambda (request)
        (def uid (symbol->string (execution-request-name request)))
        (def dig (or (hash-get digests uid) ""))
        (def pre (hash-get precomputed uid))
        (def cached-hit (and (not pre) cache-dir (hash-get cache-tbl uid)))
        (cond
         (cached-hit
          (set! cached-ids (cons uid cached-ids))
          (let ((detail (or (hash-get cached-hit "detail") "cached pass")))
            (set! outcome-hashes
              (cons (hash ("id" uid) ("status" "cached") ("digest" dig) ("durationMs" 0) ("detail" detail))
                    outcome-hashes))
            (make-adapter-result
              (list 'funflow-exec uid 'cache-hit)
              'ok
              (list 'cached uid dig detail)
              (list 'funflow-artifact (execution-request-plan-id request) (execution-request-node-id request))
              #f)))
         (pre
          (let ((ok? (cadr pre))
                (dt (cadddr pre))
                (summary (car (cddddr pre))))
            (if ok?
              (begin
                (set! executed-ids (cons uid executed-ids))
                (when cache-dir
                  (hash-put! cache-tbl uid (hash ("digest" dig) ("detail" summary)))))
              (set! failed-ids (cons uid failed-ids)))
            (set! outcome-hashes
              (cons (hash ("id" uid) ("status" (if ok? "pass" "fail")) ("digest" dig)
                          ("durationMs" dt) ("detail" summary))
                    outcome-hashes))
            (make-adapter-result
              (list 'funflow-exec uid 'executed)
              (if ok? 'ok 'failed)
              (list (if ok? 'pass 'fail) uid dig summary)
              (list 'funflow-artifact (execution-request-plan-id request) (execution-request-node-id request))
              (if ok? #f summary))))
         (else
          (set! failed-ids (cons uid failed-ids))
          (make-adapter-result
            (list 'funflow-exec uid 'skipped-after-failure)
            'failed
            (list 'skipped uid dig "aborted by fail-fast wave")
            #f
            "aborted by fail-fast wave"))))
      (lambda (rid) (make-adapter-result rid 'ok #f #f #f))
      (lambda (req) (make-adapter-result (list 'store-put (execution-request-name req)) 'ok #f #f #f))
      (lambda (h) (make-adapter-result (list 'store-get h) 'ok #f h #f))))

  (def runner (make-runner strategy adapter))
  (def plan (runner-plan runner dag-flow))
  (def run-res (runner-run runner dag-flow '()))
  (def root-receipt (run-result-receipt run-res))
  (def replay-rep (validate-replay-report plan root-receipt))
  (def replay-valid? (replay-report-valid? replay-rep))

  (when (and cache-dir (null? failed-ids))
    (save-exec-cache! repo-root cache-dir cache-tbl))

  (def wall-ms (inexact->exact (round (* 1000.0 (- (real-time) t0)))))
  (when (.get opts report-path)
    (let ((abs-rep (path-expand (.get opts report-path) repo-root)))
      (create-directory* (path-directory abs-rep))
      (call-with-output-file abs-rep
        (lambda (port)
          (write-json port
            (hash ("schema" "deterministic-engineering.funflow-exec-report.v1")
                  ("funflowManifestSchema" (symbol->string (cdr (assoc 'schema dag-manifest))))
                  ("planNodeCount" (length (execution-plan-node-ids plan)))
                  ("replayValid" replay-valid?)
                  ("replayStatus" (symbol->string (replay-report-status replay-rep)))
                  ("totalDiscovered" (length all-units))
                  ("selectedCount" (length selected))
                  ("executedCount" (length executed-ids))
                  ("cachedCount" (length cached-ids))
                  ("failedCount" (length failed-ids))
                  ("waveCount" (length waves))
                  ("durationMs" wall-ms)
                  ("outcomes" (reverse outcome-hashes))))
          (newline port)))))

  (unless (and (null? failed-ids) replay-valid?)
    (displayln "✗ FUNFLOW-EXEC-FAILED failed=" (length failed-ids)
               " replayStatus=" (replay-report-status replay-rep)
               " reasons=" (replay-report-reasons replay-rep))
    (exit 1))

  (displayln "✓ FUNFLOW-EXEC-OK selected=" (length selected)
             " executed=" (length executed-ids)
             " cached=" (length cached-ids)
             " waves=" (length waves)
             " planNodes=" (length (execution-plan-node-ids plan))
             " replayValid=" replay-valid?
             " (" wall-ms "ms)"))

(def (main . args)
  (run-funflow-cli (repo-root-dir) args))

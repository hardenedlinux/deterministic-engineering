;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Loader-owned qualification tests for library/defense-profiles (G3/G4 / 10.153):
;;; verifies Yuanxu Design 165 by-tag scoped defense profiles and Band-5 monotonic floors
;;; over defense leaves without global over-blocking.
(import :std/test
        :std/source
        :std/list/list
        :clan/poo/object
        (only-in :clan/poo/type validate)
        (only-in :tao3k/yuanxu/module-system/convergence/types
                 make-global-profile by-tag)
        :deterministic-engineering/library/defense-profiles/types
        :deterministic-engineering/library/defense-profiles/objects
        :deterministic-engineering/library/defense-profiles/interface)
(export defense-profiles-convergence-test)

(def repo-root
  (path-normalize (path-expand "../../../.." (path-directory (this-source-file)))))

(def (plist-ref-form xs key)
  (let loop ((rest xs))
    (cond
     ((or (null? rest) (null? (cdr rest))) #f)
     ((eq? (car rest) key) (cadr rest))
     (else (loop (cddr rest))))))

(def (extract-quint-interface-meta path)
  (def forms
    (call-with-input-file path
      (lambda (port)
        (let loop ((acc '()))
          (let ((datum (read port)))
            (if (eof-object? datum) (reverse acc) (loop (cons datum acc))))))))
  (let loop ((fs forms))
    (cond
     ((null? fs) (error "missing .def in quint interface.ss" path))
     ((and (pair? (car fs)) (eq? (caar fs) '.def))
      (let* ((plist (cddar fs))
             (id-form (plist-ref-form plist 'identity:))
             (tags-form (plist-ref-form plist 'tags:))
             (id (if (and (pair? id-form) (eq? (car id-form) 'quote)) (cadr id-form) id-form))
             (tags (if (and (pair? tags-form) (eq? (car tags-form) 'quote)) (cadr tags-form) '())))
        (cons id tags)))
     (else (loop (cdr fs))))))

(def (collect-live-quint-fleet-meta)
  (def models-root (path-expand "packages/quint-models" repo-root))
  (def results '())
  (for-each
    (lambda (domain)
      (def dpath (path-expand domain models-root))
      (when (and (not (string-prefix? "." domain)) (file-exists? dpath) (eq? (file-type dpath) 'directory))
        (for-each
          (lambda (subdomain)
            (def spath (path-expand subdomain dpath))
            (when (and (not (string-prefix? "." subdomain)) (file-exists? spath) (eq? (file-type spath) 'directory))
              (for-each
                (lambda (model)
                  (def mpath (path-expand model spath))
                  (def iface (path-expand "interface.ss" mpath))
                  (when (and (not (string-prefix? "." model))
                             (file-exists? iface))
                    (let ((meta (extract-quint-interface-meta iface)))
                      ;; Only include models carrying defense.mutability.* (canonical fleet)
                      (when (ormap (lambda (t) (memq t '(defense.mutability.immutable
                                                         defense.mutability.negative-domain
                                                         defense.mutability.mutable-root)))
                                   (cdr meta))
                        (set! results (cons meta results))))))
                (directory-files spath))))
          (directory-files dpath))))
    (directory-files models-root))
  (reverse results))

(def (make-synthetic-defense-graph global-profile-ids)
  (def (make-leaf leaf-id leaf-tags leaf-floor)
    (.o kind: 'module-core
        identity: leaf-id
        publication:
        (.o identity: leaf-id
            tags: leaf-tags
            slot-specs: DefenseSlotSpecs
            defaults: DefenseDefaultSlots
            governance-floor: leaf-floor
            core: (.o exports: (.o)))))
  (.o nodes:
      (list
        (make-leaf 'leaf/immutable-epistemic
          '(defense.mutability.immutable defense.property.guard-declared)
          DefenseGovernanceFloor)
        (make-leaf 'leaf/negative-revalidation
          '(defense.mutability.negative-domain defense.property.guard-declared)
          DefenseGovernanceFloor)
        (make-leaf 'leaf/mutable-effect
          '(defense.mutability.mutable-root defense.property.guard-declared)
          DefenseGovernanceFloor))
      module-order: '(leaf/immutable-epistemic leaf/negative-revalidation leaf/mutable-effect)
      global-profiles: global-profile-ids
      module-profiles: '()))

(def defense-profiles-convergence-test
  (test-suite "defense-profiles G3/G4 scoped by-tag convergence and Band-5 monotonic floors"
    (test-case "by-tag profiles apply scoped defenses by M1/M2/M3 mutability without global over-blocking"
      (validate DefenseProfilesScopeType (.get DefenseProfilesModule core exports))
      (def graph
        (make-synthetic-defense-graph
          '(defense.mutable-root-floor
            defense.negative-domain-floor
            defense.immutable-sufficiency
            defense.guard-necessity-floor)))
      (def res (converge-defense-graph graph))
      (check-equal? (.ref res 'status) 'ready)
      (def eff (.ref res 'effective-configs))
      ;; M1 immutable leaf: sufficiency stopping enabled, NO unnecessary use-time witness or negative-manifest overhead:
      (def m1 (.ref eff 'leaf/immutable-epistemic))
      (check-equal? (.ref m1 'allow-sufficiency-stop?) #t)
      (check-equal? (.ref m1 'require-use-time-witness?) #f)
      (check-equal? (.ref m1 'require-guard-necessity-countermodel?) #t)
      (check-equal? (.ref m1 'require-admission-five-tuple?) #t)
      ;; M2 negative-domain leaf: global purge strictly forbidden (#f) + dependency manifest required (#t):
      (def m2 (.ref eff 'leaf/negative-revalidation))
      (check-equal? (.ref m2 'allow-global-purge?) #f)
      (check-equal? (.ref m2 'require-dependency-manifest?) #t)
      (check-equal? (.ref m2 'require-use-time-witness?) #f)
      ;; M3 mutable-root leaf: consumption-time authority witness required (#t), sufficiency stop disabled (#f):
      (def m3 (.ref eff 'leaf/mutable-effect))
      (check-equal? (.ref m3 'require-use-time-witness?) #t)
      (check-equal? (.ref m3 'allow-sufficiency-stop?) #f))

    (test-case "Band-5 monotonic meet blocks hostile weakening of guard/purge floors and runtime overlay switches tier cold"
      (def graph
        (make-synthetic-defense-graph
          '(defense.mutable-root-floor
            defense.negative-domain-floor
            defense.guard-necessity-floor
            hostile.weaken-all)))
      (def hostile-reg
        (object<-alist
          (list
            (cons 'defense.mutable-root-floor (.get DefenseProfiles mutable-root-floor))
            (cons 'defense.negative-domain-floor (.get DefenseProfiles negative-domain-floor))
            (cons 'defense.guard-necessity-floor (.get DefenseProfiles guard-necessity-floor))
            (cons 'hostile.weaken-all
                  (make-global-profile 'hostile.weaken-all
                    (list (by-tag 'defense.property.guard-declared))
                    (.o require-use-time-witness?: #f
                        allow-global-purge?: #t
                        require-guard-necessity-countermodel?: #f
                        require-admission-five-tuple?: #f))))))
      (def res (converge-defense-graph graph hostile-reg))
      (check-equal? (.ref res 'status) 'ready)
      (def eff (.ref res 'effective-configs))
      ;; Monotonic meet preserves every strengthened floor against hostile weakening:
      (check-equal? (.ref (.ref eff 'leaf/mutable-effect) 'require-use-time-witness?) #t)
      (check-equal? (.ref (.ref eff 'leaf/negative-revalidation) 'allow-global-purge?) #f)
      (check-equal? (.ref (.ref eff 'leaf/immutable-epistemic) 'require-guard-necessity-countermodel?) #t)
      (check-equal? (.ref (.ref eff 'leaf/immutable-epistemic) 'require-admission-five-tuple?) #t)
      ;; Runtime overlay switches stage:'runtime review-tier cold and rejects stage:'assembly mutation:
      (def rt-ok
        (apply-defense-runtime-profile graph res
          (list (cons 'leaf/mutable-effect (.o review-tier: 'semantic-review)))))
      (check-equal? (.ref rt-ok 'status) 'ready)
      (check-equal? (.ref (.ref (.ref rt-ok 'effective-configs) 'leaf/mutable-effect) 'review-tier)
                    'semantic-review)
      (def rt-bad
        (apply-defense-runtime-profile graph res
          (list (cons 'leaf/mutable-effect (.o require-use-time-witness?: #f)))))
      (check-equal? (.ref rt-bad 'status) 'rejected))

    (test-case "E1 live Quint fleet (48 canonical models) converges by-tag across M1/M2/M3 with zero over-blocking"
      (def fleet-meta (collect-live-quint-fleet-meta))
      (check-equal? (>= (length fleet-meta) 48) #t)
      (def m1-count 0)
      (def m2-count 0)
      (def m3-count 0)
      (def fleet-nodes
        (map (lambda (entry)
               (let* ((leaf-id (car entry))
                      (leaf-tags (cdr entry))
                      (mut-tags (filter (lambda (t)
                                          (memq t '(defense.mutability.immutable
                                                    defense.mutability.negative-domain
                                                    defense.mutability.mutable-root)))
                                        leaf-tags)))
                 ;; Every model must declare exactly ONE mutability class (M1/M2/M3)
                 (check-equal? (length mut-tags) 1)
                 (cond
                  ((eq? (car mut-tags) 'defense.mutability.immutable) (set! m1-count (+ m1-count 1)))
                  ((eq? (car mut-tags) 'defense.mutability.negative-domain) (set! m2-count (+ m2-count 1)))
                  ((eq? (car mut-tags) 'defense.mutability.mutable-root) (set! m3-count (+ m3-count 1))))
                 (.o kind: 'module-core
                     identity: leaf-id
                     publication:
                     (.o identity: leaf-id
                         tags: leaf-tags
                         slot-specs: DefenseSlotSpecs
                         defaults: DefenseDefaultSlots
                         governance-floor: DefenseGovernanceFloor
                         core: (.o exports: (.o))))))
             fleet-meta))
      (check-equal? (> m1-count 0) #t)
      (check-equal? (> m2-count 0) #t)
      (check-equal? (> m3-count 0) #t)
      (def fleet-graph
        (.o nodes: fleet-nodes
            module-order: (map car fleet-meta)
            global-profiles:
            '(defense.mutable-root-floor
              defense.negative-domain-floor
              defense.immutable-sufficiency
              defense.guard-necessity-floor)
            module-profiles: '()))
      (def fleet-res (converge-defense-graph fleet-graph))
      (check-equal? (.ref fleet-res 'status) 'ready)
      (def eff (.ref fleet-res 'effective-configs))
      (for-each
        (lambda (entry)
          (let* ((id (car entry))
                 (tags (cdr entry))
                 (cfg (.ref eff id)))
            (cond
             ((memq 'defense.mutability.immutable tags)
              (check-equal? (.ref cfg 'allow-sufficiency-stop?) #t)
              (check-equal? (.ref cfg 'require-use-time-witness?) #f))
             ((memq 'defense.mutability.negative-domain tags)
              (check-equal? (.ref cfg 'allow-global-purge?) #f)
              (check-equal? (.ref cfg 'require-dependency-manifest?) #t)
              (check-equal? (.ref cfg 'require-use-time-witness?) #f))
             ((memq 'defense.mutability.mutable-root tags)
              (check-equal? (.ref cfg 'require-use-time-witness?) #t)
              (check-equal? (.ref cfg 'allow-sufficiency-stop?) #f)))
            (when (memq 'defense.property.guard-declared tags)
              (check-equal? (.ref cfg 'require-guard-necessity-countermodel?) #t)
              (check-equal? (.ref cfg 'require-admission-five-tuple?) #t))))
        fleet-meta))))

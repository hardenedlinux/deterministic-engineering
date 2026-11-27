;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; L1 verification for 10.150 / 10.152:
;;; Current repository debt D1-D6 must each be reported by OR01-OR06;
;;; a repaired tree with rendered placements must produce zero findings.
(import
  :std/test
        (only-in "../../../support/repo-paths.ss" resolve-repo-root)
        (only-in :tao3k/yuanxu/testing yuanxu-test-case)
  :std/source
  :clan/poo/object
  (only-in :clan/poo/type validate)
  "../../../../library/project-organization/types.ss"
  "../../../../library/project-organization/objects.ss"
  "../../../../library/project-formation/func.ss"
  "../../../../library/library-formation-profiles/objects.ss"
  "../../../support/repository-organization-facts.ss")
(export repository-organization-test)

(def repo-root (resolve-repo-root))
(def (rows r name) ((.ref r 'rows-of) name))
(def (has-finding? findings rule subject-substr)
  (and (find (lambda (row)
               (and (equal? (car row) rule)
                    (string-contains (cadr row) subject-substr)))
             findings)
       #t))

(def (replace-fact alist key new-rows)
  (map (lambda (entry) (if (eq? (car entry) key) (cons key new-rows) entry)) alist))

(def (clean-baseline-facts rendered-sysml)
  (def placements (.get ProjectOrganization placements))
  (def rendered (map list (extract-rendered-placements rendered-sysml (map car placements))))
  (list
    (cons 'declared_placement (map (lambda (r) (list (car r) (cadr r))) placements))
    (cons 'declared_placement_role (.get ProjectOrganization placement-roles))
    (cons 'required_role (map (lambda (r) (list (car r))) (.get ProjectOrganization roles)))
    (cons 'declared_package_family
          (map (lambda (r) (list (car r) (cadr r))) (.get ProjectOrganization package-families)))
    (cons 'declared_package_dir
          (map (lambda (r) (list (car r) (caddr r))) (.get ProjectOrganization package-families)))
    (cons 'managed_path '(("library") ("languages-engineering") ("packages") ("projects")
                          ("examples") ("t") ("docs") ("gerbil.pkg") ("init.ss") ("build.ss")
                          ("types.ss") ("config.ss") ("Justfile") ("package.json")))
    (cons 'path_placement '(("library" "SchemeModule")
                            ("languages-engineering" "LanguageAssets")
                            ("packages" "DistributionPackage")
                            ("projects" "ProjectEntry")
                            ("examples" "UserExample")
                            ("t" "DevelopmentVerification")
                            ("docs" "DocumentItem")
                            ("gerbil.pkg" "PackageInfrastructure")
                            ("init.ss" "PackageInfrastructure")
                            ("build.ss" "PackageInfrastructure")
                            ("types.ss" "PackageInfrastructure")
                            ("config.ss" "PackageInfrastructure")
                            ("Justfile" "PackageInfrastructure")
                            ("package.json" "PackageInfrastructure")))
    (cons 'forbidden_item '())
    (cons 'package_manifest '(("." "deterministic-engineering-workspace" "yes")
                              ("packages/render" "@deterministic-engineering/render" "no")))
    (cons 'package_export_family '(("packages/render" "@deterministic-engineering/render"
                                    "./src/index.ts" "presentation")))
    (cons 'package_reference '(("packages/render" "@deterministic-engineering/render"
                                "./src/index.ts" "inside")))
    (cons 'declared_file_ref '(("packages/render/package.json" "src" "present")
                               ("projects/library-formation/init.ss" "project-organization" "present")))
    (cons 'rendered_placement rendered)
    (cons 'library_module '(("project-organization") ("evidence") ("backpressure-memory")
                            ("quint-methods") ("defensive-boundaries")
                            ("defensive-governance") ("defense-profiles")))
    (cons 'module_layer '(("project-organization" "de.layer.foundation" "0")
                          ("evidence" "de.layer.evidence" "1")
                          ("backpressure-memory" "de.layer.domain" "2")
                          ("quint-methods" "de.layer.method" "3")
                          ("defensive-boundaries" "de.layer.defense" "4")
                          ("defensive-governance" "de.layer.governance" "5")
                          ("defense-profiles" "de.layer.profile" "6")))
    (cons 'module_import_edge '(("defensive-governance" "defensive-boundaries")
                                ("defense-profiles" "defensive-governance")))))

(def repository-organization-test
  (test-suite "Repository organization rules OR01-OR06 and debt detection D1-D6"
    (yuanxu-test-case "organization declaration with placements and package families validates"
      (def model (validate (.get OrganizationModelContract value-contract) ProjectOrganization))
      (check-equal? (length (.get model placements)) 9)
      (check-equal? (length (.get model package-families)) 4))

    (yuanxu-test-case "actual repository yields zero OR01-OR06 findings after L2 repair"
      (def facts (capture-repository-organization-facts repo-root ProjectOrganization))
      (def result (reason-repository-organization facts))
      (check-equal? (rows result 'finding) '()))

    (yuanxu-test-case "rendered SysML with placements matches project.sysml and yields zero findings"
      (def formation (reason-project-formation (formation-inputs ProjectOrganization LibraryFormationProfile)))
      (def rendered (render-formation-model-with-placements formation LibraryFormationProfile))
      (check-equal? (and (string-contains rendered "part 'placements' {") #t) #t)
      (check-equal? (and (string-contains rendered "'RepositoryOrganization'::'SchemeModule';") #t) #t)
      (check-equal? (and (string-contains rendered "'RepositoryOrganization'::'DistributionPackage';") #t) #t)
      (def clean (clean-baseline-facts rendered))
      (def result (reason-repository-organization clean))
      (check-equal? (rows result 'finding) '()))

    (yuanxu-test-case "negative controls: each rule OR01-OR06 and debt D1-D6 is rejected"
      (def formation (reason-project-formation (formation-inputs ProjectOrganization LibraryFormationProfile)))
      (def rendered (render-formation-model-with-placements formation LibraryFormationProfile))
      (def base (clean-baseline-facts rendered))
      ;; D4 / OR01 unowned top-level path
      (def unowned
        (replace-fact base 'managed_path (cons '("observation") (cdr (assq 'managed_path base)))))
      (check-equal? (and (member '("OR01" "observation" "unowned-path")
                                 (rows (reason-repository-organization unowned) 'finding))
                         #t)
                    #t)
      ;; OR01 multiple owners
      (def dup-owner
        (replace-fact base 'path_placement
                      (cons '("packages" "SchemeModule") (cdr (assq 'path_placement base)))))
      (check-equal? (and (member '("OR01" "packages" "multiple-owners")
                                 (rows (reason-repository-organization dup-owner) 'finding))
                         #t)
                    #t)
      ;; D1 + D3 / OR02 forbidden content (root package, other-language source in SchemeModule,
      ;; JSON sidecar / relative cross-module import / incomplete co-located Quint unit)
      (def forbidden
        (replace-fact base 'forbidden_item
                      '(("package.json" "PackageInfrastructure" "package-implementation" "root-is-package:@deterministic-engineering/render")
                        ("library/backpressure-memory/model.qnt" "SchemeModule" "other-language-sources" "other-language-source-in-scheme-module:model.qnt")
                        ("packages/quint-models/threat/execution/effect-handoff/plan.json" "DistributionPackage" "tool-code-or-sidecar" "forbidden-in-quint-models:plan.json")
                        ("packages/quint-models/threat/execution/effect-handoff/types.ss" "DistributionPackage" "relative-cross-module-import" "cross-module-relative-import:../../../../../library/quint-methods/types.ss")
                        ("packages/quint-models/engineering/concurrency/orphan-model" "DistributionPackage" "incomplete-co-located-quint-unit" "missing:interface.ss"))))
      (def f-rows (rows (reason-repository-organization forbidden) 'finding))
      (check-equal? (has-finding? f-rows "OR02" "package.json") #t)
      (check-equal? (has-finding? f-rows "OR02" "library/backpressure-memory/model.qnt") #t)
      (check-equal? (has-finding? f-rows "OR02" "plan.json") #t)
      (check-equal? (has-finding? f-rows "OR02" "effect-handoff/types.ss") #t)
      (check-equal? (has-finding? f-rows "OR02" "orphan-model") #t)
      ;; OR03 cross-family export (quint inside render)
      (def cross-fam
        (replace-fact base 'package_export_family
                      '(("packages/render" "@deterministic-engineering/render"
                         "./quint/Handoff.qnt" "quint-model-content"))))
      (check-equal? (and (member '("OR03" "@deterministic-engineering/render" "cross-family-export")
                                 (rows (reason-repository-organization cross-fam) 'finding))
                         #t)
                    #t)
      ;; OR04 outside package closure
      (def outside-ref
        (replace-fact base 'package_reference
                      '(("packages/render" "@deterministic-engineering/render"
                         "../../library/evidence/objects.ss" "outside"))))
      (check-equal? (and (member '("OR04" "@deterministic-engineering/render" "../../library/evidence/objects.ss")
                                 (rows (reason-repository-organization outside-ref) 'finding))
                         #t)
                    #t)
      ;; D2 + D5 / OR05 absent package.json files entry or retired Project module
      (def absent-file
        (replace-fact base 'declared_file_ref
                      '(("package.json" "profiles" "absent")
                        ("projects/library-formation/init.ss" "project-intake" "absent"))))
      (def o5-rows (rows (reason-repository-organization absent-file) 'finding))
      (check-equal? (and (member '("OR05" "package.json" "profiles") o5-rows)
                         (member '("OR05" "projects/library-formation/init.ss" "project-intake") o5-rows)
                         #t)
                    #t)
      ;; D6 / OR06 uncovered role and missing rendered placement
      (def missing-role
        (replace-fact base 'declared_placement_role
                      (filter (lambda (r) (not (equal? (cadr r) "review")))
                              (cdr (assq 'declared_placement_role base)))))
      (check-equal? (and (member '("OR06" "review" "uncovered-role")
                                 (rows (reason-repository-organization missing-role) 'finding))
                         #t)
                    #t)
      (def missing-rendered (replace-fact base 'rendered_placement '()))
      (check-equal? (has-finding? (rows (reason-repository-organization missing-rendered) 'finding)
                                  "OR06" "SchemeModule")
                    #t)
      ;; OR07 acyclic layer DAG (10.153): missing layer tag, multiple layer tags, reverse layer imports
      (def untagged-mod
        (replace-fact base 'library_module (cons '("untagged-leaf") (cdr (assq 'library_module base)))))
      (check-equal? (and (member '("OR07" "untagged-leaf" "missing-layer-tag")
                                 (rows (reason-repository-organization untagged-mod) 'finding))
                         #t)
                    #t)
      (def multi-layer
        (replace-fact base 'module_layer
                      (cons '("backpressure-memory" "de.layer.profile" "6")
                            (cdr (assq 'module_layer base)))))
      (check-equal? (and (member '("OR07" "backpressure-memory" "multiple-layer-tags")
                                 (rows (reason-repository-organization multi-layer) 'finding))
                         #t)
                    #t)
      (def reverse-edges
        (replace-fact base 'module_import_edge
                      '(("backpressure-memory" "defense-profiles")
                        ("project-organization" "backpressure-memory")
                        ("backpressure-memory" "defensive-governance"))))
      (def o7-rows (rows (reason-repository-organization reverse-edges) 'finding))
      (check-equal? (and (member '("OR07" "backpressure-memory" "reverse-layer-dependency") o7-rows)
                         (member '("OR07" "project-organization" "reverse-layer-dependency") o7-rows)
                         #t)
                    #t))))

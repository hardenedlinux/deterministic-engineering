;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Shared Loader-owned qualification helper for Scheme-projected Quint models.
;;; Lives in t/support/ (outside the t/yanxu/ Loader test tree) per Yuanxu layout rules.
(import :std/test
        :std/source
        :std/misc/ports
        :clan/poo/object
        (only-in :clan/poo/type validate)
        :deterministic-engineering/library/quint-methods/types
        :deterministic-engineering/library/quint-methods/objects
        :deterministic-engineering/library/quint-methods/methods
        :deterministic-engineering/library/quint-methods/grammar
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 quint-model->verification-profile))
(export make-quint-model-qualification-suite)

(def repo-root
  (path-normalize (path-expand "../.." (path-directory (this-source-file)))))

(def (make-quint-model-qualification-suite label model (profile #f))
  (test-suite "Quint Loader owner qualification"
    (test-case "sealed contract, plan, same-commit .qnt and README.org projection, and gerbil-parser parse"
      (check-equal? (string? label) #t)
      (validate QuintDomainModelType model)
      (def eff-profile (or profile (quint-model->verification-profile model)))
      (def plan (quint-plan model eff-profile DefaultQuintPolicy))
      (validate QuintPlanType plan)
      (def guard-audit (quint-guard-audit model))
      (validate QuintGuardAuditReportType guard-audit)
      (check-equal? (.get guard-audit passed?) #t)
      (def expected-text (quint-module model))
      (def model-dir
        (path-expand (.get model domain-dir)
          (path-expand "packages/quint-models" repo-root)))
      (def disk-path (path-expand (.get model quint-file) model-dir))
      (check-equal? (file-exists? disk-path) #t)
      (check-equal? (read-file-string disk-path) expected-text)
      (check-equal? (quint-source-qualified? expected-text) #t)
      (when (.slot? model 'title)
        (let ((readme-path (path-expand "README.org" model-dir)))
          (check-equal? (file-exists? readme-path) #t)
          (check-equal? (read-file-string readme-path) (quint-model-readme model)))))))

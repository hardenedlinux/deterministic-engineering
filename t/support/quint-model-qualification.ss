;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Shared Loader-owned qualification helper for .qnt-SSOT Quint models (10.204).
;;; Uses native :tao3k/yuanxu/testing (yuanxu-test-case) and owns .qnt file lookup
;;; so individual test modules carry zero path boilerplate.
(import :std/test
        :std/source
        :std/misc/ports
        :clan/poo/object
        (only-in :clan/poo/type validate)
        (only-in :tao3k/yuanxu/testing yuanxu-test-case)
        :deterministic-engineering/library/quint-methods/types
        :deterministic-engineering/library/quint-methods/objects
        :deterministic-engineering/library/quint-methods/methods
        :deterministic-engineering/library/quint-methods/grammar
        (only-in :deterministic-engineering/library/quint-profiles/objects
                 quint-model->verification-profile))
(export quint-model-dir
        read-quint-model-source
        make-quint-model-qualification-suite)

(def (quint-models-root)
  (let ((cwd-pkg (path-expand "packages/quint-models" (current-directory))))
    (if (file-exists? cwd-pkg)
      cwd-pkg
      (path-expand "packages/quint-models"
        (path-normalize (path-expand "../.." (path-directory (this-source-file))))))))

(def (quint-model-dir model)
  (path-expand (.get model domain-dir) (quint-models-root)))

(def (read-quint-model-source model)
  (read-file-string (path-expand (.get model quint-file) (quint-model-dir model))))

(def (make-quint-model-qualification-suite label model (profile #f))
  (test-suite "Quint Loader owner qualification (.qnt-SSOT)"
    (yuanxu-test-case "hard sealed metadata contract, native .qnt LR parse, plan, F3 guard audit, and README parity"
      (check-equal? (string? label) #t)
      (validate QuintDomainModelType model)
      (def model-dir (quint-model-dir model))
      (def disk-path (path-expand (.get model quint-file) model-dir))
      (check-equal? (file-exists? disk-path) #t)
      (def disk-text (read-file-string disk-path))
      (check-equal? (quint-source-qualified? disk-text) #t)
      (def spec (parse-quint-model-spec disk-text))
      (def eff-profile
        (or profile
            (quint-model->verification-profile
              model
              (.o verify-depth: (.get spec verify-depth)
                  countermodel-depth: (.get spec countermodel-depth)
                  require-countermodels?:
                  (or (string-prefix? "engineering/" (.get model domain-dir))
                      (and (pair? (.get spec countermodels)) #t))))))
      (def plan (quint-plan model disk-text eff-profile DefaultQuintPolicy))
      (validate QuintPlanType plan)
      (def guard-audit (quint-guard-audit model disk-text))
      (validate QuintGuardAuditReportType guard-audit)
      (check-equal? (.get guard-audit passed?) #t)
      (when (.slot? model 'title)
        (let ((readme-path (path-expand "README.org" model-dir)))
          (check-equal? (file-exists? readme-path) #t)
          (check-equal? (read-file-string readme-path)
                        (quint-model-readme model disk-text)))))))

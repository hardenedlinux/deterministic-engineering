;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Shared Loader-owned qualification helper for Scheme-projected Quint models.
;;; Lives in t/support/ (outside the t/yanxu/ Loader test tree) per Yuanxu layout rules.
(import :std/test
        :std/source
        :std/misc/ports
        :clan/poo/object
        (only-in :clan/poo/type validate)
        "../../library/quint-methods/types.ss"
        "../../library/quint-methods/objects.ss"
        "../../library/quint-methods/methods.ss"
        "../../library/quint-methods/grammar.ss")
(export make-quint-model-qualification-suite)

(def repo-root (path-normalize (path-expand "../.." (path-directory (this-source-file)))))

(def (make-quint-model-qualification-suite label model profile)
  (test-suite "Quint Loader owner qualification"
    (test-case "sealed contract, plan, same-commit .qnt projection, and gerbil-parser parse"
      (check-equal? (string? label) #t)
      (validate QuintDomainModelType model)
      (def plan (quint-plan model profile DefaultQuintPolicy))
      (validate QuintPlanType plan)
      (def expected-text (quint-module model))
      (def disk-path
        (path-expand (.get model quint-file)
          (path-expand (.get model domain-dir)
            (path-expand "packages/quint-models" repo-root))))
      (check-equal? (file-exists? disk-path) #t)
      (check-equal? (read-file-string disk-path) expected-text)
      (check-equal? (quint-source-qualified? expected-text) #t))))

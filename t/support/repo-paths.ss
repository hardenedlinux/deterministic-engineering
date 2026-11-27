;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Canonical repository path helper for t/yanxu/ test modules (10.205).
;;; Eliminates duplicated (path-expand "../../../.." (path-directory (this-source-file)))
;;; boilerplate across all Loader-owned test suites.
(import :std/source)
(export resolve-repo-root repo-path)

(def (resolve-repo-root)
  (let ((cwd (current-directory)))
    (if (and (file-exists? (path-expand "init.ss" cwd))
             (file-exists? (path-expand "packages/quint-models" cwd)))
      (path-normalize cwd)
      (path-normalize (path-expand "../.." (path-directory (this-source-file)))))))

(def (repo-path rel)
  (path-expand rel (resolve-repo-root)))

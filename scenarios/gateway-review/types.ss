;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; -*- Gerbil -*-
(import
  :clan/poo/object
  (only-in :yuanxu/object-types/contracts yuanxu-predicate-contract)
  (only-in
   "../../library/drivers/rust-resources/types.ss"
   RustResourcesScopeContract)
  (only-in "../../library/drivers/evidence/types.ss" ResourceEvidenceScopeContract))
(export
  RustResourcesScopeContract
  ResourceEvidenceScopeContract
  ScenarioScopeContract)
(def ScenarioScopeContract
  (yuanxu-predicate-contract
   'gateway/scenario-scope
   (lambda (v)
     (and (object? v) (.slot? v 'open-review) (procedure? (.ref v 'open-review))))
   (lambda (_v _c) '())))

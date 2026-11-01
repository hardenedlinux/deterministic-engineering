;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

(import
  :clan/poo/object)
(export
  FormationSemantics)
;; No copied LR list or independent version; actual Program owns its rules/bounds.
(def FormationSemantics
  (.o
    purpose: 'declaration-layout
    authority: 'design-only
    program-owner: 'project-formation
    reason-operation: 'reason
    render-operation: 'render))

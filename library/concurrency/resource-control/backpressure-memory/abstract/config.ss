;;; SPDX-FileCopyrightText: 2026 tao3k team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-only

(import
  :clan/poo/object
  "objects.ss")
(export
  Config)
(def Config
  (.o
    entry: BackpressureModel
    declaration: BackpressureDeclaration))

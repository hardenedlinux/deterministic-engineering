;;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;;;
;;; SPDX-License-Identifier: LGPL-2.1-or-later

(import
  :clan/poo/object
  "objects.ss")
(export
  Config)
(def Config
  (.o
    entry: BackpressureModel
    declaration: BackpressureDeclaration))

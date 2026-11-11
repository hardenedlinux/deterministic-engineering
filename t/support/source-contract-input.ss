;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Development input for real compiler/solver controls; not a product Runtime.
(import :clan/poo/object
        (only-in :yuanxu/module-system/source/observations
                 module-source-read module-source-admit-current!
                 module-source-object-policy))
(export SourceContractInput.)

;;; A language-input value delegates guards to its selected native Module owner.
(.def (SourceContractInput. subject [])
  scenario: (error "Select a declarative Library Scenario")
  tools: (error "Select tool paths")
  module-owner: (error "Select the native init owner")
  driver: (error "Select the native source-contract driver leaf")
  verification-plan:
  (.call (.get driver plan-library) plan
    (.get scenario profile executor) (.get scenario profile))
  source-inputs:
  (map (lambda (relative)
         (def path (path-expand relative (.get scenario root)))
         (cons path (module-source-read path)))
       (.get scenario profile inputs))
  translation-units: (map (cut path-expand <> (.get scenario root)) (.get scenario profile units))
  value-current?: (module-source-object-policy (list subject scenario (.get scenario profile) (.get scenario entry) tools))
  admit-current:
  (lambda ()
    (.call module-owner admit-current)
    (unless (value-current?) (error "selected source-contract leaf changed"))
    (module-source-admit-current! source-inputs "selected C/C++ source changed"))
  .verify: (lambda (output) ((.get driver run) subject output)))

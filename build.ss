#!/usr/bin/env gxi
;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Product construction via native Yuanxu .compile-selection with package-roots?: #t
;;; so on-demand upstream mounts (LabModules/funflow) and local mounts build cleanly.
(import (only-in :clan/poo/object .call .get)
        (only-in :std/build-script defbuild-script)
        (only-in :std/make make make-clean)
        (only-in "./init.ss" deterministic-engineering.init.exports))

(def build-mounts
  '(LabModules
    Library
    Quint.Engineering.Storage
    Quint.Engineering.Consensus
    Quint.Engineering.Concurrency
    Quint.Engineering.Parallel
    Quint.Engineering.GC
    Quint.Engineering.Defense
    Quint.Threat.ZeroTrust
    Quint.Threat.Identity
    Quint.Threat.Protocol
    Quint.Threat.SupplyChain
    Quint.Threat.Execution))

(def (build-options flags)
  (foldr (lambda (flag options)
           (match flag
             ("--release" (cons* build-release: #t options))
             ("--optimized" (cons* build-optimized: #t options))
             ("--debug" (cons* debug: #t options))
             (else (error "Unexpected build option" flag))))
         '() flags))

(def (compile flags)
  (def options (build-options flags))
  (.call deterministic-engineering.init.exports .compile-selection '() build-mounts
    (lambda (targets root) (apply make targets srcdir: root options))
    package-roots?: #t))

(def (main . arguments)
  (match arguments
    ([] (compile '()))
    (["compile" . flags] (compile flags))
    (["clean"]
     (.call deterministic-engineering.init.exports .clean-selection '() build-mounts
       (lambda (targets root) (make-clean targets srcdir: root))
       package-roots?: #t))
    (else
     (let ()
       (defbuild-script (.get deterministic-engineering.init.exports std-make-spec))
       (apply main arguments)))))

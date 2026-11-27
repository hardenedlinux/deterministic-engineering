;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Canonical .qnt-SSOT prototype and default verification policy (10.204).
;;; ThreatModel. carries ONLY Yuanxu metadata and the .qnt pointer; state, guards,
;;; transitions, safety, traces, and countermodels live exclusively in <Model>.qnt
;;; and are forbidden in Scheme by the sealed QuintDomainModelShape contract.
(import :clan/poo/object)
(export DefaultQuintPolicy ThreatModel.)

(.def DefaultQuintPolicy
  quint-version: "0.33.0"
  apalache-version: "0.62.1"
  timeout: 120)

(.def ThreatModel.
  identity: 'threat.base
  family: 'threat.base
  parent: #f
  revision: "1"
  quint-module: "threat_base"
  quint-file: "ThreatBase.qnt"
  domain-dir: "threat/base"
  factor-implications: '()
  rules: '()
  dependencies: '()
  invariant: "Finite safety predicate defined natively in the paired .qnt file."
  limits: "Finite model abstraction; no cryptography, network or Lean refinement is claimed.")

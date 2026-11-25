;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned finite attacker acquisition model; no Quint CLI or I/O here.
(import :clan/poo/object)
(export ThreatModel. CapabilitiesModel)

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
  invariant: "Finite safety predicate over declared state."
  state: '()
  guards: '()
  transitions: '()
  safety: "true"
  traces: '()
  countermodels: '()
  parameters: '()
  limits: "Finite model abstraction; no cryptography, network or Lean refinement is claimed.")

(.def (CapabilitiesModel @ ThreatModel.)
  identity: 'threat.capabilities
  family: 'threat.capabilities
  quint-module: "threat_capabilities"
  quint-file: "Capabilities.qnt"
  domain-dir: "threat/capabilities"
  rules: '((capability-projection CAP-ACQ quint))
  dependencies: '((CAP-ACQ source) (CAP-ACQ profile) (CAP-ACQ method))
  invariant: "Target capability is learnable iff a rule grants it and its prerequisites are known."
  state: '((known "Set[str]"))
  guards: '((rule-prerequisites "rule.needs.subseteq(known)"))
  transitions: '((canLearn "pure def canLearn(known: Set[str], rules: Set[{ needs: Set[str], grants: str }], target: str): bool =\n    rules.exists(rule => rule.grants == target and rule.needs.subseteq(known))"))
  safety: "true"
  traces: '((learnableTest "pure val sampleRules = Set({ needs: Set(\"a\"), grants: \"b\" })\n  run learnableTest = all { assert(canLearn(Set(\"a\"), sampleRules, \"b\")), assert(not(canLearn(Set(), sampleRules, \"b\"))) }"))
  countermodels: '()
  parameters: '()
  limits: "Finite acquisition projection; does not model timing, side channels or cryptographic compromise.")

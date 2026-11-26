;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned finite attacker acquisition model; no Quint CLI or I/O here.
(import :clan/poo/object
        (only-in "../quint-methods/objects.ss" ThreatModel.))
(export ThreatModel. CapabilitiesModel)

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
  guards: '((rule-prerequisites (subseteq (. rule needs) known)))
  transitions:
  '((canLearn
     (pure-def canLearn ((known "Set[str]")
                         (rules "Set[{ needs: Set[str], grants: str }]")
                         (target "str"))
               "bool"
       (exists rules rule
         (and (= (. rule grants) target)
              (subseteq (. rule needs) known))))))
  safety: #t
  traces:
  '((sampleRules
     (pure-val sampleRules
       (set (record (needs (set "a")) (grants "b")))))
    (learnableTest
     (run learnableTest
       (all (assert (call canLearn (set "a") sampleRules "b"))
            (assert (not (call canLearn (set) sampleRules "b")))))))
  countermodels: '()
  parameters: '()
  limits: "Finite acquisition projection; does not model timing, side channels or cryptographic compromise.")

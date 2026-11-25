;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned authority currentness predicates; no Quint CLI or I/O here.
(import :clan/poo/object
        (only-in "../threat-capabilities/objects.ss" ThreatModel.))
(export AuthorityCurrentnessModel)

(.def (AuthorityCurrentnessModel @ ThreatModel.)
  identity: 'threat.authority-currentness
  family: 'threat.authority-currentness
  quint-module: "authority_currentness"
  quint-file: "AuthorityCurrentness.qnt"
  domain-dir: "threat/authority-currentness"
  rules: '((authority-currentness AUTH-CURR quint))
  dependencies: '((AUTH-CURR source) (AUTH-CURR profile) (AUTH-CURR method))
  invariant: "Authority is current only while unpaused, fresh, valid credential, intact bytes, and matching writer epoch."
  state: '((paused "bool")
           (fresh "bool")
           (credential "bool")
           (bytes "bool")
           (epoch "int")
           (planned "int"))
  guards: '((unpaused "not(paused)")
            (fresh "fresh")
            (credential "credential")
            (bytes "bytes")
            (epoch-match "epoch == planned"))
  transitions: '((isCurrent "pure def isCurrent(paused: bool, fresh: bool, credential: bool, bytes: bool): bool =\n    not(paused) and fresh and credential and bytes")
                 (epochCurrent "pure def epochCurrent(epoch: int, planned: int): bool =\n    epoch == planned"))
  safety: "true"
  traces: '((currentnessTest "run currentnessTest = all {\n    assert(isCurrent(false, true, true, true)),\n    assert(not(isCurrent(true, true, true, true))),\n    assert(not(isCurrent(false, false, true, true))),\n    assert(not(isCurrent(false, true, false, true))),\n    assert(not(isCurrent(false, true, true, false))),\n    assert(epochCurrent(0, 0)),\n    assert(not(epochCurrent(1, 0)))\n  }"))
  countermodels: '()
  parameters: '()
  limits: "Trusted boolean bits abstract real clock freshness, revocation checks, signature verification and writer fencing.")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B3 (10.160): Cross-Trust-Boundary Multi-Agent Delegation,
;;; Macaroon-Style Monotonic Capability Attenuation, and Cascading Ancestor Revocation.
;;; Proves three capability-security invariants across multi-hop agent supply chains:
;;;   1. Monotonic attenuation: no delegated child can widen scope beyond parent/root
;;;      (escalationViolations == 0).
;;;   2. Cascading revocation: revoking any ancestor in live M3 immediately invalidates
;;;      all downstream delegates (revokedSubtreeExecutions == 0).
;;;   3. Chain MAC integrity, non-delegable flag, and finite hop depth are strictly
;;;      enforced at consumption time (forgedOrDepthViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export CapabilityAttenuationModel)

(.def (CapabilityAttenuationModel @ ThreatModel.)
  identity: 'engineering.defense.capability-attenuation
  family: 'engineering.defense.capability-attenuation
  title: "Cross-Trust-Boundary Delegation: Monotonic Capability Attenuation & Cascading Revocation"
  subdomain: 'quint.engineering.defense
  papers:
  '(("N. Hardy (ACM OSR 1988) / M. S. Miller, K.-P. Yee & J. Shapiro (2003)"
     "The Confused Deputy & Capability Myths Demolished: strict confinement, attenuation, and revocable caretakers.")
    ("A. Birgisson et al. (NDSS 2014)"
     "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud.")
    ("Deterministic Engineering (10.156 / 10.160)"
     "Immutable M1 Merkle delegation certificates chained with live M3 root signing keys and cascading revocation."))
  quint-module: "capability_attenuation"
  quint-file: "CapabilityAttenuation.qnt"
  domain-dir: "engineering/defense/capability-attenuation"
  rules:
  '((capability-attenuation-safe DE-CAP-SAFE quint)
    (capability-attenuation-countermodel DE-CAP-COUNTER quint))
  dependencies:
  '((DE-CAP-SAFE source)
    (DE-CAP-SAFE profile)
    (DE-CAP-SAFE method)
    (DE-CAP-COUNTER source)
    (DE-CAP-COUNTER profile)
    (DE-CAP-COUNTER method))
  invariant: "No delegated agent executes with an escalated scope exceeding parent/root (escalationViolations == 0), no downstream delegate executes after any ancestor is revoked in M3 (revokedSubtreeExecutions == 0), and no forged chain MAC, non-delegable hop, or hop-depth overflow executes (forgedOrDepthViolations == 0)."
  limits: "Finite two-hop monotonic scope attenuation, chain MAC integrity, hop-depth bound, and M3 cascading revocation abstraction; does not model side-channel exfiltration by an authorized delegate or out-of-band network collusion.")

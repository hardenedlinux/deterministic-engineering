;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned effect containment and verified clearance witness model.
;;; Co-located Yuanxu unit: single source of truth alongside EffectContainment.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export EffectContainmentModel)

(.def (EffectContainmentModel @ AuthorityCurrentnessModel)
  identity: 'threat.execution.effect-containment
  family: 'threat.execution.effect-containment
  title: "Assume-Breach Effect Containment & Finalized Clearance Witness"
  subdomain: 'quint.threat.execution
  papers:
  '(("S. Rose, O. Borchert, S. Mitchell & S. Connelly (NIST SP 800-207, 2020)"
     "Zero Trust Architecture: assume-breach pause, blast-radius containment, and verified re-admission.")
    ("M. S. Miller (Johns Hopkins PhD Thesis 2006)"
     "Robust Composition: non-recoverable revocation until explicit verified clearance witness."))
  quint-module: "effect_containment"
  quint-file: "EffectContainment.qnt"
  domain-dir: "threat/execution/effect-containment"
  rules:
  '((effect-containment-safe CONT-SAFE quint)
    (effect-containment-stale-recovery CONT-STALE quint)
    (effect-containment-false-clear CONT-FALSE quint))
  dependencies:
  '((CONT-SAFE source)
    (CONT-SAFE profile)
    (CONT-SAFE method)
    (CONT-STALE source)
    (CONT-STALE profile)
    (CONT-STALE method)
    (CONT-FALSE source)
    (CONT-FALSE profile)
    (CONT-FALSE method))
  invariant: "No signature occurs while delegated, paused, revoked, or clear-pending; clearance requires verified finalized witness."
  limits: "Finite containment abstraction; verified/finalized/noCode bits abstract trusted Host observations, not EVM/consensus proofs.")

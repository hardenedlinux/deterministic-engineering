;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F4 / P2 / M3: Unknown remote effect retry and consumption-time authority boundary (20.16 CO05 / 10.153).
;;; Proves that an unknown remote effect cannot be auto-retried without an idempotency contract,
;;; and that request-time allow never substitutes for live consumption-time authority.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export UnknownEffectRetryModel)

(.def (UnknownEffectRetryModel @ ThreatModel.)
  identity: 'engineering.defense.unknown-effect-retry
  family: 'engineering.defense.unknown-effect-retry
  title: "Unknown Remote Effect Retry & Consumption-Time Authority Boundary"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Deterministic Engineering (20.16 CO05 / DE01-S4 / 10.153)"
     "Unresolved remote effects are not safe retry; request-time allow is not consumption-time authority.")
    ("P. Helland (CIDR 2007)"
     "Life Beyond Distributed Transactions: idempotency contracts under uncertain delivery outcomes."))
  quint-module: "unknown_effect_retry"
  quint-file: "UnknownEffectRetry.qnt"
  domain-dir: "engineering/defense/unknown-effect-retry"
  rules:
  '((unknown-effect-safe DE-EFF-SAFE quint)
    (unknown-effect-countermodel DE-EFF-COUNTER quint))
  dependencies:
  '((DE-EFF-SAFE source)
    (DE-EFF-SAFE profile)
    (DE-EFF-SAFE method)
    (DE-EFF-COUNTER source)
    (DE-EFF-COUNTER profile)
    (DE-EFF-COUNTER method))
  invariant: "Every dispatched effect is authorized at actual consumption time (authorizedDispatches == dispatches), and no non-idempotent effect is dispatched more than once under an unknown remote outcome."
  limits: "Finite single-effect retry and revocation abstraction; does not model network packet duplication, compensation saga choreography, or clock skew.")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F4 / P2 / M3: Unknown remote effect retry and consumption-time authority boundary (20.16 CO05 / 10.153).
;;; Proves that an unknown remote effect cannot be auto-retried without an idempotency contract,
;;; and that request-time allow never substitutes for live consumption-time authority.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export UnknownEffectRetryModel
        BlindRetryUnknownEffectCountermodel
        ToctouRevokedUseCountermodel)

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
  verify-depth: 10
  countermodel-depth: 6
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
  parameters: '()
  state:
  '((requestAllowed "bool" "false")
    (authorityRevoked "bool" "false")
    (idempotentContract "bool" "false")
    (effectUnknown "bool" "false")
    (dispatches "int" "0")
    (authorizedDispatches "int" "0")
    (nonIdempotentDispatches "int" "0"))
  guards:
  '((check-authority-at-use (not (. h authorityRevoked)))
    (no-blind-retry-unknown-effect (. h idempotentContract)))
  transitions:
  '((grantRequest
      (action grantRequest ()
        (if (not (. h requestAllowed))
          (set-h (requestAllowed #t))
          (keep-h))))
    (establishIdempotency
      (action establishIdempotency ()
        (if (and (not (. h idempotentContract)) (= (. h dispatches) 0))
          (set-h (idempotentContract #t))
          (keep-h))))
    (revokeAuthority
      (action revokeAuthority ()
        (if (not (. h authorityRevoked))
          (set-h (authorityRevoked #t))
          (keep-h))))
    (dispatchEffect
      (action dispatchEffect ()
        (if (and (. h requestAllowed)
                 (= (. h dispatches) 0)
                 (guard check-authority-at-use (not (. h authorityRevoked))))
          (set-h (dispatches (+ (. h dispatches) 1))
                 (effectUnknown #t)
                 (authorizedDispatches
                   (if (. h authorityRevoked)
                     (. h authorizedDispatches)
                     (+ (. h authorizedDispatches) 1)))
                 (nonIdempotentDispatches
                   (if (. h idempotentContract)
                     (. h nonIdempotentDispatches)
                     (+ (. h nonIdempotentDispatches) 1))))
          (keep-h))))
    (resolveEffectOutcome
      (action resolveEffectOutcome ()
        (if (. h effectUnknown)
          (set-h (effectUnknown #f))
          (keep-h))))
    (retryEffect
      (action retryEffect ()
        (if (and (. h requestAllowed)
                 (. h effectUnknown)
                 (guard no-blind-retry-unknown-effect (. h idempotentContract))
                 (guard check-authority-at-use (not (. h authorityRevoked))))
          (set-h (dispatches (+ (. h dispatches) 1))
                 (effectUnknown #f)
                 (authorizedDispatches
                   (if (. h authorityRevoked)
                     (. h authorizedDispatches)
                     (+ (. h authorizedDispatches) 1)))
                 (nonIdempotentDispatches
                   (if (. h idempotentContract)
                     (. h nonIdempotentDispatches)
                     (+ (. h nonIdempotentDispatches) 1))))
          (keep-h))))
    (step
      (action step ()
        (any grantRequest establishIdempotency revokeAuthority
             dispatchEffect resolveEffectOutcome retryEffect))))
  safety:
  '(and (= (. h authorizedDispatches) (. h dispatches))
        (<= (. h nonIdempotentDispatches) 1))
  traces:
  '((idempotentRetrySafeTest
      (run idempotentRetrySafeTest
        (then init grantRequest establishIdempotency dispatchEffect retryEffect
              (all (assert safety)
                   (assert (= (. h dispatches) 2))
                   (assert (= (. h nonIdempotentDispatches) 0))
                   (keep-h)))))
    (nonIdempotentBlocksRetryTest
      (run nonIdempotentBlocksRetryTest
        (then init grantRequest dispatchEffect retryEffect
              (all (assert safety)
                   (assert (= (. h dispatches) 1))
                   (assert (. h effectUnknown))
                   (keep-h)))))
    (blindRetryViolatesSafetyTest
      (run blindRetryViolatesSafetyTest
        (then init grantRequest dispatchEffect retryBlindUnknownEffect
              (all (assert (not safety))
                   (assert (> (. h nonIdempotentDispatches) 1))
                   (keep-h)))))
    (toctouRevokedViolatesSafetyTest
      (run toctouRevokedViolatesSafetyTest
        (then init grantRequest revokeAuthority dispatchIgnoreRevocation
              (all (assert (not safety))
                   (assert (< (. h authorizedDispatches) (. h dispatches)))
                   (keep-h))))))
  countermodels:
  (list BlindRetryUnknownEffectCountermodel
        ToctouRevokedUseCountermodel)
  limits: "Finite single-effect retry and revocation abstraction; does not model network packet duplication, compensation saga choreography, or clock skew.")

(.def (BlindRetryUnknownEffectCountermodel @ UnknownEffectRetryModel)
  identity: 'engineering.defense.unknown-effect-retry.blind-retry
  dropped-guard: 'no-blind-retry-unknown-effect
  step-action: "stepBlindRetry"
  derive-from-transition: 'retryEffect
  derive-action-name: 'retryBlindUnknownEffect
  expected-itf-predicate: "h.nonIdempotentDispatches > 1")

(.def (ToctouRevokedUseCountermodel @ UnknownEffectRetryModel)
  identity: 'engineering.defense.unknown-effect-retry.toctou-revoked-use
  dropped-guard: 'check-authority-at-use
  step-action: "stepToctouRevokedUse"
  derive-from-transition: 'dispatchEffect
  derive-action-name: 'dispatchIgnoreRevocation
  expected-itf-predicate: "h.authorizedDispatches < h.dispatches")

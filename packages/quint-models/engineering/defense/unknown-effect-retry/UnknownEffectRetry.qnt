// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model engineering.defense.unknown-effect-retry
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=10
// @countermodel no-blind-retry-unknown-effect step=stepBlindRetry max-steps=6 itf="h.nonIdempotentDispatches > 1"
// @countermodel check-authority-at-use step=stepToctouRevokedUse max-steps=6 itf="h.authorizedDispatches < h.dispatches"
// Limits: Finite single-effect retry and revocation abstraction; does not model network packet duplication, compensation saga choreography, or clock skew.
module unknown_effect_retry {
  type State = { requestAllowed: bool, authorityRevoked: bool, idempotentContract: bool, effectUnknown: bool, dispatches: int, authorizedDispatches: int, nonIdempotentDispatches: int }
  var h: State
  action init = h' = { requestAllowed: false, authorityRevoked: false, idempotentContract: false, effectUnknown: false, dispatches: 0, authorizedDispatches: 0, nonIdempotentDispatches: 0 }
  action grantRequest = if (not(h.requestAllowed)) h' = h.with("requestAllowed", true) else h' = h
  action establishIdempotency = if ((not(h.idempotentContract) and h.dispatches == 0)) h' = h.with("idempotentContract", true) else h' = h
  action revokeAuthority = if (not(h.authorityRevoked)) h' = h.with("authorityRevoked", true) else h' = h
  action dispatchEffect = if ((h.requestAllowed and h.dispatches == 0 and not(h.authorityRevoked))) h' = h.with("dispatches", (h.dispatches + 1)).with("effectUnknown", true).with("authorizedDispatches", if (h.authorityRevoked) h.authorizedDispatches else (h.authorizedDispatches + 1)).with("nonIdempotentDispatches", if (h.idempotentContract) h.nonIdempotentDispatches else (h.nonIdempotentDispatches + 1)) else h' = h
  action resolveEffectOutcome = if (h.effectUnknown) h' = h.with("effectUnknown", false) else h' = h
  action retryEffect = if ((h.requestAllowed and h.effectUnknown and h.idempotentContract and not(h.authorityRevoked))) h' = h.with("dispatches", (h.dispatches + 1)).with("effectUnknown", false).with("authorizedDispatches", if (h.authorityRevoked) h.authorizedDispatches else (h.authorizedDispatches + 1)).with("nonIdempotentDispatches", if (h.idempotentContract) h.nonIdempotentDispatches else (h.nonIdempotentDispatches + 1)) else h' = h
  action step = any { grantRequest, establishIdempotency, revokeAuthority, dispatchEffect, resolveEffectOutcome, retryEffect }
  val safety = (h.authorizedDispatches == h.dispatches and h.nonIdempotentDispatches <= 1)
  // Countermodel engineering.defense.unknown-effect-retry.blind-retry (dropped guard: no-blind-retry-unknown-effect)
  action retryBlindUnknownEffect = if ((h.requestAllowed and h.effectUnknown and true and not(h.authorityRevoked))) h' = h.with("dispatches", (h.dispatches + 1)).with("effectUnknown", false).with("authorizedDispatches", if (h.authorityRevoked) h.authorizedDispatches else (h.authorizedDispatches + 1)).with("nonIdempotentDispatches", if (h.idempotentContract) h.nonIdempotentDispatches else (h.nonIdempotentDispatches + 1)) else h' = h
  action stepBlindRetry = any { step, retryBlindUnknownEffect }
  // Countermodel engineering.defense.unknown-effect-retry.toctou-revoked-use (dropped guard: check-authority-at-use)
  action dispatchIgnoreRevocation = if ((h.requestAllowed and h.dispatches == 0 and true)) h' = h.with("dispatches", (h.dispatches + 1)).with("effectUnknown", true).with("authorizedDispatches", if (h.authorityRevoked) h.authorizedDispatches else (h.authorizedDispatches + 1)).with("nonIdempotentDispatches", if (h.idempotentContract) h.nonIdempotentDispatches else (h.nonIdempotentDispatches + 1)) else h' = h
  action stepToctouRevokedUse = any { step, dispatchIgnoreRevocation }
  run idempotentRetrySafeTest = init.then(grantRequest).then(establishIdempotency).then(dispatchEffect).then(retryEffect).then(all { assert(safety), assert(h.dispatches == 2), assert(h.nonIdempotentDispatches == 0), h' = h })
  run nonIdempotentBlocksRetryTest = init.then(grantRequest).then(dispatchEffect).then(retryEffect).then(all { assert(safety), assert(h.dispatches == 1), assert(h.effectUnknown), h' = h })
  run blindRetryViolatesSafetyTest = init.then(grantRequest).then(dispatchEffect).then(retryBlindUnknownEffect).then(all { assert(not(safety)), assert(h.nonIdempotentDispatches > 1), h' = h })
  run toctouRevokedViolatesSafetyTest = init.then(grantRequest).then(revokeAuthority).then(dispatchIgnoreRevocation).then(all { assert(not(safety)), assert(h.authorizedDispatches < h.dispatches), h' = h })
}

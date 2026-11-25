// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// Projected from Scheme POO module threat.device-authorization. Do not edit by hand.
// Limits: Finite RFC 8628 device authorization and two-account binding abstraction; does not model network polling backoff intervals or TLS transport.
module device_authorization {
  import authority_currentness.* from "../authority-currentness/AuthorityCurrentness"
  type State = { flowEpoch: int, deviceActive: bool, deviceExpired: bool, deviceCancelled: bool, pollInFlight: bool, pollStartedEpoch: int, admitted: bool, activeAccount: int, ticketAccount: int, attachedTokenAccount: int, unsafe: bool }
  var h: State
  action init = h' = { flowEpoch: 0, deviceActive: false, deviceExpired: false, deviceCancelled: false, pollInFlight: false, pollStartedEpoch: 0, admitted: false, activeAccount: 1, ticketAccount: 0, attachedTokenAccount: 0, unsafe: false }
  action beginDeviceFlow = if (not(h.deviceActive) and not(h.admitted) and h.flowEpoch < 3)
    h' = h.with("flowEpoch", h.flowEpoch + 1).with("deviceActive", true).with("deviceExpired", false).with("deviceCancelled", false)
    else h' = h
  action startDevicePoll = if (h.deviceActive and not(h.deviceExpired) and not(h.pollInFlight))
    h' = h.with("pollInFlight", true).with("pollStartedEpoch", h.flowEpoch)
    else h' = h
  action expireDeviceCode = if (h.deviceActive and not(h.deviceExpired))
    h' = h.with("deviceExpired", true)
    else h' = h
  action cancelDeviceFlow = if (h.deviceActive and h.flowEpoch < 3)
    h' = h.with("flowEpoch", h.flowEpoch + 1).with("deviceActive", false).with("deviceCancelled", true)
    else h' = h
  action finishDevicePoll = if (h.pollInFlight)
    if (epochCurrent(h.flowEpoch, h.pollStartedEpoch) and h.deviceActive and not(h.deviceExpired) and not(h.deviceCancelled))
      h' = h.with("pollInFlight", false).with("deviceActive", false).with("admitted", true)
    else h' = h.with("pollInFlight", false)
    else h' = h
  action issueTicketForActive = h' = h.with("ticketAccount", h.activeAccount).with("attachedTokenAccount", 0)
  action switchAccount = h' = h.with("activeAccount", if (h.activeAccount == 1) 2 else 1)
  action attachBearerForTicket = if (h.ticketAccount > 0)
    h' = h.with("attachedTokenAccount", h.ticketAccount)
    else h' = h
  action step = any { beginDeviceFlow, startDevicePoll, expireDeviceCode, cancelDeviceFlow, finishDevicePoll, issueTicketForActive, switchAccount, attachBearerForTicket }
  val safety = not(h.unsafe) and (not(h.admitted) or (not(h.deviceCancelled) and not(h.deviceExpired))) and (h.attachedTokenAccount == 0 or h.attachedTokenAccount == h.ticketAccount)
  // Countermodel threat.device-authorization.cancelled-device-admit (dropped guard: device-flow-epoch-currency)
  action finishDevicePollNoEpoch = if (h.pollInFlight and h.deviceCancelled)
    h' = h.with("pollInFlight", false).with("admitted", true).with("unsafe", true)
    else h' = h
  action stepCancelledDeviceAdmit = any { step, finishDevicePollNoEpoch }
  // Countermodel threat.device-authorization.expired-device-admit (dropped guard: device-code-freshness)
  action finishDevicePollExpired = if (h.pollInFlight and h.deviceExpired)
    h' = h.with("pollInFlight", false).with("admitted", true).with("unsafe", true)
    else h' = h
  action stepExpiredDeviceAdmit = any { step, finishDevicePollExpired }
  // Countermodel threat.device-authorization.cross-account-token-bind (dropped guard: ticket-account-binding)
  action attachBearerFromActive = if (h.ticketAccount > 0 and h.activeAccount != h.ticketAccount)
    h' = h.with("attachedTokenAccount", h.activeAccount).with("unsafe", true)
    else h' = h
  action stepCrossAccountBind = any { step, attachBearerFromActive }
  action checkSafe = all { assert(safety), h' = h }
  action checkUnsafe = all { assert(not(safety)), h' = h }
  run validDeviceFlowTest = init.then(beginDeviceFlow).then(startDevicePoll).then(finishDevicePoll).then(all { assert(h.admitted), assert(safety), h' = h })
  run cancelBlocksInFlightPollTest = init.then(beginDeviceFlow).then(startDevicePoll).then(cancelDeviceFlow).then(finishDevicePoll).then(all { assert(not(h.admitted)), assert(safety), h' = h })
  run switchAccountPreservesTicketBindingTest = init.then(issueTicketForActive).then(switchAccount).then(attachBearerForTicket).then(all { assert(h.attachedTokenAccount == 1), assert(h.activeAccount == 2), assert(safety), h' = h })
  run crossAccountConfusionCountermodelTest = init.then(issueTicketForActive).then(switchAccount).then(attachBearerFromActive).then(checkUnsafe)
}

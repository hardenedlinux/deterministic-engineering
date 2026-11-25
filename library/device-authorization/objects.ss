;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; RFC 8628 Device Authorization & Multi-Account Token Binding threat model.
;;; Models device-code expiry/cancellation epoch currency, verification URI safety,
;;; and ticket-to-account Bearer token binding against cross-account confusion.
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export DeviceAuthorizationModel
        CancelledDeviceAdmitCountermodel
        ExpiredDeviceAdmitCountermodel
        CrossAccountTokenBindCountermodel)

(.def (DeviceAuthorizationModel @ AuthorityCurrentnessModel)
  identity: 'threat.device-authorization
  family: 'threat.device-authorization
  quint-module: "device_authorization"
  quint-file: "DeviceAuthorization.qnt"
  domain-dir: "threat/device-authorization"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((device-flow-epoch DEV-FLOW-EPOCH quint)
           (device-code-freshness DEV-CODE-FRESH quint)
           (ticket-account-binding TICKET-ACCT-BIND quint))
  dependencies: '((DEV-FLOW-EPOCH source) (DEV-FLOW-EPOCH profile) (DEV-FLOW-EPOCH method)
                  (DEV-CODE-FRESH source) (DEV-CODE-FRESH profile) (DEV-CODE-FRESH method)
                  (TICKET-ACCT-BIND source) (TICKET-ACCT-BIND profile) (TICKET-ACCT-BIND method))
  invariant: "Device authorization never admits a cancelled or expired flow, and Bearer token attachment strictly binds to the authorized ticket account even across active-account switches."
  parameters: '()
  state: '((flowEpoch "int" "0")
           (deviceActive "bool" "false")
           (deviceExpired "bool" "false")
           (deviceCancelled "bool" "false")
           (pollInFlight "bool" "false")
           (pollStartedEpoch "int" "0")
           (admitted "bool" "false")
           (activeAccount "int" "1")
           (ticketAccount "int" "0")
           (attachedTokenAccount "int" "0")
           (unsafe "bool" "false"))
  guards: '((device-flow-epoch-currency "epochCurrent(h.flowEpoch, h.pollStartedEpoch) and not(h.deviceCancelled)")
            (device-code-freshness "h.deviceActive and not(h.deviceExpired)")
            (ticket-account-binding "h.ticketAccount > 0 and boundAccount == h.ticketAccount"))
  transitions:
  '((beginDeviceFlow "action beginDeviceFlow = if (not(h.deviceActive) and not(h.admitted) and h.flowEpoch < 3)\n    h' = h.with(\"flowEpoch\", h.flowEpoch + 1).with(\"deviceActive\", true).with(\"deviceExpired\", false).with(\"deviceCancelled\", false)\n    else h' = h")
    (startDevicePoll "action startDevicePoll = if (h.deviceActive and not(h.deviceExpired) and not(h.pollInFlight))\n    h' = h.with(\"pollInFlight\", true).with(\"pollStartedEpoch\", h.flowEpoch)\n    else h' = h")
    (expireDeviceCode "action expireDeviceCode = if (h.deviceActive and not(h.deviceExpired))\n    h' = h.with(\"deviceExpired\", true)\n    else h' = h")
    (cancelDeviceFlow "action cancelDeviceFlow = if (h.deviceActive and h.flowEpoch < 3)\n    h' = h.with(\"flowEpoch\", h.flowEpoch + 1).with(\"deviceActive\", false).with(\"deviceCancelled\", true)\n    else h' = h")
    (finishDevicePoll "action finishDevicePoll = if (h.pollInFlight)\n    if (epochCurrent(h.flowEpoch, h.pollStartedEpoch) and h.deviceActive and not(h.deviceExpired) and not(h.deviceCancelled))\n      h' = h.with(\"pollInFlight\", false).with(\"deviceActive\", false).with(\"admitted\", true)\n    else h' = h.with(\"pollInFlight\", false)\n    else h' = h")
    (issueTicketForActive "action issueTicketForActive = h' = h.with(\"ticketAccount\", h.activeAccount).with(\"attachedTokenAccount\", 0)")
    (switchAccount "action switchAccount = h' = h.with(\"activeAccount\", if (h.activeAccount == 1) 2 else 1)")
    (attachBearerForTicket "action attachBearerForTicket = if (h.ticketAccount > 0)\n    h' = h.with(\"attachedTokenAccount\", h.ticketAccount)\n    else h' = h")
    (step "action step = any { beginDeviceFlow, startDevicePoll, expireDeviceCode, cancelDeviceFlow, finishDevicePoll, issueTicketForActive, switchAccount, attachBearerForTicket }"))
  safety: "not(h.unsafe) and (not(h.admitted) or (not(h.deviceCancelled) and not(h.deviceExpired))) and (h.attachedTokenAccount == 0 or h.attachedTokenAccount == h.ticketAccount)"
  traces:
  '((checkSafe "action checkSafe = all { assert(safety), h' = h }")
    (checkUnsafe "action checkUnsafe = all { assert(not(safety)), h' = h }")
    (validDeviceFlowTest "run validDeviceFlowTest = init.then(beginDeviceFlow).then(startDevicePoll).then(finishDevicePoll).then(all { assert(h.admitted), assert(safety), h' = h })")
    (cancelBlocksInFlightPollTest "run cancelBlocksInFlightPollTest = init.then(beginDeviceFlow).then(startDevicePoll).then(cancelDeviceFlow).then(finishDevicePoll).then(all { assert(not(h.admitted)), assert(safety), h' = h })")
    (switchAccountPreservesTicketBindingTest "run switchAccountPreservesTicketBindingTest = init.then(issueTicketForActive).then(switchAccount).then(attachBearerForTicket).then(all { assert(h.attachedTokenAccount == 1), assert(h.activeAccount == 2), assert(safety), h' = h })")
    (crossAccountConfusionCountermodelTest "run crossAccountConfusionCountermodelTest = init.then(issueTicketForActive).then(switchAccount).then(attachBearerFromActive).then(checkUnsafe)"))
  countermodels: (list CancelledDeviceAdmitCountermodel ExpiredDeviceAdmitCountermodel CrossAccountTokenBindCountermodel)
  limits: "Finite RFC 8628 device authorization and two-account binding abstraction; does not model network polling backoff intervals or TLS transport.")

(.def (CancelledDeviceAdmitCountermodel @ DeviceAuthorizationModel)
  identity: 'threat.device-authorization.cancelled-device-admit
  dropped-guard: 'device-flow-epoch-currency
  step-action: "stepCancelledDeviceAdmit"
  counter-action: "action finishDevicePollNoEpoch = if (h.pollInFlight and h.deviceCancelled)\n    h' = h.with(\"pollInFlight\", false).with(\"admitted\", true).with(\"unsafe\", true)\n    else h' = h\n  action stepCancelledDeviceAdmit = any { step, finishDevicePollNoEpoch }"
  expected-itf-predicate: "h.admitted == true and h.deviceCancelled == true")

(.def (ExpiredDeviceAdmitCountermodel @ DeviceAuthorizationModel)
  identity: 'threat.device-authorization.expired-device-admit
  dropped-guard: 'device-code-freshness
  step-action: "stepExpiredDeviceAdmit"
  counter-action: "action finishDevicePollExpired = if (h.pollInFlight and h.deviceExpired)\n    h' = h.with(\"pollInFlight\", false).with(\"admitted\", true).with(\"unsafe\", true)\n    else h' = h\n  action stepExpiredDeviceAdmit = any { step, finishDevicePollExpired }"
  expected-itf-predicate: "h.admitted == true and h.deviceExpired == true")

(.def (CrossAccountTokenBindCountermodel @ DeviceAuthorizationModel)
  identity: 'threat.device-authorization.cross-account-token-bind
  dropped-guard: 'ticket-account-binding
  step-action: "stepCrossAccountBind"
  counter-action: "action attachBearerFromActive = if (h.ticketAccount > 0 and h.activeAccount != h.ticketAccount)\n    h' = h.with(\"attachedTokenAccount\", h.activeAccount).with(\"unsafe\", true)\n    else h' = h\n  action stepCrossAccountBind = any { step, attachBearerFromActive }"
  expected-itf-predicate: "h.attachedTokenAccount > 0 and h.attachedTokenAccount != h.ticketAccount")

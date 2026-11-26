;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; RFC 8628 Device Authorization & Multi-Account Token Binding threat model.
;;; Emergent safety (zero synthetic unsafe flag); all 3 countermodels auto-derived via (guard ...).
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
           (attachedTokenAccount "int" "0"))
  guards: '((device-flow-epoch-currency (and (call epochCurrent (. h flowEpoch) (. h pollStartedEpoch))
                                             (. h deviceActive) (not (. h deviceCancelled))))
            (device-code-freshness (not (. h deviceExpired)))
            (ticket-account-binding (and (> (. h ticketAccount) 0) (= (. h attachedTokenAccount) (. h ticketAccount)))))
  transitions:
  '((beginDeviceFlow
     (action beginDeviceFlow ()
       (if (and (not (. h deviceActive)) (not (. h admitted)) (< (. h flowEpoch) 3))
         (set-h (flowEpoch (+ (. h flowEpoch) 1))
                (deviceActive #t)
                (deviceExpired #f)
                (deviceCancelled #f))
         (keep-h))))
    (startDevicePoll
     (action startDevicePoll ()
       (if (and (. h deviceActive) (not (. h deviceExpired)) (not (. h pollInFlight)))
         (set-h (pollInFlight #t) (pollStartedEpoch (. h flowEpoch)))
         (keep-h))))
    (expireDeviceCode
     (action expireDeviceCode ()
       (if (and (. h deviceActive) (not (. h deviceExpired)))
         (set-h (deviceExpired #t))
         (keep-h))))
    (cancelDeviceFlow
     (action cancelDeviceFlow ()
       (if (and (. h deviceActive) (< (. h flowEpoch) 3))
         (set-h (flowEpoch (+ (. h flowEpoch) 1))
                (deviceActive #f)
                (deviceCancelled #t))
         (keep-h))))
    (finishDevicePoll
     (action finishDevicePoll ()
       (if (. h pollInFlight)
         (if (and (guard device-flow-epoch-currency
                         (and (call epochCurrent (. h flowEpoch) (. h pollStartedEpoch))
                              (. h deviceActive)
                              (not (. h deviceCancelled))))
                  (guard device-code-freshness (not (. h deviceExpired))))
           (set-h (pollInFlight #f) (deviceActive #f) (admitted #t))
           (set-h (pollInFlight #f)))
         (keep-h))))
    (issueTicketForActive
     (action issueTicketForActive ()
       (set-h (ticketAccount (. h activeAccount)) (attachedTokenAccount 0))))
    (switchAccount
     (action switchAccount ()
       (set-h (activeAccount (if (= (. h activeAccount) 1) 2 1)))))
    (attachBearerForTicket
     (action attachBearerForTicket ()
       (if (> (. h ticketAccount) 0)
         (set-h (attachedTokenAccount (guard ticket-account-binding (. h ticketAccount) (. h activeAccount))))
         (keep-h))))
    (step
     (action step ()
       (any beginDeviceFlow startDevicePoll expireDeviceCode cancelDeviceFlow
            finishDevicePoll issueTicketForActive switchAccount attachBearerForTicket))))
  safety:
  '(and (or (not (. h admitted))
            (and (not (. h deviceCancelled)) (not (. h deviceExpired))))
        (or (= (. h attachedTokenAccount) 0)
            (= (. h attachedTokenAccount) (. h ticketAccount))))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (validDeviceFlowTest
     (run validDeviceFlowTest
       (then init beginDeviceFlow startDevicePoll finishDevicePoll
             (all (assert (. h admitted)) (assert safety) (keep-h)))))
    (cancelBlocksInFlightPollTest
     (run cancelBlocksInFlightPollTest
       (then init beginDeviceFlow startDevicePoll cancelDeviceFlow finishDevicePoll
             (all (assert (not (. h admitted))) (assert safety) (keep-h)))))
    (switchAccountPreservesTicketBindingTest
     (run switchAccountPreservesTicketBindingTest
       (then init issueTicketForActive switchAccount attachBearerForTicket
             (all (assert (= (. h attachedTokenAccount) 1))
                  (assert (= (. h activeAccount) 2))
                  (assert safety)
                  (keep-h)))))
    (crossAccountConfusionCountermodelTest
     (run crossAccountConfusionCountermodelTest
       (then init issueTicketForActive switchAccount attachBearerFromActive checkUnsafe))))
  countermodels: (list CancelledDeviceAdmitCountermodel ExpiredDeviceAdmitCountermodel CrossAccountTokenBindCountermodel)
  limits: "Finite RFC 8628 device authorization and two-account binding abstraction; does not model network polling backoff intervals or TLS transport.")

(.def (CancelledDeviceAdmitCountermodel @ DeviceAuthorizationModel)
  identity: 'threat.device-authorization.cancelled-device-admit
  dropped-guard: 'device-flow-epoch-currency
  step-action: "stepCancelledDeviceAdmit"
  derive-from-transition: 'finishDevicePoll
  derive-action-name: 'finishDevicePollNoEpoch
  expected-itf-predicate: "h.admitted == true and h.deviceCancelled == true")

(.def (ExpiredDeviceAdmitCountermodel @ DeviceAuthorizationModel)
  identity: 'threat.device-authorization.expired-device-admit
  dropped-guard: 'device-code-freshness
  step-action: "stepExpiredDeviceAdmit"
  derive-from-transition: 'finishDevicePoll
  derive-action-name: 'finishDevicePollExpired
  expected-itf-predicate: "h.admitted == true and h.deviceExpired == true")

(.def (CrossAccountTokenBindCountermodel @ DeviceAuthorizationModel)
  identity: 'threat.device-authorization.cross-account-token-bind
  dropped-guard: 'ticket-account-binding
  step-action: "stepCrossAccountBind"
  derive-from-transition: 'attachBearerForTicket
  derive-action-name: 'attachBearerFromActive
  expected-itf-predicate: "h.attachedTokenAccount > 0 and h.attachedTokenAccount != h.ticketAccount")

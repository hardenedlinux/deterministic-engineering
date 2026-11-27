;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; RFC 8628 Device Authorization & Multi-Account Token Binding threat model.
;;; Co-located Yuanxu unit: single source of truth alongside DeviceAuthorization.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/packages/quint-models/threat/zero-trust/authority-currentness/objects
                 AuthorityCurrentnessModel))
(export DeviceAuthorizationModel)

(.def (DeviceAuthorizationModel @ AuthorityCurrentnessModel)
  identity: 'threat.identity.device-authorization
  family: 'threat.identity.device-authorization
  title: "RFC 8628 Device Authorization & Multi-Account Token Binding"
  subdomain: 'quint.threat.identity
  papers:
  '(("W. Denniss, J. Bradley, M. Jones & H. Tschofenig (IETF RFC 8628, 2019)"
     "OAuth 2.0 Device Authorization Grant: polling cancellation, expiry, and device-code isolation.")
    ("T. Lodderstedt et al. (IETF RFC 9700, 2025)"
     "Best Current Practice for OAuth 2.0 Security: multi-account token confusion prevention."))
  quint-module: "device_authorization"
  quint-file: "DeviceAuthorization.qnt"
  domain-dir: "threat/identity/device-authorization"
  rules:
  '((device-flow-epoch DEV-FLOW-EPOCH quint)
    (device-code-freshness DEV-CODE-FRESH quint)
    (ticket-account-binding TICKET-ACCT-BIND quint))
  dependencies:
  '((DEV-FLOW-EPOCH source)
    (DEV-FLOW-EPOCH profile)
    (DEV-FLOW-EPOCH method)
    (DEV-CODE-FRESH source)
    (DEV-CODE-FRESH profile)
    (DEV-CODE-FRESH method)
    (TICKET-ACCT-BIND source)
    (TICKET-ACCT-BIND profile)
    (TICKET-ACCT-BIND method))
  invariant: "Device authorization never admits a cancelled or expired flow, and Bearer token attachment strictly binds to the authorized ticket account even across active-account switches."
  limits: "Finite RFC 8628 device authorization and two-account binding abstraction; does not model network polling backoff intervals or TLS transport.")

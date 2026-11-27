;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Adversarial (ADV-L4) outbound HTTP redirect, SSRF, cleartext remote
;;; credential leakage, URL userinfo smuggling, and symlink file-serve
;;; confinement model (SM23, 101st Quint formal model).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export OutboundHttpRedirectSsrfConfinementModel)

(.def (OutboundHttpRedirectSsrfConfinementModel @ ThreatModel.)
  identity: 'threat.protocol.outbound-http-redirect-ssrf-confinement
  family: 'threat.protocol.outbound-http-redirect-ssrf-confinement
  title: "Adversarial (ADV-L4) Outbound HTTP Redirect, SSRF & Credential Exfiltration Confinement"
  subdomain: 'quint.threat.protocol
  papers:
  '(("OWASP SSRF Prevention & CWE-918 / CWE-601"
     "Default HTTP client redirect following silently bypasses initial URL allowlists, downgrades HTTPS to HTTP, and exfiltrates POST bodies or credentials to loopback/cloud-metadata services.")
    ("RFC 9110 Section 15.4 & RFC 6750 Bearer Token Usage"
     "Bearer credentials MUST NOT be transmitted over cleartext HTTP to non-loopback hosts, and 301/302/307/308 redirects must be fail-closed on authenticated or origin-pinned clients.")
    ("CWE-59 / CWE-22 Symlink Following in Static HTTP File Handlers"
     "Static file handlers that validate paths with os.Stat before ServeFile follow symlinks planted inside served directories and leak arbitrary host files."))
  quint-module: "protocol_outbound_http_redirect_ssrf_confinement"
  quint-file: "OutboundHttpRedirectSsrfConfinement.qnt"
  domain-dir: "threat/protocol/outbound-http-redirect-ssrf-confinement"
  rules:
  '((proto-http-no-redirect PROTO-HTTP-NO-REDIRECT quint)
    (proto-http-remote-tls PROTO-HTTP-REMOTE-TLS quint)
    (proto-http-origin-ssrf PROTO-HTTP-ORIGIN-SSRF quint)
    (proto-http-userinfo-lstat PROTO-HTTP-USERINFO-LSTAT quint))
  dependencies:
  '((PROTO-HTTP-NO-REDIRECT source)
    (PROTO-HTTP-NO-REDIRECT profile)
    (PROTO-HTTP-NO-REDIRECT method)
    (PROTO-HTTP-REMOTE-TLS source)
    (PROTO-HTTP-REMOTE-TLS profile)
    (PROTO-HTTP-REMOTE-TLS method)
    (PROTO-HTTP-ORIGIN-SSRF source)
    (PROTO-HTTP-ORIGIN-SSRF profile)
    (PROTO-HTTP-ORIGIN-SSRF method)
    (PROTO-HTTP-USERINFO-LSTAT source)
    (PROTO-HTTP-USERINFO-LSTAT profile)
    (PROTO-HTTP-USERINFO-LSTAT method))
  invariant: "Under ADV-L4 hostile HTTP/redirect/SSRF inputs, authenticated and origin-pinned HTTP clients never follow unchecked redirects (redirectLeaks == 0), never send remote Bearer credentials or downgrade HTTPS endpoints to cleartext HTTP (schemeDowngrades == 0), reject cross-origin/metadata DownloadURL SSRF (ssrfCrossOriginHits == 0), and block URL userinfo smuggling and symlink HTTP file disclosure (userinfoSmuggles == 0 and symlinkServeLeaks == 0)."
  limits: "Finite outbound HTTP request/redirect/download/serve state abstraction (ADV-L4 hostile attack tier); verifies fail-closed no-redirect policy, remote HTTPS credential confinement, DownloadURL origin/scheme confinement, userinfo rejection, and Lstat symlink-safe file serving, not kernel TCP stack or DNS rebinding TTL races.")

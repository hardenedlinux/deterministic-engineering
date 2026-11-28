;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; TLS 1.3 & Noise Protocol 0-RTT Anti-Replay and Forward Secrecy threat model.
;;; Co-located Yuanxu unit: single source of truth alongside Tls13ZeroRttForwardSecrecy.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export Tls13ZeroRttForwardSecrecyModel)

(.def (Tls13ZeroRttForwardSecrecyModel @ ThreatModel.)
  identity: 'threat.protocol.tls13-0rtt-forward-secrecy
  family: 'threat.protocol.tls13-0rtt-forward-secrecy
  title: "TLS 1.3 & Noise Protocol 0-RTT Anti-Replay and Forward Secrecy"
  subdomain: 'quint.threat.protocol
  papers:
  '(("E. Rescorla (IETF RFC 8446, 2018)"
     "The Transport Layer Security (TLS) Protocol Version 1.3: §2.3 0-RTT Early Data and §8 Replay Protection.")
    ("M. Thomson, M. Nottingham & W. Tarreau (IETF RFC 8470, 2018)"
     "Using Early Data in HTTP: idempotency requirements for 0-RTT requests.")
    ("C. Cremers, M. Horvat, J. Hoyland, S. Scott & T. van der Merwe (ACM CCS 2017)"
     "A Comprehensive Symbolic Analysis of TLS 1.3 (Tamarin).")
    ("K. Bhargavan, B. Blanchet & N. Kobeissi (IEEE S&P 2017)"
     "Verified Models and Reference Implementations for the TLS 1.3 Standard Candidate.")
    ("M. Fischlin & F. Günther (IEEE EuroS&P 2017)"
     "Replay Attacks on Zero Round-Trip Time: The Case of the TLS 1.3 Handshake Candidates."))
  quint-module: "tls13_0rtt_forward_secrecy"
  quint-file: "Tls13ZeroRttForwardSecrecy.qnt"
  domain-dir: "threat/protocol/tls13-0rtt-forward-secrecy"
  rules:
  '((reject-non-idempotent-0rtt TLS13-0RTT-IDEMPOTENT quint)
    (cross-edge-strike-sync TLS13-0RTT-STRIKE-SYNC quint)
    (require-ecdhe-pfs TLS13-PFS-ECDHE quint))
  dependencies:
  '((TLS13-0RTT-IDEMPOTENT source)
    (TLS13-0RTT-IDEMPOTENT profile)
    (TLS13-0RTT-IDEMPOTENT method)
    (TLS13-0RTT-STRIKE-SYNC source)
    (TLS13-0RTT-STRIKE-SYNC profile)
    (TLS13-0RTT-STRIKE-SYNC method)
    (TLS13-PFS-ECDHE source)
    (TLS13-PFS-ECDHE profile)
    (TLS13-PFS-ECDHE method))
  invariant: "Non-idempotent operations never execute in 0-RTT, total 0-RTT executions never exceed genuine client transmissions across edge nodes, and later long-term PSK/STEK compromise never recovers previously exchanged confidential secrets."
  limits: "Symbolic Dolev-Yao abstraction of TLS 1.3 / Noise 0-RTT anti-replay across 2 edge nodes and post-compromise forward secrecy; does not model cryptographic key schedule collision bounds, ticket age skew windows, or active MitM downgrade cipher suites.")

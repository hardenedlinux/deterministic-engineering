;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Domain-owned authority currentness predicates; pure reference Quint module.
;;; Co-located Yuanxu unit: single source of truth alongside AuthorityCurrentness.qnt and README.org.
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export AuthorityCurrentnessModel)

(.def (AuthorityCurrentnessModel @ ThreatModel.)
  identity: 'threat.zero-trust.authority-currentness
  family: 'threat.zero-trust.authority-currentness
  title: "Authority Currentness & Writer-Epoch Predicates"
  subdomain: 'quint.threat.zero-trust
  papers:
  '(("S. Rose, O. Borchert, S. Mitchell & S. Connelly (NIST SP 800-207, 2020)"
     "Zero Trust Architecture: continuous per-request verification, credential freshness, and revocation currency.")
    ("M. S. Miller (Johns Hopkins PhD Thesis 2006)"
     "Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control."))
  quint-module: "authority_currentness"
  quint-file: "AuthorityCurrentness.qnt"
  domain-dir: "threat/zero-trust/authority-currentness"
  rules:
  '((authority-currentness AUTH-CURR quint))
  dependencies:
  '((AUTH-CURR source)
    (AUTH-CURR profile)
    (AUTH-CURR method))
  invariant: "Authority is current only while unpaused, fresh, valid credential, intact bytes, and matching writer epoch."
  state:
  '((paused "bool")
    (fresh "bool")
    (credential "bool")
    (bytes "bool")
    (epoch "int")
    (planned "int"))
  guards:
  '((unpaused (not paused))
    (fresh fresh)
    (credential credential)
    (bytes bytes)
    (epoch-match (= epoch planned)))
  transitions:
  '((isCurrent
      (pure-def isCurrent ((paused "bool")
                           (fresh "bool")
                           (credential "bool")
                           (bytes "bool"))
                "bool"
        (and (not paused) fresh credential bytes)))
    (epochCurrent
      (pure-def epochCurrent ((epoch "int") (planned "int"))
                "bool"
        (= epoch planned))))
  safety: #t
  traces:
  '((currentnessTest
      (run currentnessTest
        (all (assert (call isCurrent #f #t #t #t))
             (assert (not (call isCurrent #t #t #t #t)))
             (assert (not (call isCurrent #f #f #t #t)))
             (assert (not (call isCurrent #f #t #f #t)))
             (assert (not (call isCurrent #f #t #t #f)))
             (assert (call epochCurrent 0 0))
             (assert (not (call epochCurrent 1 0)))))))
  countermodels: '()
  parameters: '()
  limits: "Trusted boolean bits abstract real clock freshness, revocation checks, signature verification and writer fencing.")

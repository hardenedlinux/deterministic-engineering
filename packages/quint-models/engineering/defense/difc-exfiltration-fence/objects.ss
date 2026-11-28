;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Business Extension B7 (10.164): Decentralized Information Flow Control (DIFC),
;;; CaMeL Control-Flow Integrity, and Exfiltration Confinement for Tool-Calling Agents.
;;; Proves three non-interference & integrity invariants against indirect prompt injection:
;;;   1. No-Write-Down Confidentiality: secret-tainted data can never flow into a public
;;;      tool sink without audited declassification (exfiltrationViolations == 0).
;;;   2. CaMeL Control-Flow Integrity: untrusted external inputs can never dictate tool
;;;      control targets (URLs, recipients, shell commands) (controlHijackViolations == 0).
;;;   3. Audited M3 Declassification: secret taint can only be cleared when BOTH an explicit
;;;      M3 declassification capability AND a deterministic redaction sanitizer pass
;;;      (unauthorizedDeclassViolations == 0).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export DifcExfiltrationFenceModel)

(.def (DifcExfiltrationFenceModel @ ThreatModel.)
  identity: 'engineering.defense.difc-exfiltration-fence
  family: 'engineering.defense.difc-exfiltration-fence
  title: "DIFC Taint Confinement, CaMeL Control-Flow Integrity & Audited Declassification"
  subdomain: 'quint.engineering.defense
  papers:
  '(("A. C. Myers & B. Liskov (ACM SOSP 1997) / N. Zeldovich et al. (OSDI 2006)"
     "Decentralized Information Flow Control (DIFC) & HiStar explicit declassification capabilities.")
    ("E. Debenedetti et al. (Google DeepMind 2025)"
     "Defeating Prompt Injections by Design (CaMeL): separating control flow from untrusted data flow.")
    ("Deterministic Engineering (10.156 / 10.164)"
     "Immutable M1 dual-lattice taint envelopes paired with non-serializable M3 declassification capabilities."))
  quint-module: "difc_exfiltration_fence"
  quint-file: "DifcExfiltrationFence.qnt"
  domain-dir: "engineering/defense/difc-exfiltration-fence"
  rules:
  '((difc-fence-safe DE-DIFC-SAFE quint)
    (difc-fence-countermodel DE-DIFC-COUNTER quint))
  dependencies:
  '((DE-DIFC-SAFE source)
    (DE-DIFC-SAFE profile)
    (DE-DIFC-SAFE method)
    (DE-DIFC-COUNTER source)
    (DE-DIFC-COUNTER profile)
    (DE-DIFC-COUNTER method))
  invariant: "No secret-tainted payload flows to a public sink (exfiltrationViolations == 0), no untrusted external input hijacks tool control flow (controlHijackViolations == 0), and no declassification bypasses explicit M3 capability or deterministic redaction sanitization (unauthorizedDeclassViolations == 0)."
  limits: "Finite single-value confidentiality/integrity lattice and declassification abstraction; does not model timing/length covert channels, steganographic encoding inside allowed public fields, or hardware side channels.")

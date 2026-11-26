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
(export DifcExfiltrationFenceModel
        SecretExfiltrationCountermodel
        ControlHijackCountermodel
        UnauthorizedDeclassCountermodel)

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
  verify-depth: 10
  countermodel-depth: 6
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
  parameters: '()
  state:
  '((secretRead "bool" "false")
    (untrustedInputRead "bool" "false")
    (valueTaintedSecret "bool" "false")
    (controlTaintedUntrusted "bool" "false")
    (hasDeclassCap "bool" "false")
    (sanitizerPassed "bool" "false")
    (declassifiedClean "bool" "false")
    (exfiltrationViolations "int" "0")
    (controlHijackViolations "int" "0")
    (unauthorizedDeclassViolations "int" "0")
    (safePublicSinks "int" "0"))
  guards:
  '((forbid-secret-to-public-sink (not (. h valueTaintedSecret)))
    (forbid-untrusted-control-flow (not (. h controlTaintedUntrusted)))
    (require-cap-and-sanitizer-for-declassify (and (. h hasDeclassCap) (. h sanitizerPassed))))
  transitions:
  '((readSecretSource
      (action readSecretSource ()
        (if (not (. h secretRead))
          (set-h (secretRead #t) (valueTaintedSecret #t))
          (keep-h))))
    (readUntrustedWeb
      (action readUntrustedWeb ()
        (if (not (. h untrustedInputRead))
          (set-h (untrustedInputRead #t) (controlTaintedUntrusted #t))
          (keep-h))))
    (grantDeclassCap
      (action grantDeclassCap ()
        (if (not (. h hasDeclassCap))
          (set-h (hasDeclassCap #t))
          (keep-h))))
    (runDeterministicSanitizer
      (action runDeterministicSanitizer ()
        (if (and (. h valueTaintedSecret) (not (. h sanitizerPassed)))
          (set-h (sanitizerPassed #t))
          (keep-h))))
    (useTrustedControlTarget
      (action useTrustedControlTarget ()
        (if (. h controlTaintedUntrusted)
          (set-h (controlTaintedUntrusted #f))
          (keep-h))))
    (declassifyValue
      (action declassifyValue ()
        (if (and (. h valueTaintedSecret)
                 (not (. h declassifiedClean))
                 (guard require-cap-and-sanitizer-for-declassify
                   (and (. h hasDeclassCap) (. h sanitizerPassed))))
          (set-h (declassifiedClean #t)
                 (valueTaintedSecret #f)
                 (unauthorizedDeclassViolations
                   (if (and (. h hasDeclassCap) (. h sanitizerPassed))
                     (. h unauthorizedDeclassViolations)
                     (+ (. h unauthorizedDeclassViolations) 1))))
          (keep-h))))
    (emitToPublicSink
      (action emitToPublicSink ()
        (if (and (guard forbid-secret-to-public-sink (not (. h valueTaintedSecret)))
                 (guard forbid-untrusted-control-flow (not (. h controlTaintedUntrusted))))
          (set-h (safePublicSinks (+ (. h safePublicSinks) 1))
                 (exfiltrationViolations
                   (if (not (. h valueTaintedSecret))
                     (. h exfiltrationViolations)
                     (+ (. h exfiltrationViolations) 1)))
                 (controlHijackViolations
                   (if (not (. h controlTaintedUntrusted))
                     (. h controlHijackViolations)
                     (+ (. h controlHijackViolations) 1))))
          (keep-h))))
    (step
      (action step ()
        (any readSecretSource readUntrustedWeb grantDeclassCap runDeterministicSanitizer
             useTrustedControlTarget declassifyValue emitToPublicSink))))
  safety:
  '(and (= (. h exfiltrationViolations) 0)
        (= (. h controlHijackViolations) 0)
        (= (. h unauthorizedDeclassViolations) 0))
  traces:
  '((auditedDeclassAndSafePublicEmitTest
      (run auditedDeclassAndSafePublicEmitTest
        (then init readSecretSource readUntrustedWeb grantDeclassCap
              runDeterministicSanitizer declassifyValue useTrustedControlTarget emitToPublicSink
              (all (assert safety)
                   (assert (= (. h safePublicSinks) 1))
                   (assert (. h declassifiedClean))
                   (keep-h)))))
    (secretExfiltrationViolatesSafetyTest
      (run secretExfiltrationViolatesSafetyTest
        (then init readSecretSource emitExfiltrating
              (all (assert (not safety))
                   (assert (> (. h exfiltrationViolations) 0))
                   (keep-h)))))
    (controlHijackViolatesSafetyTest
      (run controlHijackViolatesSafetyTest
        (then init readUntrustedWeb emitHijackedControl
              (all (assert (not safety))
                   (assert (> (. h controlHijackViolations) 0))
                   (keep-h)))))
    (unauthorizedDeclassViolatesSafetyTest
      (run unauthorizedDeclassViolatesSafetyTest
        (then init readSecretSource declassifyUnauthorized
              (all (assert (not safety))
                   (assert (> (. h unauthorizedDeclassViolations) 0))
                   (keep-h))))))
  countermodels:
  (list SecretExfiltrationCountermodel
        ControlHijackCountermodel
        UnauthorizedDeclassCountermodel)
  limits: "Finite single-value confidentiality/integrity lattice and declassification abstraction; does not model timing/length covert channels, steganographic encoding inside allowed public fields, or hardware side channels.")

(.def (SecretExfiltrationCountermodel @ DifcExfiltrationFenceModel)
  identity: 'engineering.defense.difc-exfiltration-fence.secret-exfiltration
  dropped-guard: 'forbid-secret-to-public-sink
  step-action: "stepSecretExfiltration"
  derive-from-transition: 'emitToPublicSink
  derive-action-name: 'emitExfiltrating
  expected-itf-predicate: "h.exfiltrationViolations > 0")

(.def (ControlHijackCountermodel @ DifcExfiltrationFenceModel)
  identity: 'engineering.defense.difc-exfiltration-fence.control-hijack
  dropped-guard: 'forbid-untrusted-control-flow
  step-action: "stepControlHijack"
  derive-from-transition: 'emitToPublicSink
  derive-action-name: 'emitHijackedControl
  expected-itf-predicate: "h.controlHijackViolations > 0")

(.def (UnauthorizedDeclassCountermodel @ DifcExfiltrationFenceModel)
  identity: 'engineering.defense.difc-exfiltration-fence.unauthorized-declass
  dropped-guard: 'require-cap-and-sanitizer-for-declassify
  step-action: "stepUnauthorizedDeclass"
  derive-from-transition: 'declassifyValue
  derive-action-name: 'declassifyUnauthorized
  expected-itf-predicate: "h.unauthorizedDeclassViolations > 0")

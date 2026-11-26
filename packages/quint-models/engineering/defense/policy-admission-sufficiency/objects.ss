;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; F2 / G3: Evidence sufficiency vs. policy-required direct boundary records and method admission
;;; (20.17 HA/AH & 20.18 OP/BR/AM / 10.153).
;;; Proves:
;;;   1. When policy does not demand a direct boundary record, sufficient existing history qualifies
;;;      without inventing redundant receipt formats (anti-P3/P4 bloat).
;;;   2. When authentic policy requires a direct record (BR01) or closed method admission (AM01/AM02),
;;;      history-only or unadmitted bindings cannot silently qualify (anti-P1 weakening).
;;;   3. Refusing an unadmitted or forbidden association preserves authentic original method bytes (AM02).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export PolicyAdmissionSufficiencyModel
        BypassDirectRecordCountermodel
        UnadmittedMethodCountermodel
        PurgeMethodOnRefusalCountermodel)

(.def (PolicyAdmissionSufficiencyModel @ ThreatModel.)
  identity: 'engineering.defense.policy-admission-sufficiency
  family: 'engineering.defense.policy-admission-sufficiency
  title: "Evidence Sufficiency vs. Policy-Required Checks & Method Admission (20.17-20.18)"
  subdomain: 'quint.engineering.defense
  papers:
  '(("Deterministic Engineering (20.17 HA/AH & 20.18 OP/BR/AM)"
     "Sufficient existing evidence stops redundant format demands, while authentic mandatory policy clauses and method admission mappings remain strictly enforced.")
    ("Deterministic Engineering (10.153)"
     "G3 Monotonic governance floor vs. M1 sufficiency stopping."))
  quint-module: "policy_admission_sufficiency"
  quint-file: "PolicyAdmissionSufficiency.qnt"
  domain-dir: "engineering/defense/policy-admission-sufficiency"
  verify-depth: 10
  countermodel-depth: 6
  rules:
  '((policy-sufficiency-safe DE-POL-SAFE quint)
    (policy-sufficiency-countermodel DE-POL-COUNTER quint))
  dependencies:
  '((DE-POL-SAFE source)
    (DE-POL-SAFE profile)
    (DE-POL-SAFE method)
    (DE-POL-COUNTER source)
    (DE-POL-COUNTER profile)
    (DE-POL-COUNTER method))
  invariant: "Refusing an offered binding never deletes authentic original method bytes; a policy-qualified verdict always has sufficient underlying history, an admitted method mapping (status == 1), and a direct boundary record whenever authentic policy requires one."
  parameters: '()
  state:
  '((historySufficient "bool" "false")
    (policyRequiresDirectRecord "bool" "false")
    (directRecordPresent "bool" "false")
    (methodAdmissionStatus "int" "0")
    (verdictQualified "bool" "false")
    (methodPreserved "bool" "true"))
  guards:
  '((enforce-policy-direct-record
      (or (not (. h policyRequiresDirectRecord)) (. h directRecordPresent)))
    (require-admitted-method-mapping
      (= (. h methodAdmissionStatus) 1))
    (preserve-authentic-method-on-refusal
      (. h methodPreserved)))
  transitions:
  '((supplySufficientHistory
      (action supplySufficientHistory ()
        (if (not (. h historySufficient))
          (set-h (historySufficient #t))
          (keep-h))))
    (requireDirectRecordPolicy
      (action requireDirectRecordPolicy ()
        (if (and (not (. h policyRequiresDirectRecord)) (not (. h verdictQualified)))
          (set-h (policyRequiresDirectRecord #t))
          (keep-h))))
    (supplyDirectRecord
      (action supplyDirectRecord ()
        (if (not (. h directRecordPresent))
          (set-h (directRecordPresent #t))
          (keep-h))))
    (admitMethodMapping
      (action admitMethodMapping ()
        (if (= (. h methodAdmissionStatus) 0)
          (set-h (methodAdmissionStatus 1))
          (keep-h))))
    (forbidMethodMapping
      (action forbidMethodMapping ()
        (if (= (. h methodAdmissionStatus) 0)
          (set-h (methodAdmissionStatus 2))
          (keep-h))))
    (refuseUnadmittedBinding
      (action refuseUnadmittedBinding ()
        (if (= (. h methodAdmissionStatus) 2)
          (set-h (methodPreserved (guard preserve-authentic-method-on-refusal
                                         (. h methodPreserved)
                                         #f)))
          (keep-h))))
    (qualifyVerdict
      (action qualifyVerdict ()
        (if (and (. h historySufficient)
                 (guard enforce-policy-direct-record
                        (or (not (. h policyRequiresDirectRecord)) (. h directRecordPresent)))
                 (guard require-admitted-method-mapping
                        (= (. h methodAdmissionStatus) 1)))
          (set-h (verdictQualified #t))
          (keep-h))))
    (step
      (action step ()
        (any supplySufficientHistory
             requireDirectRecordPolicy
             supplyDirectRecord
             admitMethodMapping
             forbidMethodMapping
             refuseUnadmittedBinding
             qualifyVerdict))))
  safety:
  '(and (. h methodPreserved)
        (or (not (. h verdictQualified)) (. h historySufficient))
        (or (not (. h verdictQualified))
            (not (. h policyRequiresDirectRecord))
            (. h directRecordPresent))
        (or (not (. h verdictQualified))
            (= (. h methodAdmissionStatus) 1)))
  traces:
  '((sufficientHistoryWithoutDirectPolicyTest
      (run sufficientHistoryWithoutDirectPolicyTest
        (then init supplySufficientHistory admitMethodMapping qualifyVerdict
              (all (assert safety)
                   (assert (. h verdictQualified))
                   (assert (not (. h directRecordPresent)))
                   (keep-h)))))
    (strictPolicyNeedsDirectRecordTest
      (run strictPolicyNeedsDirectRecordTest
        (then init supplySufficientHistory requireDirectRecordPolicy admitMethodMapping qualifyVerdict
              (all (assert safety)
                   (assert (not (. h verdictQualified)))
                   (keep-h))
              supplyDirectRecord qualifyVerdict
              (all (assert safety)
                   (assert (. h verdictQualified))
                   (keep-h)))))
    (bypassDirectRecordCountermodelTest
      (run bypassDirectRecordCountermodelTest
        (then init supplySufficientHistory requireDirectRecordPolicy admitMethodMapping qualifyWithoutDirectRecord
              (all (assert (not safety))
                   (assert (. h verdictQualified))
                   (assert (. h policyRequiresDirectRecord))
                   (assert (not (. h directRecordPresent)))
                   (keep-h)))))
    (unadmittedMethodCountermodelTest
      (run unadmittedMethodCountermodelTest
        (then init supplySufficientHistory qualifyWithoutAdmittedMethod
              (all (assert (not safety))
                   (assert (. h verdictQualified))
                   (assert (!= (. h methodAdmissionStatus) 1))
                   (keep-h)))))
    (purgeMethodOnRefusalCountermodelTest
      (run purgeMethodOnRefusalCountermodelTest
        (then init forbidMethodMapping refuseAndPurgeMethod
              (all (assert (not safety))
                   (assert (not (. h methodPreserved)))
                   (keep-h))))))
  countermodels:
  (list BypassDirectRecordCountermodel
        UnadmittedMethodCountermodel
        PurgeMethodOnRefusalCountermodel)
  limits: "Finite single-verdict policy-admission and sufficiency abstraction (methodAdmissionStatus: 0=unknown, 1=admitted, 2=forbidden); does not model multi-tenant delegation chains or cryptographic receipt verification.")

(.def (BypassDirectRecordCountermodel @ PolicyAdmissionSufficiencyModel)
  identity: 'engineering.defense.policy-admission-sufficiency.bypass-direct-record
  dropped-guard: 'enforce-policy-direct-record
  step-action: "stepBypassDirectRecord"
  derive-from-transition: 'qualifyVerdict
  derive-action-name: 'qualifyWithoutDirectRecord
  expected-itf-predicate: "h.verdictQualified == true and h.policyRequiresDirectRecord == true and h.directRecordPresent == false")

(.def (UnadmittedMethodCountermodel @ PolicyAdmissionSufficiencyModel)
  identity: 'engineering.defense.policy-admission-sufficiency.unadmitted-method
  dropped-guard: 'require-admitted-method-mapping
  step-action: "stepUnadmittedMethod"
  derive-from-transition: 'qualifyVerdict
  derive-action-name: 'qualifyWithoutAdmittedMethod
  expected-itf-predicate: "h.verdictQualified == true and h.methodAdmissionStatus != 1")

(.def (PurgeMethodOnRefusalCountermodel @ PolicyAdmissionSufficiencyModel)
  identity: 'engineering.defense.policy-admission-sufficiency.purge-method-on-refusal
  dropped-guard: 'preserve-authentic-method-on-refusal
  step-action: "stepPurgeMethodOnRefusal"
  derive-from-transition: 'refuseUnadmittedBinding
  derive-action-name: 'refuseAndPurgeMethod
  expected-itf-predicate: "h.methodPreserved == false")

;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Zero Trust short-lived workload identity (SVID) rotation and emergency revocation.
;;; Models overlap-window rotation vs. immediate revocation precedence with emergent safety.
(import :clan/poo/object
        (only-in "../authority-currentness/objects.ss" AuthorityCurrentnessModel))
(export WorkloadIdentityRotationModel GraceWindowRevokedCountermodel)

(.def (WorkloadIdentityRotationModel @ AuthorityCurrentnessModel)
  identity: 'threat.workload-identity-rotation
  family: 'threat.workload-identity-rotation
  quint-module: "workload_identity_rotation"
  quint-file: "WorkloadIdentityRotation.qnt"
  domain-dir: "threat/workload-identity-rotation"
  quint-imports: '(("authority_currentness" "../authority-currentness/AuthorityCurrentness"))
  rules: '((zt-svid-rotate ZT-SVID-ROT quint)
           (zt-svid-revoked-grace ZT-SVID-GRACE quint))
  dependencies: '((ZT-SVID-ROT source) (ZT-SVID-ROT profile) (ZT-SVID-ROT method)
                  (ZT-SVID-GRACE source) (ZT-SVID-GRACE profile) (ZT-SVID-GRACE method))
  invariant: "Emergency revocation overrides any overlap/TTL window; no active workload session runs on a revoked or expired credential generation."
  parameters: '()
  state: '((activeGen "int" "1")
           (overlapGen "int" "0")
           (revokedGen "int" "0")
           (credGen "int" "1")
           (credExpired "bool" "false")
           (accepted "int" "0")
           (sessionActive "bool" "false")
           (sessionGen "int" "0")
           (sessionExpired "bool" "false"))
  guards: '((revocation-overrides-overlap (!= (. h credGen) (. h revokedGen)))
            (valid-generation (or (= (. h credGen) (. h activeGen))
                                  (and (> (. h overlapGen) 0) (= (. h credGen) (. h overlapGen))))))
  transitions:
  '((inWindow
     (val inWindow
       (and (not (. h credExpired))
            (or (= (. h credGen) (. h activeGen))
                (and (> (. h overlapGen) 0) (= (. h credGen) (. h overlapGen)))))))
    (rotateStart
     (action rotateStart ()
       (if (and (= (. h overlapGen) 0) (< (. h activeGen) 3))
         (set-h (overlapGen (. h activeGen))
                (activeGen (+ (. h activeGen) 1)))
         (keep-h))))
    (retireOverlap
     (action retireOverlap ()
       (if (> (. h overlapGen) 0)
         (set-h (overlapGen 0))
         (keep-h))))
    (renewWorkloadCred
     (action renewWorkloadCred ()
       (set-h (credGen (. h activeGen)) (credExpired #f))))
    (expireCred
     (action expireCred ()
       (set-h (credExpired #t)
              (sessionActive (if (= (. h sessionGen) (. h credGen)) #f (. h sessionActive))))))
    (emergencyRevoke
     (action emergencyRevoke ()
       (set-h (revokedGen (. h credGen))
              (sessionActive (if (= (. h sessionGen) (. h credGen)) #f (. h sessionActive))))))
    (authenticate
     (action authenticate ()
       (if (and (guard valid-generation inWindow)
                (guard revocation-overrides-overlap (!= (. h credGen) (. h revokedGen))))
         (set-h (accepted (+ (. h accepted) 1))
                (sessionActive #t)
                (sessionGen (. h credGen))
                (sessionExpired (. h credExpired)))
         (keep-h))))
    (step
     (action step ()
       (any rotateStart retireOverlap renewWorkloadCred expireCred emergencyRevoke authenticate))))
  safety:
  '(or (not (. h sessionActive))
       (and (!= (. h sessionGen) (. h revokedGen))
            (not (. h sessionExpired))))
  traces:
  '((checkSafe (action checkSafe () (all (assert safety) (keep-h))))
    (checkBlocked (action checkBlocked () (all (assert (= (. h accepted) 0)) (assert safety) (keep-h))))
    (checkUnsafe (action checkUnsafe () (all (assert (not safety)) (keep-h))))
    (overlapRotationTest
     (run overlapRotationTest
       (then init rotateStart authenticate
             (all (assert (= (. h accepted) 1)) (assert (. h sessionActive)) (assert safety) (keep-h)))))
    (retireBlocksOldCredTest
     (run retireBlocksOldCredTest
       (then init rotateStart retireOverlap authenticate checkBlocked)))
    (revocationOverridesOverlapTest
     (run revocationOverridesOverlapTest
       (then init rotateStart emergencyRevoke authenticate checkBlocked)))
    (revokedGraceCountermodelTest
     (run revokedGraceCountermodelTest
       (then init rotateStart emergencyRevoke authIgnoreRevocation checkUnsafe))))
  countermodels: (list GraceWindowRevokedCountermodel)
  limits: "Finite SVID generation-rotation abstraction; does not model X.509/JWT cryptography, clock drift, or CRL/OCSP transport latency.")

;; Weakened descendant: acceptor trusts TTL/overlap window without checking revocation list.
(.def (GraceWindowRevokedCountermodel @ WorkloadIdentityRotationModel)
  identity: 'threat.workload-identity-rotation.revoked-in-grace-window
  dropped-guard: 'revocation-overrides-overlap
  step-action: "stepGraceWindowReuse"
  derive-from-transition: 'authenticate
  derive-action-name: 'authIgnoreRevocation
  expected-itf-predicate: "h.sessionActive == true and h.sessionGen == h.revokedGen")

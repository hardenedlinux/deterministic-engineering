;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Adversarial (ADV-L4) control-plane entrypoint authentication convergence,
;;; mutating RPC Emergency-Stop governance confinement, empty-Bearer prefix
;;; rejection, and release-gate shell secret scrubbing (SM26, 104th Quint model).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export ControlPlaneAuthAndGovernanceConfinementModel)

(.def (ControlPlaneAuthAndGovernanceConfinementModel @ ThreatModel.)
  identity: 'threat.execution.control-plane-auth-and-governance-confinement
  family: 'threat.execution.control-plane-auth-and-governance-confinement
  title: "Adversarial (ADV-L4) Control-Plane Entrypoint Auth & E-Stop Governance Confinement"
  subdomain: 'quint.threat.execution
  papers:
  '(("Saltzer & Schroeder (1975) Fail-Safe Defaults & Complete Mediation"
     "Every production binary entrypoint must bind through one canonical constant-time, non-empty Bearer authenticator and refuse non-loopback wildcard binds with default or blank credentials; shadow binary-local auth helpers negate library hardening.")
    ("CWE-208 / CWE-287 / CWE-798 & Empty-Scheme Prefix Confusion"
     "Validating !header.trim().is_empty() on 'Bearer ' admits an empty credential because the scheme prefix itself is non-empty; authenticators must parse and verify a non-blank credential payload in constant time.")
    ("AI Defensive Programming Anti-Pattern: Surface-Scoped Defense Illusion (Real-Repo Marlin Case)"
     "Hardening library helpers and atomic executors while leaving production host binaries (marlin_mygo_host.rs), mutating gRPC RPCs (ui_grpc.rs, grpc.rs), and release-gate shells (release.rs sh -lc) unmediated creates live E-Stop bypasses and secret exfiltration."))
  quint-module: "execution_control_plane_auth_and_governance_confinement"
  quint-file: "ControlPlaneAuthAndGovernanceConfinement.qnt"
  domain-dir: "threat/execution/control-plane-auth-and-governance-confinement"
  rules:
  '((exec-cp-canonical-ct-auth EXEC-CP-CANONICAL-CT-AUTH quint)
    (exec-cp-rpc-estop-enforced EXEC-CP-RPC-ESTOP-ENFORCED quint)
    (exec-cp-release-shell-scrubbed EXEC-CP-RELEASE-SHELL-SCRUBBED quint)
    (exec-cp-bearer-payload-nonempty EXEC-CP-BEARER-PAYLOAD-NONEMPTY quint))
  dependencies:
  '((EXEC-CP-CANONICAL-CT-AUTH source)
    (EXEC-CP-CANONICAL-CT-AUTH profile)
    (EXEC-CP-CANONICAL-CT-AUTH method)
    (EXEC-CP-RPC-ESTOP-ENFORCED source)
    (EXEC-CP-RPC-ESTOP-ENFORCED profile)
    (EXEC-CP-RPC-ESTOP-ENFORCED method)
    (EXEC-CP-RELEASE-SHELL-SCRUBBED source)
    (EXEC-CP-RELEASE-SHELL-SCRUBBED profile)
    (EXEC-CP-RELEASE-SHELL-SCRUBBED method)
    (EXEC-CP-BEARER-PAYLOAD-NONEMPTY source)
    (EXEC-CP-BEARER-PAYLOAD-NONEMPTY profile)
    (EXEC-CP-BEARER-PAYLOAD-NONEMPTY method))
  invariant: "Under ADV-L4 hostile control-plane probes, every binary entrypoint delegates to canonical constant-time non-empty Bearer auth refusing blank credentials and non-loopback default tokens (shadowAuthBypasses == 0 and emptyBearerBypasses == 0), every mutating or LLM-streaming gRPC RPC fails closed while Operator E-Stop is active (controlPlaneEstopBypasses == 0), and release-gate subprocesses execute without login-shell profile loading or inherited host credentials under strict output/timeout bounds (releaseShellSecretLeaks == 0)."
  limits: "Finite control-plane entrypoint auth, mutating RPC E-Stop governance confinement, empty-Bearer credential rejection, and release-gate shell secret scrubbing abstraction (ADV-L4 hostile attack tier); proves every production binary entrypoint and mutating RPC enforces canonical constant-time non-empty Bearer auth and fail-closed E-Stop mediation, not arbitrary OS kernel bypasses.")

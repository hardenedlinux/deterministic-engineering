;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; Adversarial (ADV-L4) ambient secret environment scrubbing for untrusted
;;; agent tool & plugin-build subprocesses plus constant-time Bearer token
;;; verification and fail-closed blank-secret refusal (SM24, 102nd Quint model).
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export SubprocessEnvScrubAndAuthTimingModel)

(.def (SubprocessEnvScrubAndAuthTimingModel @ ThreatModel.)
  identity: 'threat.execution.subprocess-env-scrub-and-auth-timing
  family: 'threat.execution.subprocess-env-scrub-and-auth-timing
  title: "Adversarial (ADV-L4) Subprocess Secret Environment Scrubbing & Constant-Time Auth Verification"
  subdomain: 'quint.threat.execution
  papers:
  '(("CWE-526 / CWE-200 Exposure of Sensitive Information Through Environmental Variables"
     "Spawning untrusted AI tool or plugin-build subprocesses with inherited os.Environ()/std::env::vars() leaks LLM API keys, cloud credentials, and bridge tokens directly to child code.")
    ("Miller (2006) Robust Composition & Principle of Least Authority (POLA)"
     "Untrusted child processes MUST start from an empty environment populated strictly via an explicit safe-toolchain allowlist (default-deny) with null stdin isolation.")
    ("CWE-208 Observable Timing Discrepancy & RFC 6750 Bearer Token Verification"
     "Short-circuit string equality (`==`) on Bearer authorization headers leaks token prefix timing side channels and fails open on blank expected tokens unless constant-time full-length comparison and non-empty guards are enforced."))
  quint-module: "execution_subprocess_env_scrub_and_auth_timing"
  quint-file: "SubprocessEnvScrubAndAuthTiming.qnt"
  domain-dir: "threat/execution/subprocess-env-scrub-and-auth-timing"
  rules:
  '((exec-env-scrub-sandbox EXEC-ENV-SCRUB-SANDBOX quint)
    (exec-env-scrub-plugin-build EXEC-ENV-SCRUB-PLUGIN-BUILD quint)
    (exec-auth-constant-time EXEC-AUTH-CONSTANT-TIME quint)
    (exec-auth-reject-blank-stdin EXEC-AUTH-REJECT-BLANK-STDIN quint))
  dependencies:
  '((EXEC-ENV-SCRUB-SANDBOX source)
    (EXEC-ENV-SCRUB-SANDBOX profile)
    (EXEC-ENV-SCRUB-SANDBOX method)
    (EXEC-ENV-SCRUB-PLUGIN-BUILD source)
    (EXEC-ENV-SCRUB-PLUGIN-BUILD profile)
    (EXEC-ENV-SCRUB-PLUGIN-BUILD method)
    (EXEC-AUTH-CONSTANT-TIME source)
    (EXEC-AUTH-CONSTANT-TIME profile)
    (EXEC-AUTH-CONSTANT-TIME method)
    (EXEC-AUTH-REJECT-BLANK-STDIN source)
    (EXEC-AUTH-REJECT-BLANK-STDIN profile)
    (EXEC-AUTH-REJECT-BLANK-STDIN method))
  invariant: "Under ADV-L4 hostile agent tools and untrusted plugins, sandboxed tool and plugin-build subprocesses never inherit ambient secret environment variables (sandboxSecretLeaks == 0 and pluginSecretLeaks == 0), gRPC/HTTP Bearer token checks execute in constant time without short-circuit timing oracles (authTimingOracles == 0), and blank expected auth headers or ambient stdin inheritance are rejected fail-closed (blankAuthBypasses == 0)."
  limits: "Finite subprocess environment allowlist, plugin build sandbox, and constant-time bearer auth state abstraction (ADV-L4 hostile attack tier); verifies zero ambient secret inheritance into sandbox/plugin subprocesses, constant-time bearer verification, and fail-closed blank-token refusal, not hardware microarchitectural cache-line side channels.")

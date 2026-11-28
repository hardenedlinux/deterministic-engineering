;; SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
;; SPDX-License-Identifier: LGPL-2.1-or-later

;;; SM40 (ADV-L4): ASP HTTP Patch Confinement, Loopback Transport Integrity,
;;; Circular Schema Anti-DoS & Search-Index Cache/Queue Isolation.
;;; Formalizes four real ADV-L4 boundary defects discovered in
;;; marlin-agent-search-engine:
;;;  1. asp_http_client/patch_client.rs: apply_ast_patch_via_asp_http joined
;;;     untrusted request.path directly onto workspace_root without traversal,
;;;     absolute-path, or symlink checks and read files unboundedly via
;;;     fs::read_to_string, allowing arbitrary host file read and overwrite.
;;;  2. asp_http_client/{domain_types,transport}.rs: AspForwardingEndpoint::new
;;;     admitted @-userinfo/port-0/CRLF endpoints, with_control_token and
;;;     HttpEndpointPath::new admitted CRLF HTTP header injection and request
;;;     smuggling, decode_http_body suffered checked-arithmetic-free pos + size
;;;     integer overflow panic on crafted chunked sizes, and http_loopback_request
;;;     silently truncated responses exceeding MAX_HTTP_RESPONSE_BYTES.
;;;  3. asp_http_client/domain_types.rs: TargetedJsonSchemaDocument::resolve_schema_node
;;;     recursed infinitely on circular JSON Schema $ref pointers causing stack
;;;     overflow crashes.
;;;  4. engine.rs, open_edb_hydrator.rs & edb_bridge/runner.rs: snapshot and
;;;     Open EDB cache paths followed symlinks and staged temp files via
;;;     File::create without create_new/O_NOFOLLOW/dir fsync, projectMarkers
;;;     accepted traversal segments, and package_search_dsl_worker used an
;;;     unbounded mpsc::channel().
(import :clan/poo/object
        (only-in :deterministic-engineering/library/quint-methods/objects ThreatModel.))
(export AspPatchTransportSchemaCacheConfinementModel)

(.def (AspPatchTransportSchemaCacheConfinementModel @ ThreatModel.)
  identity: 'threat.execution.asp-patch-transport-schema-cache-confinement
  family: 'threat.execution.asp-patch-transport-schema-cache-confinement
  title: "ASP HTTP Patch, Loopback Transport, Schema & Search Cache Confinement (SM40)"
  subdomain: 'quint.threat.execution
  papers:
  '(("Deterministic Engineering (30.06 / 40.05)"
     "SM40 ADV-L4 workspace-confined non-symlink bounded AST patch execution, strict loopback HTTP/1.1 endpoint validation with CRLF-free tokens/paths and checked chunked-response bounds, cycle-bounded JSON Schema $ref resolution, and non-symlink snapshot/cache persistence with bounded Search DSL worker queues.")
    ("Marlin Agent Core Empirical Case Study (2026)"
     "marlin-agent-search-engine apply_ast_patch_via_asp_http joined untrusted relative/absolute/symlink paths onto workspace_root enabling arbitrary file read and overwrite, AspForwardingEndpoint::new and HttpEndpointPath::new admitted @-userinfo SSRF and CRLF header smuggling while decode_http_body panicked on pos + size chunk overflow and silently truncated oversize bodies, TargetedJsonSchemaDocument::resolve_schema_node stack-overflowed on circular $ref cycles, and snapshot/cache persistence followed symlinks while package_search_dsl_worker used an unbounded mpsc::channel."))
  quint-module: "execution_asp_patch_transport_schema_cache_confinement"
  quint-file: "AspPatchTransportSchemaCacheConfinement.qnt"
  domain-dir: "threat/execution/asp-patch-transport-schema-cache-confinement"
  rules:
  '((asp-patch-transport-schema-cache-safe DE-SM40-SAFE quint)
    (asp-patch-transport-schema-cache-countermodel DE-SM40-COUNTER quint))
  dependencies:
  '((DE-SM40-SAFE source)
    (DE-SM40-SAFE profile)
    (DE-SM40-SAFE method)
    (DE-SM40-COUNTER source)
    (DE-SM40-COUNTER profile)
    (DE-SM40-COUNTER method))
  invariant: "ASP HTTP AST patches enforce workspace-root confinement, non-symlink O_NOFOLLOW bounded reads, and symlink-safe atomic writes (patchEscapeBreaches == 0 and patchConfinementEnforced), loopback ASP HTTP transport enforces strict host:port endpoints, CRLF-free Bearer tokens and route paths, fail-closed response size caps, and checked chunked-transfer decoding (transportSmugglingBreaches == 0 and loopbackTransportIntegrityEnforced), JSON Schema $ref resolution enforces depth and cycle bounds preventing stack-overflow crashes (schemaCycleCrashBreaches == 0 and schemaRefCycleGuardEnforced), and workspace snapshot/cache persistence refuses symlinks while Search DSL worker dispatch enforces bounded sync_channel backpressure (cacheQueueBreaches == 0 and snapshotCacheQueueConfinementEnforced and pendingDslJobs <= 12)."
  limits: "Finite bounded ASP HTTP AST patch confinement, loopback HTTP/1.1 endpoint and chunked-response transport integrity, circular JSON Schema $ref depth bounding, and workspace snapshot/cache symlink refusal with bounded Search DSL worker queueing (pendingDslJobs <= 12, stepCount <= 12); models workspace-confined non-symlink bounded AST patch reads and atomic writes, strict loopback host:port endpoints with CRLF-free Bearer tokens/paths and checked chunked/response bounds, cycle-bounded JSON Schema $ref resolution, and O_NOFOLLOW non-symlink snapshot/cache persistence with bounded sync_channel DSL queues, without modeling TCP congestion control or OS filesystem journaling internals.")

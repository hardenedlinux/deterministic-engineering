// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.asp-patch-transport-schema-cache-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel forbid-ast-patch-traversal-symlink-or-unbounded-read step=stepAstPatchEscapeOrUnboundedRead max-steps=6 itf="h.patchEscapeBreaches > 0"
// @countermodel forbid-loopback-ssrf-crlf-or-chunked-overflow step=stepLoopbackSsrfCrlfOrChunkOverflow max-steps=6 itf="h.transportSmugglingBreaches > 0"
// @countermodel forbid-circular-json-schema-ref-stack-overflow step=stepCircularSchemaRefOverflow max-steps=6 itf="h.schemaCycleCrashBreaches > 0"
// @countermodel forbid-snapshot-cache-symlink-or-unbounded-dsl-queue step=stepCacheSymlinkOrUnboundedDslQueue max-steps=6 itf="h.cacheQueueBreaches > 0"
// Limits: Finite bounded ASP HTTP AST patch confinement, loopback HTTP/1.1 endpoint and chunked-response transport integrity, circular JSON Schema $ref depth bounding, and workspace snapshot/cache symlink refusal with bounded Search DSL worker queueing (pendingDslJobs <= 12, stepCount <= 12); models workspace-confined non-symlink bounded AST patch reads and atomic writes, strict loopback host:port endpoints with CRLF-free Bearer tokens/paths and checked chunked/response bounds, cycle-bounded JSON Schema $ref resolution, and O_NOFOLLOW non-symlink snapshot/cache persistence with bounded sync_channel DSL queues, without modeling TCP congestion control or OS filesystem journaling internals.
module execution_asp_patch_transport_schema_cache_confinement {
  type State = { pendingDslJobs: int, patchConfinementEnforced: bool, loopbackTransportIntegrityEnforced: bool, schemaRefCycleGuardEnforced: bool, snapshotCacheQueueConfinementEnforced: bool, patchEscapeBreaches: int, transportSmugglingBreaches: int, schemaCycleCrashBreaches: int, cacheQueueBreaches: int, cleanVerifiedOps: int, stepCount: int }
  var h: State
  action init = h' = { pendingDslJobs: 0, patchConfinementEnforced: true, loopbackTransportIntegrityEnforced: true, schemaRefCycleGuardEnforced: true, snapshotCacheQueueConfinementEnforced: true, patchEscapeBreaches: 0, transportSmugglingBreaches: 0, schemaCycleCrashBreaches: 0, cacheQueueBreaches: 0, cleanVerifiedOps: 0, stepCount: 0 }
  action applyConfinedBoundedAstPatch = if ((h.stepCount < 12 and h.patchConfinementEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action sendValidatedLoopbackCheckedChunkedHttp = if ((h.stepCount < 12 and h.loopbackTransportIntegrityEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action resolveDepthBoundedSchemaRef = if ((h.stepCount < 12 and h.schemaRefCycleGuardEnforced)) h' = h.with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action persistNoSymlinkCacheOrEnqueueBoundedDsl = if ((h.stepCount < 12 and h.snapshotCacheQueueConfinementEnforced and h.pendingDslJobs < 12)) h' = h.with("pendingDslJobs", (h.pendingDslJobs + 1)).with("cleanVerifiedOps", (h.cleanVerifiedOps + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action step = any { applyConfinedBoundedAstPatch, sendValidatedLoopbackCheckedChunkedHttp, resolveDepthBoundedSchemaRef, persistNoSymlinkCacheOrEnqueueBoundedDsl }
  val safety = (h.patchEscapeBreaches == 0 and h.transportSmugglingBreaches == 0 and h.schemaCycleCrashBreaches == 0 and h.cacheQueueBreaches == 0 and h.patchConfinementEnforced and h.loopbackTransportIntegrityEnforced and h.schemaRefCycleGuardEnforced and h.snapshotCacheQueueConfinementEnforced and h.pendingDslJobs >= 0 and h.pendingDslJobs <= 12 and h.stepCount <= 12)
  // Countermodel threat.execution.asp-patch-transport-schema-cache-confinement.ast-patch-escape-or-unbounded-read (dropped guard: forbid-ast-patch-traversal-symlink-or-unbounded-read)
  action exploitAstPatchEscapeOrUnboundedRead = if ((h.stepCount < 12)) h' = h.with("patchConfinementEnforced", false).with("patchEscapeBreaches", (h.patchEscapeBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepAstPatchEscapeOrUnboundedRead = any { step, exploitAstPatchEscapeOrUnboundedRead }
  // Countermodel threat.execution.asp-patch-transport-schema-cache-confinement.loopback-ssrf-crlf-or-chunk-overflow (dropped guard: forbid-loopback-ssrf-crlf-or-chunked-overflow)
  action exploitLoopbackSsrfCrlfOrChunkOverflow = if ((h.stepCount < 12)) h' = h.with("loopbackTransportIntegrityEnforced", false).with("transportSmugglingBreaches", (h.transportSmugglingBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepLoopbackSsrfCrlfOrChunkOverflow = any { step, exploitLoopbackSsrfCrlfOrChunkOverflow }
  // Countermodel threat.execution.asp-patch-transport-schema-cache-confinement.circular-schema-ref-overflow (dropped guard: forbid-circular-json-schema-ref-stack-overflow)
  action exploitCircularSchemaRefOverflow = if ((h.stepCount < 12)) h' = h.with("schemaRefCycleGuardEnforced", false).with("schemaCycleCrashBreaches", (h.schemaCycleCrashBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepCircularSchemaRefOverflow = any { step, exploitCircularSchemaRefOverflow }
  // Countermodel threat.execution.asp-patch-transport-schema-cache-confinement.cache-symlink-or-unbounded-dsl-queue (dropped guard: forbid-snapshot-cache-symlink-or-unbounded-dsl-queue)
  action exploitCacheSymlinkOrUnboundedDslQueue = if ((h.stepCount < 12)) h' = h.with("snapshotCacheQueueConfinementEnforced", false).with("cacheQueueBreaches", (h.cacheQueueBreaches + 1)).with("stepCount", (h.stepCount + 1)) else h' = h
  action stepCacheSymlinkOrUnboundedDslQueue = any { step, exploitCacheSymlinkOrUnboundedDslQueue }
  action checkSm40Safe = all { assert(safety), assert(h.cleanVerifiedOps > 0), h' = h }
  action checkSm40Violated = all { assert((h.patchEscapeBreaches > 0 or h.transportSmugglingBreaches > 0 or h.schemaCycleCrashBreaches > 0 or h.cacheQueueBreaches > 0)), assert(not(safety)), h' = h }
  run cleanAspPatchTransportSchemaCacheSafeTest = init.then(applyConfinedBoundedAstPatch).then(sendValidatedLoopbackCheckedChunkedHttp).then(resolveDepthBoundedSchemaRef).then(persistNoSymlinkCacheOrEnqueueBoundedDsl).then(checkSm40Safe)
  run astPatchEscapeOrUnboundedReadRefutedTest = init.then(exploitAstPatchEscapeOrUnboundedRead).then(checkSm40Violated)
  run loopbackSsrfCrlfOrChunkOverflowRefutedTest = init.then(exploitLoopbackSsrfCrlfOrChunkOverflow).then(checkSm40Violated)
  run circularSchemaRefOverflowRefutedTest = init.then(exploitCircularSchemaRefOverflow).then(checkSm40Violated)
  run cacheSymlinkOrUnboundedDslQueueRefutedTest = init.then(exploitCacheSymlinkOrUnboundedDslQueue).then(checkSm40Violated)
}

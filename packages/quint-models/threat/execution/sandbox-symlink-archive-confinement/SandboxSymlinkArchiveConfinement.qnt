// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later
// @quint-model threat.execution.sandbox-symlink-archive-confinement
// @quint-version 0.33.0
// @apalache-version 0.62.1
// @verify safety max-steps=12
// @countermodel reject-symlink-escape step=stepLexicalOnlySymlinkEscape max-steps=6 itf="h.symlinkEscapes > 0"
// @countermodel confine-entry-path-to-root step=stepManifestPathTraversal max-steps=6 itf="h.traversalEscapes > 0"
// @countermodel reject-duplicate-and-alias-entries step=stepDuplicateTarShadowing max-steps=6 itf="h.duplicateShadows > 0"
// @countermodel enforce-cumulative-decompressed-cap step=stepCumulativeZipBomb max-steps=6 itf="h.decompressionOverruns > 0"
// Limits: Finite 4-unit cumulative extraction cap and canonical path/symlink/archive-entry abstraction (ADV-L4 hostile attack tier); verifies symlink ancestor confinement, manifest entry containment, duplicate/alias archive rejection, and cumulative decompression caps, not OS kernel openat2 VFS race windows or gzip Huffman internals.
module execution_sandbox_symlink_archive_confinement {
  type State = { maxDecompressed: int, extractedBytes: int, distinctEntries: int, hostileBlocked: int, cleanAdmitted: int, symlinkEscapes: int, traversalEscapes: int, duplicateShadows: int, decompressionOverruns: int }
  var h: State
  action init = h' = { maxDecompressed: 4, extractedBytes: 0, distinctEntries: 0, hostileBlocked: 0, cleanAdmitted: 0, symlinkEscapes: 0, traversalEscapes: 0, duplicateShadows: 0, decompressionOverruns: 0 }
  action admitCanonicalWrite = h' = h.with("cleanAdmitted", (h.cleanAdmitted + 1))
  action blockSymlinkAttempt = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockTraversalAttempt = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action extractBoundedUniqueEntry = if ((h.extractedBytes + 1) <= h.maxDecompressed) h' = h.with("extractedBytes", (h.extractedBytes + 1)).with("distinctEntries", (h.distinctEntries + 1)).with("cleanAdmitted", (h.cleanAdmitted + 1)) else h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action blockDuplicateOrAliasEntry = h' = h.with("hostileBlocked", (h.hostileBlocked + 1))
  action resetArchiveBatch = h' = h.with("extractedBytes", 0).with("distinctEntries", 0)
  action step = any { admitCanonicalWrite, blockSymlinkAttempt, blockTraversalAttempt, extractBoundedUniqueEntry, blockDuplicateOrAliasEntry, resetArchiveBatch }
  val safety = (h.extractedBytes <= h.maxDecompressed and h.extractedBytes >= 0 and h.symlinkEscapes == 0 and h.traversalEscapes == 0 and h.duplicateShadows == 0 and h.decompressionOverruns == 0)
  // Countermodel threat.execution.sandbox-symlink-archive-confinement.lexical-only-symlink-escape (dropped guard: reject-symlink-escape)
  action writeThroughSymlinkEscape = h' = h.with("symlinkEscapes", (h.symlinkEscapes + 1))
  action stepLexicalOnlySymlinkEscape = any { step, writeThroughSymlinkEscape }
  // Countermodel threat.execution.sandbox-symlink-archive-confinement.manifest-path-traversal (dropped guard: confine-entry-path-to-root)
  action joinUnconfinedManifestEntry = h' = h.with("traversalEscapes", (h.traversalEscapes + 1))
  action stepManifestPathTraversal = any { step, joinUnconfinedManifestEntry }
  // Countermodel threat.execution.sandbox-symlink-archive-confinement.duplicate-tar-shadowing (dropped guard: reject-duplicate-and-alias-entries)
  action overwriteDuplicateTarEntry = if (h.distinctEntries > 0) h' = h.with("duplicateShadows", (h.duplicateShadows + 1)) else h' = h
  action stepDuplicateTarShadowing = any { step, overwriteDuplicateTarEntry }
  // Countermodel threat.execution.sandbox-symlink-archive-confinement.cumulative-zip-bomb (dropped guard: enforce-cumulative-decompressed-cap)
  action extractUnboundedCumulativeEntry = h' = h.with("extractedBytes", (h.maxDecompressed + 3)).with("decompressionOverruns", (h.decompressionOverruns + 1))
  action stepCumulativeZipBomb = any { step, extractUnboundedCumulativeEntry }
  action checkHostileConfinementSafe = all { assert(h.cleanAdmitted > 0), assert(h.hostileBlocked > 0), assert(h.extractedBytes <= h.maxDecompressed), assert(h.symlinkEscapes == 0), assert(h.traversalEscapes == 0), assert(h.duplicateShadows == 0), assert(h.decompressionOverruns == 0), assert(safety), h' = h }
  action checkHostileConfinementViolated = all { assert((h.symlinkEscapes > 0 or h.traversalEscapes > 0 or h.duplicateShadows > 0 or h.decompressionOverruns > 0)), assert(not(safety)), h' = h }
  run hostileConfinementSafeTest = init.then(admitCanonicalWrite).then(blockSymlinkAttempt).then(blockTraversalAttempt).then(extractBoundedUniqueEntry).then(blockDuplicateOrAliasEntry).then(resetArchiveBatch).then(checkHostileConfinementSafe)
  run symlinkEscapeRefutedTest = init.then(writeThroughSymlinkEscape).then(checkHostileConfinementViolated)
  run manifestTraversalRefutedTest = init.then(joinUnconfinedManifestEntry).then(checkHostileConfinementViolated)
  run duplicateTarShadowRefutedTest = init.then(extractBoundedUniqueEntry).then(overwriteDuplicateTarEntry).then(checkHostileConfinementViolated)
  run cumulativeZipBombRefutedTest = init.then(extractUnboundedCumulativeEntry).then(checkHostileConfinementViolated)
}

#!/usr/bin/env bun
// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Zero-Dependency Portable Cross-Language Air-Gapped Offline Attestation Verifier (10.154).
 *
 * Byte-for-byte isomorphic to `library/verification-flow/attestation.ss` and
 * `t/support/offline-attestation-verifier.ss`, using ONLY Node/Bun built-ins
 * (`node:crypto`, `node:fs`, `node:path`) — ZERO Gerbil, ZERO OpenSSL CLI,
 * ZERO external npm dependencies, ZERO temp files, sub-100ms cold verification.
 *
 * CLI (100% flag- and JSON-schema-compatible with `offline-attestation-verifier.ss`):
 *   bun t/harness/offline-attestation-verifier.ts [--json] --verify-report <report.json> <trust-store.json>
 *   bun t/harness/offline-attestation-verifier.ts [--json] --verify-fleet  <fleet-report.json> <trust-store.json>
 *   bun t/harness/offline-attestation-verifier.ts [--json] --verify-cache  <verification-cache.v1.json> <trust-store.json>
 *   bun t/harness/offline-attestation-verifier.ts [--json] --verify-trust-store <trust-store.json>
 *   bun t/harness/offline-attestation-verifier.ts [--json] --export-trust-bundle <out.json> [--revoke <keyId>]... <pub1.pem>...
 */

import {createHash, createPublicKey, verify as cryptoVerify} from 'node:crypto';
import {existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';

export interface TrustPair {
  trusted: Array<[string, string]>;
  revoked: string[];
}

export interface ExportBundleResult {
  active: string[];
  revoked: string[];
}

const TRUST_STORE_SCHEMA = 'de.attestation.ed25519-trust-store.v1';
const VERIFY_RESULT_SCHEMA = 'de.attestation.offline-verify-result.v1';
const PUBLIC_KEY_HEADER = '-----BEGIN PUBLIC KEY-----';
const STRICT_BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

// ── 1. Pure Canonical Framing (Byte-for-Byte Isomorphic to attestation.ss) ──

/** Unicode code-point length matching Gambit/Gerbil `(string-length s)`. */
export function codePointLength(s: string): number {
  let n = 0;
  for (const _cp of s) n += 1;
  return n;
}

/** Strict Unicode code-point comparator matching Scheme `(string<? a b)`. */
export function codePointCompare(a: string, b: string): number {
  const iterA = a[Symbol.iterator]();
  const iterB = b[Symbol.iterator]();
  while (true) {
    const na = iterA.next();
    const nb = iterB.next();
    if (na.done && nb.done) return 0;
    if (na.done) return -1;
    if (nb.done) return 1;
    const ca = na.value.codePointAt(0)!;
    const cb = nb.value.codePointAt(0)!;
    if (ca !== cb) return ca < cb ? -1 : 1;
  }
}

export function frameCanonicalKv(k: string, v: string): string {
  return `${k}=${codePointLength(v)}:${v}\n`;
}

export function trustStoreKeyAdmitted(
  trustedKeys: ReadonlyArray<readonly [string, string]>,
  revokedKeyIds: ReadonlyArray<string>,
  keyId: unknown,
): string | null {
  if (typeof keyId !== 'string') return null;
  if (revokedKeyIds.includes(keyId)) return null;
  for (const [kid, pub] of trustedKeys) {
    if (kid === keyId) return pub;
  }
  return null;
}

export function safeRelativeChildPath(rel: unknown): rel is string {
  if (typeof rel !== 'string' || rel.length === 0) return false;
  if (rel.startsWith('/') || rel.startsWith('\\')) return false;
  for (let i = 0; i < rel.length; i += 1) {
    const ch = rel.charCodeAt(i);
    if (ch === 92 /* '\\' */ || ch === 0 /* '\0' */) return false;
  }
  const segs = rel.split('/');
  if (segs.length === 0) return false;
  return segs.every((seg) => seg.length > 0 && seg !== '.' && seg !== '..');
}

export function canonicalWitnessSigningPayload(
  step: string,
  obligation: string,
  method: string,
  claimKind: string,
  outcome: string,
  detail: string,
  toolchain: string,
  inputPairs: ReadonlyArray<readonly [string, string]>,
  issuedAt: string | number = '',
): string {
  const sortedInputs = [...inputPairs].sort((a, b) => codePointCompare(a[0], b[0]));
  const issuedStr = typeof issuedAt === 'number' ? String(issuedAt) : issuedAt;
  const parts: string[] = [
    'de.verification-witness.v2\n',
    frameCanonicalKv('step', step),
    frameCanonicalKv('obligation', obligation),
    frameCanonicalKv('method', method),
    frameCanonicalKv('claimKind', claimKind),
    frameCanonicalKv('outcome', outcome),
    frameCanonicalKv('detail', detail),
    frameCanonicalKv('toolchain', toolchain),
  ];
  if (issuedStr.length > 0) {
    parts.push(frameCanonicalKv('issuedAt', issuedStr));
  }
  parts.push(frameCanonicalKv('inputCount', String(sortedInputs.length)));
  for (const [k, v] of sortedInputs) {
    parts.push(frameCanonicalKv(`in:${k}`, v));
  }
  return parts.join('');
}

export function canonicalReportSigningPayload(
  subject: string,
  requestId: string,
  replayStatus: string,
  replayValid: boolean,
  admittedSubjects: ReadonlyArray<string>,
  evidenceRows: ReadonlyArray<readonly [string, string, string, string, string, string]>,
  toolchainPairs: ReadonlyArray<readonly [string, string]>,
): string {
  const sortedAdmitted = [...admittedSubjects].sort(codePointCompare);
  const sortedTc = [...toolchainPairs].sort((a, b) => codePointCompare(a[0], b[0]));
  const sortedEv = [...evidenceRows].sort((a, b) => codePointCompare(a[0], b[0]));
  const parts: string[] = [
    'de.verification-report.v2\n',
    frameCanonicalKv('subject', subject),
    frameCanonicalKv('requestId', requestId),
    frameCanonicalKv('replayStatus', replayStatus),
    frameCanonicalKv('replayValid', replayValid ? 'true' : 'false'),
    frameCanonicalKv('admittedCount', String(sortedAdmitted.length)),
  ];
  for (const s of sortedAdmitted) {
    parts.push(frameCanonicalKv('admitted', s));
  }
  parts.push(frameCanonicalKv('toolchainCount', String(sortedTc.length)));
  for (const [k, v] of sortedTc) {
    parts.push(frameCanonicalKv(`tc:${k}`, v));
  }
  parts.push(frameCanonicalKv('evidenceCount', String(sortedEv.length)));
  for (const ev of sortedEv) {
    parts.push(
      frameCanonicalKv('ev.step', ev[0]),
      frameCanonicalKv('ev.obligation', ev[1]),
      frameCanonicalKv('ev.method', ev[2]),
      frameCanonicalKv('ev.claimKind', ev[3]),
      frameCanonicalKv('ev.outcome', ev[4]),
      frameCanonicalKv('ev.detail', ev[5]),
    );
  }
  return parts.join('');
}

export function canonicalFleetSigningPayload(
  fleetId: string,
  sysmlSha256: string,
  subjectEntries: ReadonlyArray<readonly [string, string, string, boolean, boolean]>,
): string {
  const sortedEntries = [...subjectEntries].sort((a, b) => codePointCompare(a[0], b[0]));
  const parts: string[] = [
    'de.verification-fleet-report.v1\n',
    frameCanonicalKv('fleetId', fleetId),
    frameCanonicalKv('sysmlSha256', sysmlSha256),
    frameCanonicalKv('subjectCount', String(sortedEntries.length)),
  ];
  for (const e of sortedEntries) {
    parts.push(
      frameCanonicalKv('sub.key', e[0]),
      frameCanonicalKv('sub.id', e[1]),
      frameCanonicalKv('sub.reportSha256', e[2]),
      frameCanonicalKv('sub.replayValid', e[3] ? 'true' : 'false'),
      frameCanonicalKv('sub.admitted', e[4] ? 'true' : 'false'),
    );
  }
  return parts.join('');
}

// ── 2. Crypto, POSIX lstat Containment & Trust Store Operations ──

export function sha256File(filePath: string): string {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex');
}

export function sha256Str(text: string): string {
  return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

export function isInlinePemString(val: unknown): val is string {
  return typeof val === 'string' && val.startsWith(PUBLIC_KEY_HEADER);
}

function lstatKind(targetPath: string): 'regular' | 'directory' | 'other' | null {
  try {
    const st = lstatSync(targetPath);
    if (st.isSymbolicLink()) return 'other';
    if (st.isFile()) return 'regular';
    if (st.isDirectory()) return 'directory';
    return 'other';
  } catch {
    return null;
  }
}

/**
 * Native POSIX lstat() segment-by-segment containment check:
 * Rejects lexical traversal (`safeRelativeChildPath`) AND any symbolic link
 * along intermediate directories OR the leaf file itself.
 */
export function resolveContainedChildReportPath(baseDir: string, rel: unknown): string | null {
  if (!safeRelativeChildPath(rel)) return null;
  const segs = rel.split('/');
  let acc = baseDir;
  for (let i = 0; i < segs.length; i += 1) {
    const cur = join(acc, segs[i]);
    const kind = lstatKind(cur);
    if (i === segs.length - 1) {
      return kind === 'regular' ? cur : null;
    }
    if (kind !== 'directory') return null;
    acc = cur;
  }
  return null;
}

export function resolveTrustedPemPath(baseDir: string, rawPath: unknown): string {
  if (typeof rawPath !== 'string' || rawPath.length === 0) {
    throw new Error(`Invalid trusted public key path: ${String(rawPath)}`);
  }
  if (rawPath.startsWith('/')) {
    if (lstatKind(rawPath) !== 'regular') {
      throw new Error(`Trusted public key must be an existing regular non-symlink file: ${rawPath}`);
    }
    return rawPath;
  }
  const contained = resolveContainedChildReportPath(baseDir, rawPath);
  if (!contained) {
    throw new Error(`Relative trusted public key path rejected (missing, traversal, or symlink): ${rawPath}`);
  }
  return contained;
}

export function ed25519VerifyRaw(pubPemOrPath: string, payloadStr: string, sigB64: unknown): boolean {
  if (typeof pubPemOrPath !== 'string' || typeof sigB64 !== 'string' || sigB64.length === 0) {
    return false;
  }
  if (sigB64.length % 4 !== 0 || !STRICT_BASE64_RE.test(sigB64)) {
    return false;
  }
  const sigBytes = Buffer.from(sigB64, 'base64');
  if (sigBytes.length !== 64) {
    return false;
  }
  try {
    const pemStr = isInlinePemString(pubPemOrPath)
      ? pubPemOrPath
      : existsSync(pubPemOrPath)
        ? readFileSync(pubPemOrPath, 'utf8')
        : null;
    if (!pemStr) return false;
    const keyObj = createPublicKey(pemStr);
    if (keyObj.asymmetricKeyType !== 'ed25519') return false;
    return cryptoVerify(null, Buffer.from(payloadStr, 'utf8'), keyObj, sigBytes);
  } catch {
    return false;
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function readJsonObject(filePath: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(filePath, 'utf8'));
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function objectToStringPairs(obj: unknown): Array<[string, string]> {
  if (!isPlainObject(obj)) return [];
  const out: Array<[string, string]> = [];
  for (const [k, v] of Object.entries(obj)) {
    out.push([k, typeof v === 'string' ? v : String(v ?? '')]);
  }
  return out;
}

export function loadTrustStoreJsonLite(storePath: string): TrustPair {
  if (typeof storePath !== 'string' || !existsSync(storePath)) {
    throw new Error(`Ed25519 trust store file not found: ${storePath}`);
  }
  const baseDir = dirname(resolve(storePath));
  const doc = readJsonObject(storePath);
  if (!doc || doc.schema !== TRUST_STORE_SCHEMA) {
    throw new Error(`Invalid Ed25519 trust store schema: ${storePath}`);
  }
  const keysObj = doc.trustedKeys;
  if (!isPlainObject(keysObj)) {
    throw new Error(`Ed25519 trust store missing trustedKeys map: ${storePath}`);
  }
  const trusted: Array<[string, string]> = [];
  for (const [declaredKid, rawVal] of Object.entries(keysObj)) {
    if (typeof declaredKid !== 'string' || typeof rawVal !== 'string') {
      throw new Error(`Invalid trustedKeys entry for ${declaredKid}`);
    }
    if (isInlinePemString(rawVal)) {
      const actualKid = sha256Str(rawVal).slice(0, 16);
      if (actualKid !== declaredKid) {
        throw new Error(
          `Inline trusted public keyId mismatch (possible spoofing): declared=${declaredKid} actual=${actualKid}`,
        );
      }
      trusted.push([declaredKid, rawVal]);
    } else {
      const resolved = resolveTrustedPemPath(baseDir, rawVal);
      const actualKid = sha256File(resolved).slice(0, 16);
      if (actualKid !== declaredKid) {
        throw new Error(
          `Trusted public keyId mismatch (possible spoofing): declared=${declaredKid} actual=${actualKid} path=${resolved}`,
        );
      }
      trusted.push([declaredKid, resolved]);
    }
  }
  const revokedRaw = Array.isArray(doc.revokedKeyIds) ? doc.revokedKeyIds : [];
  const revoked = revokedRaw.filter((x): x is string => typeof x === 'string');
  return {trusted, revoked};
}

export function verifyReportOffline(reportPath: string, trustPair: TrustPair): boolean {
  if (!existsSync(reportPath)) return false;
  const doc = readJsonObject(reportPath);
  if (!doc) return false;
  const att = doc.attestation;
  if (!isPlainObject(att)) return false;
  const pub = trustStoreKeyAdmitted(trustPair.trusted, trustPair.revoked, att.keyId);
  if (!pub) return false;
  if (att.algorithm !== 'Ed25519') return false;
  if (doc.replayValid !== true) return false;
  if (!Array.isArray(doc.mrFindings) || doc.mrFindings.length !== 0) return false;
  if (!Array.isArray(doc.mrOpenPremises) || doc.mrOpenPremises.length !== 0) return false;
  if (!Array.isArray(doc.erFindings) || doc.erFindings.length !== 0) return false;
  if (!Array.isArray(doc.verificationAdmitted) || doc.verificationAdmitted.length === 0) return false;

  const admittedFlat = doc.verificationAdmitted.map((r) =>
    Array.isArray(r) ? String(r[0] ?? '') : String(r ?? ''),
  );
  const evRaw = Array.isArray(doc.evidence) ? doc.evidence : [];
  const evRows: Array<[string, string, string, string, string, string]> = evRaw.map((e) => {
    const rec = isPlainObject(e) ? e : {};
    return [
      typeof rec.step === 'string' ? rec.step : '',
      typeof rec.obligation === 'string' ? rec.obligation : '',
      typeof rec.method === 'string' ? rec.method : '',
      typeof rec.claimKind === 'string' ? rec.claimKind : '',
      typeof rec.outcome === 'string' ? rec.outcome : '',
      typeof rec.detail === 'string' ? rec.detail : '',
    ];
  });
  const tcPairs = objectToStringPairs(doc.toolchainFingerprints);
  const canonical = canonicalReportSigningPayload(
    typeof doc.subject === 'string' ? doc.subject : '',
    typeof doc.requestId === 'string' ? doc.requestId : '',
    typeof doc.replayStatus === 'string' ? doc.replayStatus : '',
    true,
    admittedFlat,
    evRows,
    tcPairs,
  );
  if (sha256Str(canonical) !== att.payloadSha256) return false;
  return ed25519VerifyRaw(pub, canonical, att.signature);
}

export function verifyFleetOffline(fleetReportPath: string, trustPair: TrustPair): boolean {
  if (!existsSync(fleetReportPath)) return false;
  const doc = readJsonObject(fleetReportPath);
  if (!doc) return false;
  const att = doc.attestation;
  const subjects = doc.subjects;
  if (!isPlainObject(att) || !Array.isArray(subjects) || subjects.length === 0) return false;
  const fleetPub = trustStoreKeyAdmitted(trustPair.trusted, trustPair.revoked, att.keyId);
  if (!fleetPub) return false;
  if (att.algorithm !== 'Ed25519') return false;

  const fleetDir = dirname(resolve(fleetReportPath));
  const entries: Array<[string, string, string, boolean, boolean]> = subjects.map((s) => {
    const rec = isPlainObject(s) ? s : {};
    return [
      typeof rec.subjectKey === 'string' ? rec.subjectKey : '',
      typeof rec.subjectId === 'string' ? rec.subjectId : '',
      typeof rec.reportPayloadSha256 === 'string' ? rec.reportPayloadSha256 : '',
      rec.replayValid === true,
      rec.admitted === true,
    ];
  });
  const canonical = canonicalFleetSigningPayload(
    typeof doc.fleetId === 'string' ? doc.fleetId : '',
    typeof doc.sysmlSha256 === 'string' ? doc.sysmlSha256 : '',
    entries,
  );
  if (sha256Str(canonical) !== att.payloadSha256) return false;
  if (!ed25519VerifyRaw(fleetPub, canonical, att.signature)) return false;

  for (const s of subjects) {
    if (!isPlainObject(s)) return false;
    const childPath = resolveContainedChildReportPath(fleetDir, s.reportRelativePath);
    if (!childPath) return false;
    if (!verifyReportOffline(childPath, trustPair)) return false;
    const cdoc = readJsonObject(childPath);
    const catt = cdoc && isPlainObject(cdoc.attestation) ? cdoc.attestation : null;
    if (!catt || catt.payloadSha256 !== s.reportPayloadSha256) return false;
  }
  return true;
}

export function verifyCacheOffline(cachePath: string, trustPair: TrustPair): number | null {
  if (!existsSync(cachePath)) return null;
  const doc = readJsonObject(cachePath);
  if (!doc || !isPlainObject(doc.entries)) return null;
  const entries = Object.entries(doc.entries);
  if (entries.length === 0) return null;

  for (const [stepStr, rec] of entries) {
    if (!isPlainObject(rec)) return null;
    const pub = trustStoreKeyAdmitted(trustPair.trusted, trustPair.revoked, rec.keyId);
    if (!pub) return null;
    if (typeof rec.toolchainFingerprint !== 'string' || typeof rec.signature !== 'string') {
      return null;
    }
    const issuedStr =
      typeof rec.issuedAtEpoch === 'number' && Number.isInteger(rec.issuedAtEpoch)
        ? String(rec.issuedAtEpoch)
        : '';
    const canonical = canonicalWitnessSigningPayload(
      stepStr,
      typeof rec.obligation === 'string' ? rec.obligation : '',
      typeof rec.method === 'string' ? rec.method : '',
      typeof rec.claimKind === 'string' ? rec.claimKind : '',
      typeof rec.outcome === 'string' ? rec.outcome : '',
      typeof rec.detail === 'string' ? rec.detail : '',
      rec.toolchainFingerprint,
      objectToStringPairs(rec.inputDigests),
      issuedStr,
    );
    if (!ed25519VerifyRaw(pub, canonical, rec.signature)) return null;
  }
  return entries.length;
}

export function exportTrustBundleOffline(
  outPath: string,
  pubPaths: ReadonlyArray<string>,
  revokedKeyIds: ReadonlyArray<string> = [],
): ExportBundleResult {
  if (typeof outPath !== 'string' || outPath.length === 0) {
    throw new Error(`Invalid output trust bundle path: ${String(outPath)}`);
  }
  if (!Array.isArray(pubPaths) || pubPaths.length === 0) {
    throw new Error('At least one public key PEM path is required to export a trust bundle');
  }
  const cwd = process.cwd();
  const keysMap: Record<string, string> = {};
  const allKids: string[] = [];
  for (const rawPath of pubPaths) {
    const resolved = resolveTrustedPemPath(cwd, rawPath);
    const pemStr = readFileSync(resolved, 'utf8');
    if (!isInlinePemString(pemStr)) {
      throw new Error(
        `Refusing to bundle non-public-key PEM (private keys and malformed PEMs are rejected): ${rawPath}`,
      );
    }
    const kid = sha256Str(pemStr).slice(0, 16);
    keysMap[kid] = pemStr;
    if (!allKids.includes(kid)) allKids.push(kid);
  }
  const revokedSet = new Set<string>();
  for (const r of revokedKeyIds) {
    if (typeof r !== 'string' || r.length === 0) {
      throw new Error(`Invalid --revoke keyId: ${String(r)}`);
    }
    revokedSet.add(r);
  }
  const revoked = [...revokedSet].sort(codePointCompare);
  const active = allKids.filter((kid) => !revokedSet.has(kid)).sort(codePointCompare);
  if (active.length === 0) {
    throw new Error(
      `Refusing to export trust bundle with zero active unrevoked keys: revoked=${JSON.stringify(revoked)}`,
    );
  }
  const parentDir = dirname(resolve(outPath));
  if (!existsSync(parentDir)) {
    mkdirSync(parentDir, {recursive: true});
  }
  const doc = {
    schema: TRUST_STORE_SCHEMA,
    trustedKeys: keysMap,
    revokedKeyIds: revoked,
  };
  writeFileSync(outPath, `${JSON.stringify(doc)}\n`, 'utf8');
  return {active, revoked};
}

// ── 3. Standalone CLI Entrypoint ──

function emitJsonResult(
  ok: boolean,
  mode: string,
  targetPath: string,
  storePath: string,
  detailOrReason: string,
  extra: Record<string, unknown> = {},
): void {
  const doc: Record<string, unknown> = {
    schema: VERIFY_RESULT_SCHEMA,
    ok,
    mode,
    target: targetPath,
    trustStore: storePath,
    [ok ? 'detail' : 'reason']: detailOrReason,
    ...extra,
  };
  process.stdout.write(`${JSON.stringify(doc)}\n`);
}

function parseExportArgs(rest: string[]): {pubPaths: string[]; revokedIds: string[]} {
  const pubPaths: string[] = [];
  const revokedIds: string[] = [];
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === '--revoke') {
      if (i + 1 >= rest.length) throw new Error('--revoke requires a keyId argument');
      revokedIds.push(rest[i + 1]);
      i += 1;
    } else {
      pubPaths.push(rest[i]);
    }
  }
  return {pubPaths, revokedIds};
}

export function runCli(argv: string[]): number {
  const jsonMode = argv.includes('--json');
  const cleanArgs = argv.filter((a) => a !== '--json');
  if (cleanArgs.length === 0) {
    process.stderr.write(
      'usage: [--json] --verify-report|--verify-fleet|--verify-cache <artifact.json> <trust-store.json> | [--json] --verify-trust-store <trust-store.json> | [--json] --export-trust-bundle <out.json> [--revoke <keyId>]... <pub1.pem>...\n',
    );
    return 1;
  }
  const mode = cleanArgs[0];

  if (mode === '--export-trust-bundle') {
    if (cleanArgs.length < 3) {
      process.stderr.write(
        'usage: [--json] --export-trust-bundle <out.json> [--revoke <keyId>]... <pub1.pem>...\n',
      );
      return 1;
    }
    const outPath = cleanArgs[1];
    try {
      const {pubPaths, revokedIds} = parseExportArgs(cleanArgs.slice(2));
      const {active, revoked} = exportTrustBundleOffline(outPath, pubPaths, revokedIds);
      if (jsonMode) {
        emitJsonResult(true, 'export-trust-bundle', outPath, outPath, 'exported-inline-pem-trust-bundle', {
          inlinePem: true,
          activeKeyIds: active,
          revokedKeyIds: revoked,
        });
      } else {
        process.stdout.write(
          `MULTI-METHOD-EXPORT-TRUST-BUNDLE-OK ${outPath} active=${active.length} revoked=${revoked.length}\n`,
        );
      }
      return 0;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        emitJsonResult(false, 'export-trust-bundle', outPath, outPath, `export-trust-bundle failed: ${msg}`);
      } else {
        process.stderr.write(`ERROR: ${msg}\n`);
      }
      return 1;
    }
  }

  if (mode === '--verify-trust-store') {
    if (cleanArgs.length !== 2) {
      process.stderr.write('usage: [--json] --verify-trust-store <trust-store.json>\n');
      return 1;
    }
    const storePath = cleanArgs[1];
    let trustPair: TrustPair;
    try {
      trustPair = loadTrustStoreJsonLite(storePath);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        emitJsonResult(false, 'verify-trust-store', storePath, storePath, `trust-store load failed: ${msg}`);
      } else {
        process.stderr.write(`ERROR: ${msg}\n`);
      }
      return 1;
    }
    const revoked = [...trustPair.revoked].sort(codePointCompare);
    const active = trustPair.trusted
      .map(([kid]) => kid)
      .filter((kid) => !revoked.includes(kid))
      .sort(codePointCompare);
    if (active.length > 0) {
      if (jsonMode) {
        emitJsonResult(
          true,
          'verify-trust-store',
          storePath,
          storePath,
          'trust-store-valid-with-active-keys',
          {activeKeyIds: active, revokedKeyIds: revoked},
        );
      } else {
        process.stdout.write(
          `MULTI-METHOD-VERIFY-TRUST-STORE-OK ${storePath} active=${active.length} revoked=${revoked.length}\n`,
        );
      }
      return 0;
    }
    if (jsonMode) {
      emitJsonResult(
        false,
        'verify-trust-store',
        storePath,
        storePath,
        'trust-store has zero active unrevoked keys',
        {activeKeyIds: [], revokedKeyIds: revoked},
      );
    } else {
      process.stderr.write(`ERROR: trust-store has zero active unrevoked keys: ${storePath}\n`);
    }
    return 1;
  }

  if (cleanArgs.length !== 3) {
    process.stderr.write(
      'usage: [--json] --verify-report|--verify-fleet|--verify-cache <artifact.json> <trust-store.json>\n',
    );
    return 1;
  }
  const targetPath = cleanArgs[1];
  const storePath = cleanArgs[2];
  let trustPair: TrustPair;
  try {
    trustPair = loadTrustStoreJsonLite(storePath);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (jsonMode) {
      emitJsonResult(false, mode, targetPath, storePath, `trust-store load failed: ${msg}`);
    } else {
      process.stderr.write(`ERROR: ${msg}\n`);
    }
    return 1;
  }

  if (mode === '--verify-report') {
    if (verifyReportOffline(targetPath, trustPair)) {
      if (jsonMode) {
        emitJsonResult(true, 'verify-report', targetPath, storePath, 'authentic-admitted-report');
      } else {
        process.stdout.write(`MULTI-METHOD-VERIFY-REPORT-OK ${targetPath}\n`);
      }
      return 0;
    }
    if (jsonMode) {
      emitJsonResult(false, 'verify-report', targetPath, storePath, 'offline report verification failed');
    } else {
      process.stderr.write(`ERROR: offline report verification failed: ${targetPath}\n`);
    }
    return 1;
  }

  if (mode === '--verify-fleet') {
    if (verifyFleetOffline(targetPath, trustPair)) {
      if (jsonMode) {
        emitJsonResult(true, 'verify-fleet', targetPath, storePath, 'authentic-2-level-merkle-fleet');
      } else {
        process.stdout.write(`MULTI-METHOD-VERIFY-FLEET-OK ${targetPath}\n`);
      }
      return 0;
    }
    if (jsonMode) {
      emitJsonResult(false, 'verify-fleet', targetPath, storePath, 'offline fleet verification failed');
    } else {
      process.stderr.write(`ERROR: offline fleet verification failed: ${targetPath}\n`);
    }
    return 1;
  }

  if (mode === '--verify-cache') {
    const n = verifyCacheOffline(targetPath, trustPair);
    if (n !== null) {
      if (jsonMode) {
        emitJsonResult(true, 'verify-cache', targetPath, storePath, 'all-cache-witnesses-verified', {
          entries: n,
        });
      } else {
        process.stdout.write(`MULTI-METHOD-VERIFY-CACHE-OK ${targetPath} entries=${n}\n`);
      }
      return 0;
    }
    if (jsonMode) {
      emitJsonResult(false, 'verify-cache', targetPath, storePath, 'offline cache verification failed');
    } else {
      process.stderr.write(`ERROR: offline cache verification failed: ${targetPath}\n`);
    }
    return 1;
  }

  process.stderr.write(`ERROR: unknown mode ${mode}\n`);
  return 1;
}

if (import.meta.main) {
  process.exit(runCli(process.argv.slice(2)));
}

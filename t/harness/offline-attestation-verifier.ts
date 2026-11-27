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

import {createHash, createPublicKey, sign as cryptoSign, verify as cryptoVerify} from 'node:crypto';
import {existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';

export interface TrustPair {
  trusted: Array<[string, string]>;
  revoked: string[];
  keyRoles?: Record<string, string[]>;
}

export interface ExportBundleResult {
  active: string[];
  revoked: string[];
}

const TRUST_STORE_SCHEMA = 'de.attestation.ed25519-trust-store.v1';
const FLEET_BUNDLE_SCHEMA = 'de.attestation.fleet-evidence-bundle.v1';
const VERIFY_RESULT_SCHEMA = 'de.attestation.offline-verify-result.v1';
const AUDIT_POLICY_SCHEMA = 'de.attestation.policy.v1';
const AUDIT_POLICY_DSSE_PAYLOAD_TYPE = 'application/vnd.de.attestation-policy+json';
const AUDIT_POLICY_ALLOWED_KEYS = new Set([
  'schema',
  'expectedSysmlSha256',
  'expectedSubjectCount',
  'requiredSubjects',
  'minSignatures',
  'requiredSigners',
  'requiredRoles',
  'policyVersion',
  'notAfterEpoch',
]);
const INTOTO_DSSE_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const INTOTO_STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
const INTOTO_PREDICATE_TYPE =
  'https://deterministic-engineering.hardenedlinux.org/attestation/fleet-verification-summary/v1';
const INTOTO_SYSML_SUBJECT_NAME = 'sysml:10.154-multi-method-funflow-runnable-architecture';
const PUBLIC_KEY_HEADER = '-----BEGIN PUBLIC KEY-----';
const STRICT_BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Standard DSSE v1 Pre-Authentication Encoding (PAE) using exact UTF-8 byte lengths:
 *   "DSSEv1 " + utf8ByteLen(payloadType) + " " + payloadType + " " + utf8ByteLen(payload) + " " + payload
 */
export function dsseV1Pae(payloadType: string, payloadBytes: Buffer | string): Buffer {
  const typeBuf = Buffer.from(payloadType, 'utf8');
  const bodyBuf =
    typeof payloadBytes === 'string' ? Buffer.from(payloadBytes, 'utf8') : payloadBytes;
  const prefix = Buffer.from(`DSSEv1 ${typeBuf.length} `, 'utf8');
  const mid = Buffer.from(` ${bodyBuf.length} `, 'utf8');
  return Buffer.concat([prefix, typeBuf, mid, bodyBuf]);
}

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
  const keyRoles: Record<string, string[]> = {};
  if (doc.keyRoles !== undefined) {
    if (!isPlainObject(doc.keyRoles)) {
      throw new Error(`Ed25519 trust store keyRoles must be a JSON object: ${storePath}`);
    }
    for (const [kid, rlist] of Object.entries(doc.keyRoles)) {
      if (!Object.prototype.hasOwnProperty.call(keysObj, kid)) {
        throw new Error(`keyRoles references unknown keyId not in trustedKeys: ${kid}`);
      }
      if (!Array.isArray(rlist)) {
        throw new Error(`keyRoles value must be an array of non-empty strings for keyId: ${kid}`);
      }
      const cleanRoles = new Set<string>();
      for (const r of rlist) {
        if (typeof r !== 'string' || r.length === 0) {
          throw new Error(`Invalid empty or non-string role in keyRoles for keyId: ${kid}`);
        }
        cleanRoles.add(r);
      }
      keyRoles[kid] = [...cleanRoles].sort(codePointCompare);
    }
  }
  return {trusted, revoked, keyRoles};
}

export function verifyReportDocOffline(doc: Record<string, unknown>, trustPair: TrustPair): boolean {
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

export function verifyReportOffline(reportPath: string, trustPair: TrustPair): boolean {
  if (!existsSync(reportPath)) return false;
  const doc = readJsonObject(reportPath);
  if (!doc) return false;
  return verifyReportDocOffline(doc, trustPair);
}

export interface FleetVerifyOptions {
  expectedSysmlSha256?: string;
  expectedSubjectCount?: number;
  requiredSubjects?: ReadonlyArray<string>;
  minSignatures?: number;
  requiredSigners?: ReadonlyArray<string>;
  requiredRoles?: ReadonlyArray<string>;
}

export interface AuditPolicyManifest {
  expectedSysmlSha256?: string;
  expectedSubjectCount?: number;
  requiredSubjects: string[];
  minSignatures?: number;
  requiredSigners: string[];
  requiredRoles: string[];
  policyVersion?: number;
  notAfterEpoch?: number;
}

function validatePolicyStringArray(fieldName: string, raw: unknown): string[] {
  if (!Array.isArray(raw)) {
    throw new Error(`Policy field ${fieldName} must be an array of non-empty strings`);
  }
  const set = new Set<string>();
  for (const item of raw) {
    if (typeof item !== 'string' || item.length === 0) {
      throw new Error(`Invalid empty/non-string entry in policy ${fieldName}`);
    }
    set.add(item);
  }
  return [...set].sort(codePointCompare);
}

function parseAuditPolicyDoc(
  doc: Record<string, unknown> | null,
  sourceLabel: string,
): AuditPolicyManifest {
  if (!doc || doc.schema !== AUDIT_POLICY_SCHEMA) {
    throw new Error(`Invalid audit policy schema (expected ${AUDIT_POLICY_SCHEMA}): ${sourceLabel}`);
  }
  for (const k of Object.keys(doc)) {
    if (!AUDIT_POLICY_ALLOWED_KEYS.has(k)) {
      throw new Error(`Unknown key in audit policy manifest (fail-closed typo guard): ${k}`);
    }
  }
  let expectedSysmlSha256: string | undefined;
  if (doc.expectedSysmlSha256 !== undefined) {
    if (typeof doc.expectedSysmlSha256 !== 'string' || doc.expectedSysmlSha256.length === 0) {
      throw new Error('Policy expectedSysmlSha256 must be a non-empty string');
    }
    expectedSysmlSha256 = doc.expectedSysmlSha256;
  }
  let expectedSubjectCount: number | undefined;
  if (doc.expectedSubjectCount !== undefined) {
    if (
      typeof doc.expectedSubjectCount !== 'number' ||
      !Number.isInteger(doc.expectedSubjectCount) ||
      doc.expectedSubjectCount < 1
    ) {
      throw new Error('Policy expectedSubjectCount must be a positive integer');
    }
    expectedSubjectCount = doc.expectedSubjectCount;
  }
  let minSignatures: number | undefined;
  if (doc.minSignatures !== undefined) {
    if (
      typeof doc.minSignatures !== 'number' ||
      !Number.isInteger(doc.minSignatures) ||
      doc.minSignatures < 1
    ) {
      throw new Error('Policy minSignatures must be a positive integer');
    }
    minSignatures = doc.minSignatures;
  }
  const requiredSubjects =
    doc.requiredSubjects !== undefined
      ? validatePolicyStringArray('requiredSubjects', doc.requiredSubjects)
      : [];
  const requiredSigners =
    doc.requiredSigners !== undefined
      ? validatePolicyStringArray('requiredSigners', doc.requiredSigners)
      : [];
  const requiredRoles =
    doc.requiredRoles !== undefined
      ? validatePolicyStringArray('requiredRoles', doc.requiredRoles)
      : [];
  let policyVersion: number | undefined;
  if (doc.policyVersion !== undefined) {
    if (
      typeof doc.policyVersion !== 'number' ||
      !Number.isInteger(doc.policyVersion) ||
      doc.policyVersion < 1
    ) {
      throw new Error('Policy policyVersion must be a positive integer');
    }
    policyVersion = doc.policyVersion;
  }
  let notAfterEpoch: number | undefined;
  if (doc.notAfterEpoch !== undefined) {
    if (
      typeof doc.notAfterEpoch !== 'number' ||
      !Number.isInteger(doc.notAfterEpoch) ||
      doc.notAfterEpoch < 0
    ) {
      throw new Error('Policy notAfterEpoch must be a non-negative integer');
    }
    notAfterEpoch = doc.notAfterEpoch;
  }
  return {
    expectedSysmlSha256,
    expectedSubjectCount,
    requiredSubjects,
    minSignatures,
    requiredSigners,
    requiredRoles,
    policyVersion,
    notAfterEpoch,
  };
}

/**
 * Anti-rollback version floor & expiry window gate for both plaintext & signed policies.
 */
export function assertPolicyFreshnessAndVersion(
  policy: AuditPolicyManifest | null,
  minPolicyVersion?: number,
  nowEpoch?: number,
): void {
  if (!policy) return;
  const effNow = nowEpoch ?? Math.floor(Date.now() / 1000);
  if (minPolicyVersion !== undefined) {
    if (!Number.isInteger(minPolicyVersion) || minPolicyVersion < 1) {
      throw new Error(`--min-policy-version must be a positive integer: ${String(minPolicyVersion)}`);
    }
    if (policy.policyVersion === undefined || policy.policyVersion < minPolicyVersion) {
      throw new Error(
        `Audit policy rejected by anti-rollback --min-policy-version floor: policyVersion=${String(policy.policyVersion)} < minPolicyVersion=${minPolicyVersion}`,
      );
    }
  }
  if (policy.notAfterEpoch !== undefined) {
    if (!Number.isInteger(effNow) || effNow > policy.notAfterEpoch) {
      throw new Error(
        `Audit policy expired: nowEpoch=${effNow} > notAfterEpoch=${policy.notAfterEpoch}`,
      );
    }
  }
}

/**
 * Strict loader for declarative `de.attestation.policy.v1` audit policy manifests.
 * Enforces POSIX lstat non-symlink regular file, exact schema, strict allowlisted keys
 * (blocking silent typos), and valid field types.
 */
export function loadAuditPolicyJson(policyPath: string): AuditPolicyManifest {
  if (typeof policyPath !== 'string' || policyPath.length === 0) {
    throw new Error(`Invalid audit policy path: ${String(policyPath)}`);
  }
  if (lstatKind(policyPath) !== 'regular') {
    throw new Error(`Audit policy must be an existing regular non-symlink file: ${policyPath}`);
  }
  return parseAuditPolicyDoc(readJsonObject(policyPath), policyPath);
}

export interface VerifiedSignedAuditPolicy {
  policy: AuditPolicyManifest;
  verifiedKeyIds: string[];
  verifiedRoles: string[];
}

export interface SignAuditPolicyResult {
  signerKeyId: string;
  verifiedKeyIds: string[];
  verifiedRoles: string[];
}

/**
 * Strict verifier & loader for a DSSE v1 signed audit policy envelope (`--signed-policy`):
 * Enforces distinct `payloadType == application/vnd.de.attestation-policy+json`,
 * admitted unrevoked Ed25519 PAE signature(s), optional `requiredPolicyRoles`, and
 * allowlisted `de.attestation.policy.v1` payload schema.
 */
export function loadSignedAuditPolicyJson(
  signedPolicyPath: string,
  trustPair: TrustPair,
  requiredPolicyRoles: ReadonlyArray<string> = [],
): VerifiedSignedAuditPolicy {
  if (typeof signedPolicyPath !== 'string' || signedPolicyPath.length === 0) {
    throw new Error(`Invalid signed audit policy path: ${String(signedPolicyPath)}`);
  }
  if (lstatKind(signedPolicyPath) !== 'regular') {
    throw new Error(
      `Signed audit policy must be an existing regular non-symlink file: ${signedPolicyPath}`,
    );
  }
  const env = readJsonObject(signedPolicyPath);
  if (!env || env.payloadType !== AUDIT_POLICY_DSSE_PAYLOAD_TYPE) {
    throw new Error(`Invalid signed audit policy DSSE payloadType: ${signedPolicyPath}`);
  }
  const payloadB64 = env.payload;
  const sigs = env.signatures;
  if (
    typeof payloadB64 !== 'string' ||
    payloadB64.length === 0 ||
    payloadB64.length % 4 !== 0 ||
    !STRICT_BASE64_RE.test(payloadB64) ||
    !Array.isArray(sigs) ||
    sigs.length === 0
  ) {
    throw new Error(`Malformed signed audit policy DSSE envelope: ${signedPolicyPath}`);
  }
  const payloadBuf = Buffer.from(payloadB64, 'base64');
  const paeBuf = dsseV1Pae(AUDIT_POLICY_DSSE_PAYLOAD_TYPE, payloadBuf);
  const verifiedKeyIds: string[] = [];
  for (const sigEntry of sigs) {
    if (!isPlainObject(sigEntry)) continue;
    const kid = sigEntry.keyid;
    const sig = sigEntry.sig;
    const pub = trustStoreKeyAdmitted(trustPair.trusted, trustPair.revoked, kid);
    if (pub && typeof kid === 'string' && ed25519VerifyBytes(pub, paeBuf, sig)) {
      if (!verifiedKeyIds.includes(kid)) verifiedKeyIds.push(kid);
    }
  }
  if (verifiedKeyIds.length === 0) {
    throw new Error(`Signed audit policy has zero valid admitted signatures: ${signedPolicyPath}`);
  }
  const roleSet = new Set<string>();
  const keyRoles = trustPair.keyRoles ?? {};
  for (const kid of verifiedKeyIds) {
    const roles = keyRoles[kid];
    if (Array.isArray(roles)) {
      for (const r of roles) {
        if (typeof r === 'string' && r.length > 0) roleSet.add(r);
      }
    }
  }
  const verifiedRoles = [...roleSet].sort(codePointCompare);
  for (const reqRole of requiredPolicyRoles) {
    if (!roleSet.has(reqRole)) {
      throw new Error(
        `Signed audit policy missing required policy-authority role: ${reqRole} (have: ${JSON.stringify(verifiedRoles)})`,
      );
    }
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(payloadBuf.toString('utf8'));
  } catch {
    throw new Error(`Invalid JSON payload inside signed audit policy: ${signedPolicyPath}`);
  }
  const policy = parseAuditPolicyDoc(isPlainObject(parsed) ? parsed : null, signedPolicyPath);
  verifiedKeyIds.sort(codePointCompare);
  return {policy, verifiedKeyIds, verifiedRoles};
}

/**
 * Offline DSSE v1 signer for a declarative `de.attestation.policy.v1` manifest (`--sign-policy`).
 */
export function signAuditPolicyOffline(
  inPolicyPath: string,
  privPath: string,
  pubPath: string,
  trustPair: TrustPair,
  outPath: string,
): SignAuditPolicyResult {
  loadAuditPolicyJson(inPolicyPath);
  assertSafeStatementOutputPath(outPath);
  const cwd = process.cwd();
  const resolvedPriv = resolveTrustedPemPath(cwd, privPath);
  const resolvedPub = resolveTrustedPemPath(cwd, pubPath);
  const pubPem = readFileSync(resolvedPub, 'utf8');
  if (!isInlinePemString(pubPem)) {
    throw new Error(`Policy signer public key must be a valid PUBLIC KEY PEM: ${pubPath}`);
  }
  const signerKid = sha256Str(pubPem).slice(0, 16);
  const admittedPub = trustStoreKeyAdmitted(trustPair.trusted, trustPair.revoked, signerKid);
  if (!admittedPub) {
    throw new Error(`Refusing to sign audit policy with untrusted or revoked keyId: ${signerKid}`);
  }
  const policyRaw = readFileSync(inPolicyPath, 'utf8');
  const payloadBuf = Buffer.from(policyRaw, 'utf8');
  const paeBuf = dsseV1Pae(AUDIT_POLICY_DSSE_PAYLOAD_TYPE, payloadBuf);
  const privPem = readFileSync(resolvedPriv, 'utf8');
  const sigB64 = cryptoSign(null, paeBuf, privPem).toString('base64');
  if (!ed25519VerifyBytes(pubPem, paeBuf, sigB64)) {
    throw new Error(`Policy signer private/public keypair mismatch: ${signerKid}`);
  }
  const env = {
    payloadType: AUDIT_POLICY_DSSE_PAYLOAD_TYPE,
    payload: payloadBuf.toString('base64'),
    signatures: [{keyid: signerKid, sig: sigB64}],
  };
  const parentDir = dirname(resolve(outPath));
  if (!existsSync(parentDir)) {
    mkdirSync(parentDir, {recursive: true});
  }
  writeFileSync(outPath, `${JSON.stringify(env)}\n`, 'utf8');
  const verified = loadSignedAuditPolicyJson(outPath, trustPair);
  return {
    signerKeyId: signerKid,
    verifiedKeyIds: verified.verifiedKeyIds,
    verifiedRoles: verified.verifiedRoles,
  };
}

function unionSortedStrings(
  a: ReadonlyArray<string>,
  b: ReadonlyArray<string>,
): string[] {
  return [...new Set([...a, ...b])].sort(codePointCompare);
}

/**
 * Monotonic policy tightening merge: CLI overrides can ONLY tighten (never weaken) a loaded policy!
 */
export function mergeAuditPolicyStrict(
  policy: AuditPolicyManifest | null,
  cli: FleetVerifyOptions,
): FleetVerifyOptions {
  if (!policy) return cli;
  if (
    policy.expectedSysmlSha256 !== undefined &&
    cli.expectedSysmlSha256 !== undefined &&
    policy.expectedSysmlSha256 !== cli.expectedSysmlSha256
  ) {
    throw new Error(
      `CLI --expected-sysml-sha256 conflicts with policy expectedSysmlSha256: cli=${cli.expectedSysmlSha256} policy=${policy.expectedSysmlSha256}`,
    );
  }
  if (
    policy.expectedSubjectCount !== undefined &&
    cli.expectedSubjectCount !== undefined &&
    policy.expectedSubjectCount !== cli.expectedSubjectCount
  ) {
    throw new Error(
      `CLI --expected-subject-count conflicts with policy expectedSubjectCount: cli=${cli.expectedSubjectCount} policy=${policy.expectedSubjectCount}`,
    );
  }
  if (
    policy.minSignatures !== undefined &&
    cli.minSignatures !== undefined &&
    cli.minSignatures < policy.minSignatures
  ) {
    throw new Error(
      `Refusing to weaken policy minSignatures via CLI --min-signatures: cli=${cli.minSignatures} policy=${policy.minSignatures}`,
    );
  }
  const mergedSubs = unionSortedStrings(policy.requiredSubjects, cli.requiredSubjects ?? []);
  const mergedSigners = unionSortedStrings(policy.requiredSigners, cli.requiredSigners ?? []);
  const mergedRoles = unionSortedStrings(policy.requiredRoles, cli.requiredRoles ?? []);
  const effMin =
    policy.minSignatures !== undefined && cli.minSignatures !== undefined
      ? Math.max(policy.minSignatures, cli.minSignatures)
      : (cli.minSignatures ?? policy.minSignatures);
  return {
    expectedSysmlSha256: cli.expectedSysmlSha256 ?? policy.expectedSysmlSha256,
    expectedSubjectCount: cli.expectedSubjectCount ?? policy.expectedSubjectCount,
    requiredSubjects: mergedSubs.length > 0 ? mergedSubs : undefined,
    minSignatures: effMin,
    requiredSigners: mergedSigners.length > 0 ? mergedSigners : undefined,
    requiredRoles: mergedRoles.length > 0 ? mergedRoles : undefined,
  };
}

function normalizeFleetOpts(
  optsOrSha?: string | FleetVerifyOptions,
): FleetVerifyOptions {
  if (typeof optsOrSha === 'string') return {expectedSysmlSha256: optsOrSha};
  return optsOrSha ?? {};
}

function checkFleetSubjectCoverage(
  subjects: ReadonlyArray<unknown>,
  opts: FleetVerifyOptions,
): boolean {
  const seenKeys = new Set<string>();
  for (const s of subjects) {
    if (!isPlainObject(s) || typeof s.subjectKey !== 'string' || s.subjectKey.length === 0) {
      return false;
    }
    if (seenKeys.has(s.subjectKey)) return false; // reject duplicate subjectKey padding!
    seenKeys.add(s.subjectKey);
  }
  if (opts.expectedSubjectCount !== undefined) {
    if (!Number.isInteger(opts.expectedSubjectCount) || opts.expectedSubjectCount < 1) {
      return false;
    }
    if (seenKeys.size !== opts.expectedSubjectCount) return false;
  }
  if (opts.requiredSubjects !== undefined) {
    for (const req of opts.requiredSubjects) {
      if (!seenKeys.has(req)) return false;
    }
  }
  return true;
}

export function verifyFleetOffline(
  fleetReportPath: string,
  trustPair: TrustPair,
  optsOrSha?: string | FleetVerifyOptions,
): boolean {
  const opts = normalizeFleetOpts(optsOrSha);
  if (!existsSync(fleetReportPath)) return false;
  const doc = readJsonObject(fleetReportPath);
  if (!doc) return false;
  if (opts.expectedSysmlSha256 !== undefined && doc.sysmlSha256 !== opts.expectedSysmlSha256) {
    return false;
  }
  const att = doc.attestation;
  const subjects = doc.subjects;
  if (!isPlainObject(att) || !Array.isArray(subjects) || subjects.length === 0) return false;
  if (!checkFleetSubjectCoverage(subjects, opts)) return false;
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

export interface CacheFreshnessOptions {
  maxAgeSeconds?: number;
  nowEpoch?: number;
  maxFutureSkewSeconds?: number;
}

/**
 * Pure deterministic anti-replay freshness window predicate matching `witness-epoch-fresh?` in
 * `library/verification-flow/attestation.ss`:
 *   - Lower bound (TTL expiry): `nowEpoch <= issuedEpoch + maxAgeSeconds`
 *   - Upper bound (future-clock forgery): `issuedEpoch <= nowEpoch + maxFutureSkewSeconds`
 */
export function witnessEpochFresh(
  issuedEpoch: unknown,
  nowEpoch: number,
  maxAgeSeconds?: number,
  maxFutureSkewSeconds = 60,
): boolean {
  if (maxAgeSeconds === undefined) return true;
  if (typeof issuedEpoch !== 'number' || !Number.isInteger(issuedEpoch) || issuedEpoch < 0) {
    return false;
  }
  if (!Number.isInteger(nowEpoch) || nowEpoch < 0) return false;
  if (!Number.isInteger(maxAgeSeconds) || maxAgeSeconds < 0) return false;
  if (!Number.isInteger(maxFutureSkewSeconds) || maxFutureSkewSeconds < 0) return false;
  return nowEpoch <= issuedEpoch + maxAgeSeconds && issuedEpoch <= nowEpoch + maxFutureSkewSeconds;
}

export function verifyCacheOffline(
  cachePath: string,
  trustPair: TrustPair,
  freshness: CacheFreshnessOptions = {},
): number | null {
  if (!existsSync(cachePath)) return null;
  const doc = readJsonObject(cachePath);
  if (!doc || !isPlainObject(doc.entries)) return null;
  const entries = Object.entries(doc.entries);
  if (entries.length === 0) return null;

  const effectiveNow = freshness.nowEpoch ?? Math.floor(Date.now() / 1000);
  const maxSkew = freshness.maxFutureSkewSeconds ?? 60;

  for (const [stepStr, rec] of entries) {
    if (!isPlainObject(rec)) return null;
    const pub = trustStoreKeyAdmitted(trustPair.trusted, trustPair.revoked, rec.keyId);
    if (!pub) return null;
    if (typeof rec.toolchainFingerprint !== 'string' || typeof rec.signature !== 'string') {
      return null;
    }
    if (!witnessEpochFresh(rec.issuedAtEpoch, effectiveNow, freshness.maxAgeSeconds, maxSkew)) {
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
  roleBindings: ReadonlyArray<readonly [string, string]> = [],
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
  const keyRoles: Record<string, string[]> = {};
  for (const [kid, role] of roleBindings) {
    if (!Object.prototype.hasOwnProperty.call(keysMap, kid)) {
      throw new Error(`Refusing to assign role to unknown keyId not in exported bundle: ${kid}`);
    }
    if (typeof role !== 'string' || role.length === 0) {
      throw new Error(`Invalid empty role name for keyId: ${kid}`);
    }
    const cur = keyRoles[kid] ?? [];
    if (!cur.includes(role)) {
      keyRoles[kid] = [...cur, role].sort(codePointCompare);
    }
  }
  const parentDir = dirname(resolve(outPath));
  if (!existsSync(parentDir)) {
    mkdirSync(parentDir, {recursive: true});
  }
  const doc: Record<string, unknown> = {
    schema: TRUST_STORE_SCHEMA,
    trustedKeys: keysMap,
    revokedKeyIds: revoked,
  };
  if (Object.keys(keyRoles).length > 0) {
    doc.keyRoles = keyRoles;
  }
  writeFileSync(outPath, `${JSON.stringify(doc)}\n`, 'utf8');
  return {active, revoked};
}

/**
 * Packs a 2-level Merkle Fleet report and ALL contained child subject reports into a single
 * self-contained `de.attestation.fleet-evidence-bundle.v1` JSON archive.
 * Enforces POSIX `lstat` containment, rejects duplicate paths, and checks Merkle digest binding.
 */
export function packFleetBundleOffline(fleetReportPath: string, outPath: string): number {
  if (typeof fleetReportPath !== 'string' || !existsSync(fleetReportPath)) {
    throw new Error(`Fleet report file not found: ${String(fleetReportPath)}`);
  }
  if (typeof outPath !== 'string' || outPath.length === 0) {
    throw new Error(`Invalid output fleet bundle path: ${String(outPath)}`);
  }
  const fleetDoc = readJsonObject(fleetReportPath);
  if (!fleetDoc || !Array.isArray(fleetDoc.subjects) || fleetDoc.subjects.length === 0) {
    throw new Error(`Invalid or empty fleet report subjects: ${fleetReportPath}`);
  }
  const fleetDir = dirname(resolve(fleetReportPath));
  const childReports: Record<string, Record<string, unknown>> = {};
  for (const s of fleetDoc.subjects) {
    if (!isPlainObject(s)) {
      throw new Error('Malformed subject entry in fleet report');
    }
    const rel = s.reportRelativePath;
    const childPath = resolveContainedChildReportPath(fleetDir, rel);
    if (!childPath || typeof rel !== 'string') {
      throw new Error(
        `Refusing to pack uncontained/symlink/missing child report: ${String(rel)}`,
      );
    }
    if (Object.prototype.hasOwnProperty.call(childReports, rel)) {
      throw new Error(`Duplicate child reportRelativePath in fleet report: ${rel}`);
    }
    const childDoc = readJsonObject(childPath);
    const catt = childDoc && isPlainObject(childDoc.attestation) ? childDoc.attestation : null;
    if (!childDoc || !catt || catt.payloadSha256 !== s.reportPayloadSha256) {
      throw new Error(`Child report Merkle payloadSha256 mismatch while packing: ${rel}`);
    }
    childReports[rel] = childDoc;
  }
  const parentDir = dirname(resolve(outPath));
  if (!existsSync(parentDir)) {
    mkdirSync(parentDir, {recursive: true});
  }
  const bundle = {
    schema: FLEET_BUNDLE_SCHEMA,
    fleetReport: fleetDoc,
    childReports,
  };
  writeFileSync(outPath, `${JSON.stringify(bundle)}\n`, 'utf8');
  return fleetDoc.subjects.length;
}

export interface VerifiedSubjectSummary {
  subjectKey: string;
  subjectId: string;
  keyId: string;
  evidenceCount: number;
}

export interface VerifiedFleetBundleSummary {
  fleetId: string;
  sysmlSha256: string;
  fleetPayloadSha256: string;
  rootKeyId: string;
  subjectCount: number;
  verifiedSubjects: VerifiedSubjectSummary[];
}

export interface IntotoVerificationStatement {
  _type: 'https://in-toto.io/Statement/v1';
  subject: Array<{name: string; digest: {sha256: string}}>;
  predicateType: 'https://deterministic-engineering.hardenedlinux.org/attestation/fleet-verification-summary/v1';
  predicate: {
    verifier: 'de.offline-attestation-verifier.v1';
    fleetId: string;
    sysmlSha256: string;
    fleetPayloadSha256: string;
    rootKeyId: string;
    subjectCount: number;
    verifiedSubjects: VerifiedSubjectSummary[];
  };
}

/**
 * Pure zero-disk-traversal verifier returning a cryptographically authenticated audit summary
 * on full verification pass, or `null` on any failure (never leaks unverified metadata).
 */
export function inspectFleetBundleVerified(
  bundlePath: string,
  trustPair: TrustPair,
  optsOrSha?: string | FleetVerifyOptions,
): VerifiedFleetBundleSummary | null {
  const opts = normalizeFleetOpts(optsOrSha);
  if (!existsSync(bundlePath)) return null;
  const bundle = readJsonObject(bundlePath);
  if (!bundle || bundle.schema !== FLEET_BUNDLE_SCHEMA) return null;
  const fleetDoc = bundle.fleetReport;
  const childReports = bundle.childReports;
  if (!isPlainObject(fleetDoc) || !isPlainObject(childReports)) return null;
  if (opts.expectedSysmlSha256 !== undefined && fleetDoc.sysmlSha256 !== opts.expectedSysmlSha256) {
    return null;
  }
  const att = fleetDoc.attestation;
  const subjects = fleetDoc.subjects;
  if (!isPlainObject(att) || !Array.isArray(subjects) || subjects.length === 0) return null;
  if (!checkFleetSubjectCoverage(subjects, opts)) return null;
  const fleetPub = trustStoreKeyAdmitted(trustPair.trusted, trustPair.revoked, att.keyId);
  if (!fleetPub || att.algorithm !== 'Ed25519' || typeof att.keyId !== 'string') return null;

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
  const fleetId = typeof fleetDoc.fleetId === 'string' ? fleetDoc.fleetId : '';
  const sysmlSha256 = typeof fleetDoc.sysmlSha256 === 'string' ? fleetDoc.sysmlSha256 : '';
  const canonical = canonicalFleetSigningPayload(fleetId, sysmlSha256, entries);
  if (sha256Str(canonical) !== att.payloadSha256) return null;
  if (!ed25519VerifyRaw(fleetPub, canonical, att.signature)) return null;

  const embeddedKeys = Object.keys(childReports);
  if (embeddedKeys.length !== subjects.length) return null;
  const seenRels = new Set<string>();
  const verifiedSubjects: VerifiedSubjectSummary[] = [];

  for (const s of subjects) {
    if (!isPlainObject(s)) return null;
    const rel = s.reportRelativePath;
    if (!safeRelativeChildPath(rel) || seenRels.has(rel)) return null;
    seenRels.add(rel);
    if (!Object.prototype.hasOwnProperty.call(childReports, rel)) return null;
    const childDoc = childReports[rel];
    if (!isPlainObject(childDoc)) return null;
    if (!verifyReportDocOffline(childDoc, trustPair)) return null;
    const catt = isPlainObject(childDoc.attestation) ? childDoc.attestation : null;
    if (!catt || catt.payloadSha256 !== s.reportPayloadSha256 || typeof catt.keyId !== 'string') {
      return null;
    }
    const ev = Array.isArray(childDoc.evidence) ? childDoc.evidence : [];
    verifiedSubjects.push({
      subjectKey: typeof s.subjectKey === 'string' ? s.subjectKey : '',
      subjectId: typeof s.subjectId === 'string' ? s.subjectId : '',
      keyId: catt.keyId,
      evidenceCount: ev.length,
    });
  }
  if (seenRels.size !== embeddedKeys.length) return null;
  verifiedSubjects.sort((a, b) => codePointCompare(a.subjectKey, b.subjectKey));
  return {
    fleetId,
    sysmlSha256,
    fleetPayloadSha256: att.payloadSha256,
    rootKeyId: att.keyId,
    subjectCount: verifiedSubjects.length,
    verifiedSubjects,
  };
}

export function buildIntotoVerificationStatement(
  summary: VerifiedFleetBundleSummary,
): IntotoVerificationStatement {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [
      {
        name: 'sysml:10.154-multi-method-funflow-runnable-architecture',
        digest: {sha256: summary.sysmlSha256},
      },
      {
        name: `fleet:${summary.fleetId}`,
        digest: {sha256: summary.fleetPayloadSha256},
      },
    ],
    predicateType:
      'https://deterministic-engineering.hardenedlinux.org/attestation/fleet-verification-summary/v1',
    predicate: {
      verifier: 'de.offline-attestation-verifier.v1',
      fleetId: summary.fleetId,
      sysmlSha256: summary.sysmlSha256,
      fleetPayloadSha256: summary.fleetPayloadSha256,
      rootKeyId: summary.rootKeyId,
      subjectCount: summary.subjectCount,
      verifiedSubjects: summary.verifiedSubjects,
    },
  };
}

function assertSafeStatementOutputPath(outPath: string): void {
  if (typeof outPath !== 'string' || outPath.length === 0) {
    throw new Error(`Invalid --emit-statement output path: ${String(outPath)}`);
  }
  try {
    const st = lstatSync(outPath);
    if (!st.isFile() || st.isSymbolicLink()) {
      throw new Error(`Refusing to write in-toto statement to symlink or non-regular path: ${outPath}`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
      throw err;
    }
  }
  const parent = dirname(resolve(outPath));
  if (parent !== '/' && parent !== '/tmp' && parent !== '/var') {
    try {
      const pst = lstatSync(parent);
      if (!pst.isDirectory() || pst.isSymbolicLink()) {
        throw new Error(
          `Refusing to write in-toto statement inside symlinked or non-directory parent: ${parent}`,
        );
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
        throw err;
      }
    }
  }
}

export function emitIntotoVerificationStatement(
  outPath: string,
  summary: VerifiedFleetBundleSummary,
): IntotoVerificationStatement {
  assertSafeStatementOutputPath(outPath);
  const parentDir = dirname(resolve(outPath));
  if (!existsSync(parentDir)) {
    mkdirSync(parentDir, {recursive: true});
  }
  const stmt = buildIntotoVerificationStatement(summary);
  writeFileSync(outPath, `${JSON.stringify(stmt)}\n`, 'utf8');
  return stmt;
}

/**
 * Pure zero-disk-traversal verifier for a self-contained single-file Fleet Evidence Bundle
 * (`de.attestation.fleet-evidence-bundle.v1`).
 */
export function verifyFleetBundleOffline(
  bundlePath: string,
  trustPair: TrustPair,
  optsOrSha?: string | FleetVerifyOptions,
): boolean {
  return inspectFleetBundleVerified(bundlePath, trustPair, optsOrSha) !== null;
}

export interface VerifiedDsseStatementSummary extends VerifiedFleetBundleSummary {
  verifiedKeyIds: string[];
  verifiedRoles: string[];
}

function ed25519VerifyBytes(pubPemOrPath: string, payloadBuf: Buffer, sigB64: unknown): boolean {
  if (typeof sigB64 !== 'string' || sigB64.length === 0) return false;
  if (sigB64.length % 4 !== 0 || !STRICT_BASE64_RE.test(sigB64)) return false;
  try {
    const pemStr = isInlinePemString(pubPemOrPath)
      ? pubPemOrPath
      : readFileSync(pubPemOrPath, 'utf8');
    const pubKey = createPublicKey(pemStr);
    const sigBuf = Buffer.from(sigB64, 'base64');
    if (sigBuf.length !== 64) return false;
    return cryptoVerify(null, payloadBuf, pubKey, sigBuf);
  } catch {
    return false;
  }
}

function intotoSubjectDigestMatches(
  subjects: unknown,
  targetName: string,
  expectedSha: string,
): boolean {
  if (!Array.isArray(subjects) || expectedSha.length === 0) return false;
  return subjects.some((s) => {
    if (!isPlainObject(s)) return false;
    const dig = s.digest;
    return s.name === targetName && isPlainObject(dig) && dig.sha256 === expectedSha;
  });
}

/**
 * Strict offline verifier for a standard DSSE v1 signed in-toto Verification Summary Statement.
 * Returns cryptographically authenticated summary on pass, or `null` on any failure (zero leakage).
 */
export function inspectDsseStatementVerified(
  dssePath: string,
  trustPair: TrustPair,
  optsOrSha?: string | FleetVerifyOptions,
): VerifiedDsseStatementSummary | null {
  const opts = normalizeFleetOpts(optsOrSha);
  const minSignatures = opts.minSignatures ?? 1;
  if (!Number.isInteger(minSignatures) || minSignatures < 1) return null;
  if (!existsSync(dssePath)) return null;
  const env = readJsonObject(dssePath);
  if (!env) return null;
  if (env.payloadType !== INTOTO_DSSE_PAYLOAD_TYPE) return null;
  const payloadB64 = env.payload;
  const sigs = env.signatures;
  if (
    typeof payloadB64 !== 'string' ||
    payloadB64.length === 0 ||
    payloadB64.length % 4 !== 0 ||
    !STRICT_BASE64_RE.test(payloadB64)
  ) {
    return null;
  }
  if (!Array.isArray(sigs) || sigs.length === 0) return null;

  const payloadBuf = Buffer.from(payloadB64, 'base64');
  const paeBuf = dsseV1Pae(INTOTO_DSSE_PAYLOAD_TYPE, payloadBuf);

  const verifiedKeyIds: string[] = [];
  for (const sigEntry of sigs) {
    if (!isPlainObject(sigEntry)) continue;
    const kid = sigEntry.keyid;
    const sig = sigEntry.sig;
    const pub = trustStoreKeyAdmitted(trustPair.trusted, trustPair.revoked, kid);
    if (pub && typeof kid === 'string' && ed25519VerifyBytes(pub, paeBuf, sig)) {
      if (!verifiedKeyIds.includes(kid)) verifiedKeyIds.push(kid);
    }
  }
  if (verifiedKeyIds.length < minSignatures) return null;
  if (opts.requiredSigners !== undefined) {
    for (const reqSigner of opts.requiredSigners) {
      if (!verifiedKeyIds.includes(reqSigner)) return null;
    }
  }
  const roleSet = new Set<string>();
  const keyRoles = trustPair.keyRoles ?? {};
  for (const kid of verifiedKeyIds) {
    const roles = keyRoles[kid];
    if (Array.isArray(roles)) {
      for (const r of roles) {
        if (typeof r === 'string' && r.length > 0) roleSet.add(r);
      }
    }
  }
  const verifiedRoles = [...roleSet].sort(codePointCompare);
  if (opts.requiredRoles !== undefined) {
    for (const reqRole of opts.requiredRoles) {
      if (!roleSet.has(reqRole)) return null;
    }
  }

  let stmt: unknown;
  try {
    stmt = JSON.parse(payloadBuf.toString('utf8'));
  } catch {
    return null;
  }
  if (!isPlainObject(stmt)) return null;
  if (stmt._type !== INTOTO_STATEMENT_TYPE || stmt.predicateType !== INTOTO_PREDICATE_TYPE) {
    return null;
  }
  const pred = stmt.predicate;
  if (!isPlainObject(pred)) return null;
  if (pred.verifier !== 'de.offline-attestation-verifier.v1') return null;

  const fleetId = pred.fleetId;
  const sysmlSha256 = pred.sysmlSha256;
  const fleetPayloadSha256 = pred.fleetPayloadSha256;
  const rootKeyId = pred.rootKeyId;
  const subjectCount = pred.subjectCount;
  const verifiedSubjectsRaw = pred.verifiedSubjects;

  if (
    typeof fleetId !== 'string' ||
    fleetId.length === 0 ||
    typeof sysmlSha256 !== 'string' ||
    sysmlSha256.length === 0 ||
    typeof fleetPayloadSha256 !== 'string' ||
    fleetPayloadSha256.length === 0 ||
    typeof rootKeyId !== 'string' ||
    rootKeyId.length === 0 ||
    typeof subjectCount !== 'number' ||
    !Number.isInteger(subjectCount) ||
    subjectCount < 1 ||
    !Array.isArray(verifiedSubjectsRaw) ||
    verifiedSubjectsRaw.length !== subjectCount
  ) {
    return null;
  }

  if (!intotoSubjectDigestMatches(stmt.subject, INTOTO_SYSML_SUBJECT_NAME, sysmlSha256)) {
    return null;
  }
  if (!intotoSubjectDigestMatches(stmt.subject, `fleet:${fleetId}`, fleetPayloadSha256)) {
    return null;
  }
  if (opts.expectedSysmlSha256 !== undefined && sysmlSha256 !== opts.expectedSysmlSha256) {
    return null;
  }
  if (!checkFleetSubjectCoverage(verifiedSubjectsRaw, opts)) {
    return null;
  }

  const verifiedSubjects: VerifiedSubjectSummary[] = [];
  for (const s of verifiedSubjectsRaw) {
    if (
      !isPlainObject(s) ||
      typeof s.subjectKey !== 'string' ||
      typeof s.subjectId !== 'string' ||
      typeof s.keyId !== 'string' ||
      typeof s.evidenceCount !== 'number' ||
      !Number.isInteger(s.evidenceCount) ||
      s.evidenceCount < 0
    ) {
      return null;
    }
    verifiedSubjects.push({
      subjectKey: s.subjectKey,
      subjectId: s.subjectId,
      keyId: s.keyId,
      evidenceCount: s.evidenceCount,
    });
  }
  verifiedKeyIds.sort(codePointCompare);
  return {
    fleetId,
    sysmlSha256,
    fleetPayloadSha256,
    rootKeyId,
    verifiedKeyIds,
    verifiedRoles,
    subjectCount,
    verifiedSubjects,
  };
}

export function verifyDsseStatementOffline(
  dssePath: string,
  trustPair: TrustPair,
  optsOrSha?: string | FleetVerifyOptions,
): boolean {
  return inspectDsseStatementVerified(dssePath, trustPair, optsOrSha) !== null;
}

export interface CosignDsseResult {
  cosignerKeyId: string;
  verifiedKeyIds: string[];
  signatureCount: number;
}

/**
 * Air-gapped offline DSSE v1 counter-signer (`--cosign-dsse-statement`):
 * Verifies the input DSSE envelope against `trustPair`, validates non-symlink keypair & active
 * admission, signs DSSE v1 PAE, self-verifies, deduplicates `keyid`, and writes `outPath` safely.
 */
export function cosignDsseStatementOffline(
  inDssePath: string,
  privPath: string,
  pubPath: string,
  trustPair: TrustPair,
  outPath: string,
  optsOrSha?: string | FleetVerifyOptions,
): CosignDsseResult {
  const preSummary = inspectDsseStatementVerified(inDssePath, trustPair, optsOrSha);
  if (preSummary === null) {
    throw new Error(`Refusing to cosign unverified or policy-failing DSSE envelope: ${inDssePath}`);
  }
  assertSafeStatementOutputPath(outPath);
  const cwd = process.cwd();
  const resolvedPriv = resolveTrustedPemPath(cwd, privPath);
  const resolvedPub = resolveTrustedPemPath(cwd, pubPath);
  const pubPem = readFileSync(resolvedPub, 'utf8');
  if (!isInlinePemString(pubPem)) {
    throw new Error(`Cosigner public key must be a valid PUBLIC KEY PEM: ${pubPath}`);
  }
  const cosignerKid = sha256Str(pubPem).slice(0, 16);
  const admittedPub = trustStoreKeyAdmitted(trustPair.trusted, trustPair.revoked, cosignerKid);
  if (!admittedPub) {
    throw new Error(`Refusing to cosign with untrusted or revoked keyId: ${cosignerKid}`);
  }
  const env = readJsonObject(inDssePath);
  if (!env || typeof env.payloadType !== 'string' || typeof env.payload !== 'string') {
    throw new Error(`Malformed DSSE envelope: ${inDssePath}`);
  }
  const payloadBuf = Buffer.from(env.payload, 'base64');
  const paeBuf = dsseV1Pae(env.payloadType, payloadBuf);
  const privPem = readFileSync(resolvedPriv, 'utf8');
  const newSig = cryptoSign(null, paeBuf, privPem).toString('base64');
  if (!ed25519VerifyBytes(pubPem, paeBuf, newSig)) {
    throw new Error(`Cosigner private/public keypair mismatch (self-verification failed): ${cosignerKid}`);
  }
  const priorSigs = Array.isArray(env.signatures) ? env.signatures : [];
  const keptSigs = priorSigs.filter((e) => isPlainObject(e) && e.keyid !== cosignerKid);
  const nextSigs = [...keptSigs, {keyid: cosignerKid, sig: newSig}];
  const nextEnv = {
    payloadType: env.payloadType,
    payload: env.payload,
    signatures: nextSigs,
  };
  const parentDir = dirname(resolve(outPath));
  if (!existsSync(parentDir)) {
    mkdirSync(parentDir, {recursive: true});
  }
  writeFileSync(outPath, `${JSON.stringify(nextEnv)}\n`, 'utf8');
  const postSummary = inspectDsseStatementVerified(outPath, trustPair, optsOrSha);
  if (postSummary === null) {
    throw new Error(`Post-cosign DSSE self-verification failed: ${outPath}`);
  }
  return {
    cosignerKeyId: cosignerKid,
    verifiedKeyIds: postSummary.verifiedKeyIds,
    signatureCount: nextSigs.length,
  };
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

function parseExportArgs(rest: string[]): {
  pubPaths: string[];
  revokedIds: string[];
  roleBindings: Array<[string, string]>;
} {
  const pubPaths: string[] = [];
  const revokedIds: string[] = [];
  const roleBindings: Array<[string, string]> = [];
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === '--revoke') {
      if (i + 1 >= rest.length) throw new Error('--revoke requires a keyId argument');
      revokedIds.push(rest[i + 1]);
      i += 1;
    } else if (rest[i] === '--role') {
      if (i + 1 >= rest.length) throw new Error('--role requires a <keyId>=<role> argument');
      const raw = rest[i + 1];
      const eq = raw.indexOf('=');
      if (eq <= 0 || eq >= raw.length - 1) {
        throw new Error(`--role requires <keyId>=<role> format, got: ${raw}`);
      }
      roleBindings.push([raw.slice(0, eq), raw.slice(eq + 1)]);
      i += 1;
    } else {
      pubPaths.push(rest[i]);
    }
  }
  return {pubPaths, revokedIds, roleBindings};
}

function parseNonNegIntFlag(flagName: string, raw: string | undefined): number {
  if (raw === undefined || !/^\d+$/.test(raw)) {
    throw new Error(`${flagName} requires a non-negative integer, got: ${String(raw)}`);
  }
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Error(`${flagName} out of safe non-negative integer range: ${raw}`);
  }
  return n;
}

export function runCli(argv: string[]): number {
  let jsonMode = false;
  let maxAgeSeconds: number | undefined;
  let nowEpoch: number | undefined;
  let maxFutureSkewSeconds = 60;
  let expectedSysmlSha256: string | undefined;
  let expectedSubjectCount: number | undefined;
  const requiredSubjects: string[] = [];
  let emitStatementPath: string | undefined;
  let minSignatures: number | undefined;
  const requiredSigners: string[] = [];
  const requiredRoles: string[] = [];
  let policyPath: string | undefined;
  let signedPolicyPath: string | undefined;
  const requiredPolicyRoles: string[] = [];
  let minPolicyVersion: number | undefined;
  const cleanArgs: string[] = [];
  try {
    for (let i = 0; i < argv.length; i += 1) {
      const a = argv[i];
      if (a === '--json') {
        jsonMode = true;
      } else if (a === '--max-age-seconds') {
        maxAgeSeconds = parseNonNegIntFlag('--max-age-seconds', argv[i + 1]);
        i += 1;
      } else if (a === '--now-epoch') {
        nowEpoch = parseNonNegIntFlag('--now-epoch', argv[i + 1]);
        i += 1;
      } else if (a === '--max-future-skew-seconds') {
        maxFutureSkewSeconds = parseNonNegIntFlag('--max-future-skew-seconds', argv[i + 1]);
        i += 1;
      } else if (a === '--expected-sysml-sha256') {
        const val = argv[i + 1];
        if (typeof val !== 'string' || val.length === 0) {
          throw new Error('--expected-sysml-sha256 requires a non-empty digest argument');
        }
        expectedSysmlSha256 = val;
        i += 1;
      } else if (a === '--expected-subject-count') {
        const n = parseNonNegIntFlag('--expected-subject-count', argv[i + 1]);
        if (n < 1) throw new Error('--expected-subject-count must be >= 1');
        expectedSubjectCount = n;
        i += 1;
      } else if (a === '--require-subject') {
        const val = argv[i + 1];
        if (typeof val !== 'string' || val.length === 0) {
          throw new Error('--require-subject requires a non-empty subjectKey argument');
        }
        if (!requiredSubjects.includes(val)) requiredSubjects.push(val);
        i += 1;
      } else if (a === '--emit-statement') {
        const val = argv[i + 1];
        if (typeof val !== 'string' || val.length === 0) {
          throw new Error('--emit-statement requires a non-empty output file path');
        }
        emitStatementPath = val;
        i += 1;
      } else if (a === '--min-signatures') {
        const n = parseNonNegIntFlag('--min-signatures', argv[i + 1]);
        if (n < 1) throw new Error('--min-signatures must be >= 1');
        minSignatures = n;
        i += 1;
      } else if (a === '--require-signer') {
        const val = argv[i + 1];
        if (typeof val !== 'string' || val.length === 0) {
          throw new Error('--require-signer requires a non-empty keyId argument');
        }
        if (!requiredSigners.includes(val)) requiredSigners.push(val);
        i += 1;
      } else if (a === '--require-role') {
        const val = argv[i + 1];
        if (typeof val !== 'string' || val.length === 0) {
          throw new Error('--require-role requires a non-empty role name');
        }
        if (!requiredRoles.includes(val)) requiredRoles.push(val);
        i += 1;
      } else if (a === '--policy') {
        const val = argv[i + 1];
        if (typeof val !== 'string' || val.length === 0) {
          throw new Error('--policy requires a non-empty policy manifest path');
        }
        policyPath = val;
        i += 1;
      } else if (a === '--signed-policy') {
        const val = argv[i + 1];
        if (typeof val !== 'string' || val.length === 0) {
          throw new Error('--signed-policy requires a non-empty signed policy envelope path');
        }
        signedPolicyPath = val;
        i += 1;
      } else if (a === '--require-policy-role') {
        const val = argv[i + 1];
        if (typeof val !== 'string' || val.length === 0) {
          throw new Error('--require-policy-role requires a non-empty role name');
        }
        if (!requiredPolicyRoles.includes(val)) requiredPolicyRoles.push(val);
        i += 1;
      } else if (a === '--min-policy-version') {
        const n = parseNonNegIntFlag('--min-policy-version', argv[i + 1]);
        if (n < 1) throw new Error('--min-policy-version must be >= 1');
        minPolicyVersion = n;
        i += 1;
      } else {
        cleanArgs.push(a);
      }
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (jsonMode) {
      emitJsonResult(false, 'cli-parse', '', '', msg);
    } else {
      process.stderr.write(`ERROR: ${msg}\n`);
    }
    return 1;
  }
  if (cleanArgs.length === 0) {
    process.stderr.write(
      'usage: [--json] --verify-report|--verify-fleet|--verify-fleet-bundle|--verify-cache [--max-age-seconds N] [--now-epoch T] <artifact.json> <trust-store.json> | [--json] --verify-trust-store <trust-store.json> | [--json] --export-trust-bundle <out.json> [--revoke <keyId>]... <pub1.pem>... | [--json] --pack-fleet-bundle <fleet-report.json> <out-bundle.json>\n',
    );
    return 1;
  }
  if (policyPath !== undefined && signedPolicyPath !== undefined) {
    const msg = 'Cannot combine --policy and --signed-policy';
    if (jsonMode) {
      emitJsonResult(false, 'policy-load', signedPolicyPath, policyPath, msg);
    } else {
      process.stderr.write(`ERROR: ${msg}\n`);
    }
    return 1;
  }
  const rawCliPolicyOpts: FleetVerifyOptions = {
    expectedSysmlSha256,
    expectedSubjectCount,
    requiredSubjects: requiredSubjects.length > 0 ? requiredSubjects : undefined,
    minSignatures,
    requiredSigners: requiredSigners.length > 0 ? requiredSigners : undefined,
    requiredRoles: requiredRoles.length > 0 ? requiredRoles : undefined,
  };
  let loadedPolicy: AuditPolicyManifest | null = null;
  let mergedPolicyOpts: FleetVerifyOptions = rawCliPolicyOpts;
  if (policyPath !== undefined) {
    try {
      loadedPolicy = loadAuditPolicyJson(policyPath);
      assertPolicyFreshnessAndVersion(loadedPolicy, minPolicyVersion, nowEpoch);
      mergedPolicyOpts = mergeAuditPolicyStrict(loadedPolicy, mergedPolicyOpts);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        emitJsonResult(false, 'policy-load', policyPath, policyPath, `audit policy error: ${msg}`);
      } else {
        process.stderr.write(`ERROR: ${msg}\n`);
      }
      return 1;
    }
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
      const {pubPaths, revokedIds, roleBindings} = parseExportArgs(cleanArgs.slice(2));
      const {active, revoked} = exportTrustBundleOffline(outPath, pubPaths, revokedIds, roleBindings);
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

  if (mode === '--pack-fleet-bundle') {
    if (cleanArgs.length !== 3) {
      process.stderr.write(
        'usage: [--json] --pack-fleet-bundle <fleet-report.json> <out-bundle.json>\n',
      );
      return 1;
    }
    const fleetPath = cleanArgs[1];
    const outPath = cleanArgs[2];
    try {
      const count = packFleetBundleOffline(fleetPath, outPath);
      if (jsonMode) {
        emitJsonResult(true, 'pack-fleet-bundle', fleetPath, outPath, 'packed-fleet-evidence-bundle', {
          subjects: count,
        });
      } else {
        process.stdout.write(`MULTI-METHOD-PACK-FLEET-BUNDLE-OK ${outPath} subjects=${count}\n`);
      }
      return 0;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        emitJsonResult(false, 'pack-fleet-bundle', fleetPath, outPath, `pack-fleet-bundle failed: ${msg}`);
      } else {
        process.stderr.write(`ERROR: ${msg}\n`);
      }
      return 1;
    }
  }

  if (mode === '--cosign-dsse-statement') {
    if (cleanArgs.length !== 6) {
      process.stderr.write(
        'usage: [--json] --cosign-dsse-statement <in.dsse.json> <priv.pem> <pub.pem> <trust-store.json> <out.dsse.json>\n',
      );
      return 1;
    }
    const inDsse = cleanArgs[1];
    const privPem = cleanArgs[2];
    const pubPem = cleanArgs[3];
    const storePath = cleanArgs[4];
    const outDsse = cleanArgs[5];
    try {
      const tp = loadTrustStoreJsonLite(storePath);
      const res = cosignDsseStatementOffline(inDsse, privPem, pubPem, tp, outDsse, mergedPolicyOpts);
      if (jsonMode) {
        emitJsonResult(
          true,
          'cosign-dsse-statement',
          outDsse,
          storePath,
          'cosigned-dsse-v1-intoto-statement',
          {
            cosignerKeyId: res.cosignerKeyId,
            verifiedKeyIds: res.verifiedKeyIds,
            signatureCount: res.signatureCount,
          },
        );
      } else {
        process.stdout.write(
          `MULTI-METHOD-COSIGN-DSSE-STATEMENT-OK ${outDsse} cosigner=${res.cosignerKeyId} verified=${res.verifiedKeyIds.length}\n`,
        );
      }
      return 0;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        emitJsonResult(
          false,
          'cosign-dsse-statement',
          inDsse,
          storePath,
          `cosign-dsse-statement failed: ${msg}`,
        );
      } else {
        process.stderr.write(`ERROR: ${msg}\n`);
      }
      return 1;
    }
  }

  if (mode === '--sign-policy') {
    if (cleanArgs.length !== 6) {
      process.stderr.write(
        'usage: [--json] --sign-policy <in-policy.json> <priv.pem> <pub.pem> <trust-store.json> <out-policy.dsse.json>\n',
      );
      return 1;
    }
    const inPol = cleanArgs[1];
    const privPem = cleanArgs[2];
    const pubPem = cleanArgs[3];
    const storePath = cleanArgs[4];
    const outDsse = cleanArgs[5];
    try {
      const tp = loadTrustStoreJsonLite(storePath);
      const res = signAuditPolicyOffline(inPol, privPem, pubPem, tp, outDsse);
      if (jsonMode) {
        emitJsonResult(true, 'sign-policy', outDsse, storePath, 'signed-dsse-v1-audit-policy', {
          signerKeyId: res.signerKeyId,
          verifiedKeyIds: res.verifiedKeyIds,
          verifiedRoles: res.verifiedRoles,
        });
      } else {
        process.stdout.write(`MULTI-METHOD-SIGN-POLICY-OK ${outDsse} signer=${res.signerKeyId}\n`);
      }
      return 0;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        emitJsonResult(false, 'sign-policy', inPol, storePath, `sign-policy failed: ${msg}`);
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
        const keyRoles = trustPair.keyRoles ?? {};
        emitJsonResult(
          true,
          'verify-trust-store',
          storePath,
          storePath,
          'trust-store-valid-with-active-keys',
          {
            activeKeyIds: active,
            revokedKeyIds: revoked,
            ...(Object.keys(keyRoles).length > 0 ? {keyRoles} : {}),
          },
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

  let signedPolicyMeta: VerifiedSignedAuditPolicy | null = null;
  if (signedPolicyPath !== undefined) {
    try {
      signedPolicyMeta = loadSignedAuditPolicyJson(signedPolicyPath, trustPair, requiredPolicyRoles);
      assertPolicyFreshnessAndVersion(signedPolicyMeta.policy, minPolicyVersion, nowEpoch);
      mergedPolicyOpts = mergeAuditPolicyStrict(signedPolicyMeta.policy, rawCliPolicyOpts);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        emitJsonResult(
          false,
          'signed-policy-load',
          signedPolicyPath,
          storePath,
          `signed audit policy error: ${msg}`,
        );
      } else {
        process.stderr.write(`ERROR: ${msg}\n`);
      }
      return 1;
    }
  }

  const fleetOpts: FleetVerifyOptions = mergedPolicyOpts;
  const fleetJsonExtra = (): Record<string, unknown> => {
    const extra: Record<string, unknown> = {};
    if (fleetOpts.expectedSysmlSha256 !== undefined) extra.expectedSysmlSha256 = fleetOpts.expectedSysmlSha256;
    if (fleetOpts.expectedSubjectCount !== undefined) extra.expectedSubjectCount = fleetOpts.expectedSubjectCount;
    if (fleetOpts.requiredSubjects && fleetOpts.requiredSubjects.length > 0) {
      extra.requiredSubjects = [...fleetOpts.requiredSubjects].sort(codePointCompare);
    }
    if (fleetOpts.minSignatures !== undefined && fleetOpts.minSignatures > 1) {
      extra.minSignatures = fleetOpts.minSignatures;
    }
    if (fleetOpts.requiredSigners && fleetOpts.requiredSigners.length > 0) {
      extra.requiredSigners = [...fleetOpts.requiredSigners].sort(codePointCompare);
    }
    if (fleetOpts.requiredRoles && fleetOpts.requiredRoles.length > 0) {
      extra.requiredRoles = [...fleetOpts.requiredRoles].sort(codePointCompare);
    }
    if (policyPath !== undefined) extra.policyPath = policyPath;
    const activePol = signedPolicyMeta?.policy ?? loadedPolicy;
    if (activePol?.policyVersion !== undefined) extra.policyVersion = activePol.policyVersion;
    if (activePol?.notAfterEpoch !== undefined) extra.policyNotAfterEpoch = activePol.notAfterEpoch;
    if (signedPolicyPath !== undefined && signedPolicyMeta !== null) {
      extra.signedPolicyPath = signedPolicyPath;
      extra.policySignerKeyIds = signedPolicyMeta.verifiedKeyIds;
      if (signedPolicyMeta.verifiedRoles.length > 0) {
        extra.policySignerRoles = signedPolicyMeta.verifiedRoles;
      }
    }
    return extra;
  };

  if (mode === '--verify-fleet') {
    if (verifyFleetOffline(targetPath, trustPair, fleetOpts)) {
      if (jsonMode) {
        emitJsonResult(
          true,
          'verify-fleet',
          targetPath,
          storePath,
          'authentic-2-level-merkle-fleet',
          fleetJsonExtra(),
        );
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

  if (mode === '--verify-fleet-bundle') {
    const summary = inspectFleetBundleVerified(targetPath, trustPair, fleetOpts);
    if (summary !== null) {
      if (emitStatementPath !== undefined) {
        try {
          emitIntotoVerificationStatement(emitStatementPath, summary);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          if (jsonMode) {
            emitJsonResult(
              false,
              'verify-fleet-bundle',
              targetPath,
              storePath,
              `statement export failed: ${msg}`,
            );
          } else {
            process.stderr.write(`ERROR: statement export failed: ${msg}\n`);
          }
          return 1;
        }
      }
      if (jsonMode) {
        emitJsonResult(
          true,
          'verify-fleet-bundle',
          targetPath,
          storePath,
          'authentic-self-contained-fleet-bundle',
          {
            ...fleetJsonExtra(),
            ...(emitStatementPath !== undefined ? {statementPath: emitStatementPath} : {}),
            fleetId: summary.fleetId,
            sysmlSha256: summary.sysmlSha256,
            fleetPayloadSha256: summary.fleetPayloadSha256,
            rootKeyId: summary.rootKeyId,
            subjectCount: summary.subjectCount,
            verifiedSubjects: summary.verifiedSubjects,
          },
        );
      } else {
        const suffix = emitStatementPath !== undefined ? ` statement=${emitStatementPath}` : '';
        process.stdout.write(`MULTI-METHOD-VERIFY-FLEET-BUNDLE-OK ${targetPath}${suffix}\n`);
      }
      return 0;
    }
    if (jsonMode) {
      emitJsonResult(
        false,
        'verify-fleet-bundle',
        targetPath,
        storePath,
        'offline fleet bundle verification failed',
      );
    } else {
      process.stderr.write(`ERROR: offline fleet bundle verification failed: ${targetPath}\n`);
    }
    return 1;
  }

  if (mode === '--verify-dsse-statement') {
    const summary = inspectDsseStatementVerified(targetPath, trustPair, fleetOpts);
    if (summary !== null) {
      if (jsonMode) {
        emitJsonResult(
          true,
          'verify-dsse-statement',
          targetPath,
          storePath,
          'authentic-dsse-v1-intoto-statement',
          {
            ...fleetJsonExtra(),
            fleetId: summary.fleetId,
            sysmlSha256: summary.sysmlSha256,
            fleetPayloadSha256: summary.fleetPayloadSha256,
            rootKeyId: summary.rootKeyId,
            verifiedKeyIds: summary.verifiedKeyIds,
            ...(summary.verifiedRoles.length > 0 || requiredRoles.length > 0
              ? {verifiedRoles: summary.verifiedRoles}
              : {}),
            subjectCount: summary.subjectCount,
            verifiedSubjects: summary.verifiedSubjects,
          },
        );
      } else {
        process.stdout.write(`MULTI-METHOD-VERIFY-DSSE-STATEMENT-OK ${targetPath}\n`);
      }
      return 0;
    }
    if (jsonMode) {
      emitJsonResult(
        false,
        'verify-dsse-statement',
        targetPath,
        storePath,
        'offline DSSE v1 in-toto statement verification failed',
      );
    } else {
      process.stderr.write(
        `ERROR: offline DSSE v1 in-toto statement verification failed: ${targetPath}\n`,
      );
    }
    return 1;
  }

  if (mode === '--verify-cache') {
    const effNow = nowEpoch ?? Math.floor(Date.now() / 1000);
    const n = verifyCacheOffline(targetPath, trustPair, {
      maxAgeSeconds,
      nowEpoch: effNow,
      maxFutureSkewSeconds,
    });
    if (n !== null) {
      if (jsonMode) {
        const extra: Record<string, unknown> =
          maxAgeSeconds !== undefined
            ? {entries: n, maxAgeSeconds, nowEpoch: effNow}
            : {entries: n};
        emitJsonResult(true, 'verify-cache', targetPath, storePath, 'all-cache-witnesses-verified', extra);
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

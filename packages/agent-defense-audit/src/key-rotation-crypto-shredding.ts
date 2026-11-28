// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * Phase 43 (10.191): Business Extension B16 — Zero-Downtime AEAD Key Rotation,
 * Forward-Secure Envelope Re-Wrapping & Cryptographic Erasure (Crypto-Shredding).
 *
 * Resolves the classic paradox between immutable content-addressed `M1` Merkle
 * audit logs and GDPR/compliance right-to-erasure:
 *   1. `RotatableTenantAeadKeyRing`: 13th R3 non-leakable M3 capability class
 *      holding real 256-bit AES-256-GCM epoch keys in transient M3 memory.
 *   2. Active-epoch-only encryption: new writes MUST target `activeEpoch`;
 *      retired/stale epochs refuse new encryption.
 *   3. Lossless zero-downtime re-wrapping: decrypts envelope from non-shredded
 *      epoch `e_old`, re-encrypts under `activeEpoch > e_old` with fresh 96-bit
 *      IV & AAD binding `(tenantId, activeEpoch, recordId)`, verifies plaintext
 *      SHA-256 parity, and pins an `M1` `KeyRotationRewrapReceipt`.
 *   4. Physical cryptographic erasure (`cryptoShredEpoch`): overwrites key bytes
 *      with `Buffer.fill(0)`, removes the epoch key, records permanent shred
 *      tombstone in `M1` — making historical ciphertexts permanently unreadable
 *      while leaving the `M1` Merkle DAG structure and audit root 100% intact!
 */

import {createCipheriv, createDecipheriv, randomBytes} from 'node:crypto';
import {
  ContentAddressedKvStore,
  M3_NON_SERIALIZABLE_CAPABILITY,
  sha256Digest,
} from './durable-merkle-store.ts';

export interface RotatableAeadEnvelope {
  readonly tenantId: string;
  readonly keyEpoch: number;
  readonly recordId: string;
  readonly ivHex: string;
  readonly authTagHex: string;
  readonly ciphertextHex: string;
  readonly plaintextDigestHex: string;
  readonly envelopeMerkleHash: string;
}

export type KeyRotationEncryptVerdict =
  | {kind: 'Proven'; envelope: RotatableAeadEnvelope}
  | {kind: 'Refuted'; reason: 'stale-or-mismatched-write-epoch' | 'epoch-crypto-shredded'; detail: string};

export type KeyRotationDecryptVerdict =
  | {kind: 'Proven'; plaintextJson: string; plaintextDigestHex: string; keyEpoch: number}
  | {
      kind: 'Refuted';
      reason:
        | 'tenant-aad-mismatch'
        | 'epoch-crypto-shredded'
        | 'unknown-key-epoch'
        | 'aead-authentication-failed';
      detail: string;
    };

export type KeyRotationRewrapVerdict =
  | {
      kind: 'Proven';
      rewrappedEnvelope: RotatableAeadEnvelope;
      fromEpoch: number;
      toEpoch: number;
      rewrapReceiptHash: string;
    }
  | {
      kind: 'Refuted';
      reason:
        | 'rewrap-epoch-not-strictly-advancing'
        | 'tenant-aad-mismatch'
        | 'epoch-crypto-shredded'
        | 'unknown-key-epoch'
        | 'aead-authentication-failed';
      detail: string;
    };

export interface CryptoShredTombstone {
  readonly tenantId: string;
  readonly shreddedEpoch: number;
  readonly shredReason: string;
  readonly tombstoneMerkleHash: string;
}

function buildAad(tenantId: string, keyEpoch: number, recordId: string): Buffer {
  return Buffer.from(`b16-aead-v1::${tenantId}::epoch=${keyEpoch}::rec=${recordId}`, 'utf8');
}

/**
 * 13th R3 non-leakable M3 capability class: Multi-epoch AES-256-GCM tenant key ring
 * supporting zero-downtime key rotation, lossless re-wrapping, and physical zeroization.
 */
export class RotatableTenantAeadKeyRing {
  readonly [M3_NON_SERIALIZABLE_CAPABILITY] = true;
  readonly mutability = 'M3-mutable-root' as const;
  readonly capabilityId: string;

  private activeEpochValue = 1;
  private readonly epochKeys = new Map<number, Buffer>();
  private readonly shreddedEpochs = new Set<number>();

  constructor(readonly tenantId: string, initialEpoch = 1) {
    if (!Number.isInteger(initialEpoch) || initialEpoch < 1) {
      throw new Error(`Invalid initial key epoch: ${initialEpoch}`);
    }
    this.capabilityId = `rotatable-aead-keyring:${tenantId}`;
    this.activeEpochValue = initialEpoch;
    this.epochKeys.set(initialEpoch, randomBytes(32));
  }

  get activeEpoch(): number {
    return this.activeEpochValue;
  }

  isEpochShredded(epoch: number): boolean {
    return this.shreddedEpochs.has(epoch);
  }

  rotateEpoch(): number {
    const nextEpoch = this.activeEpochValue + 1;
    this.epochKeys.set(nextEpoch, randomBytes(32));
    this.activeEpochValue = nextEpoch;
    return nextEpoch;
  }

  encryptEnvelope(params: {
    kv: ContentAddressedKvStore;
    recordId: string;
    plaintext: unknown;
    requestedWriteEpoch?: number;
  }): KeyRotationEncryptVerdict {
    const targetEpoch = params.requestedWriteEpoch ?? this.activeEpochValue;
    if (this.shreddedEpochs.has(targetEpoch)) {
      return {
        kind: 'Refuted',
        reason: 'epoch-crypto-shredded',
        detail: `Epoch ${targetEpoch} for tenant '${this.tenantId}' is crypto-shredded`,
      };
    }
    if (targetEpoch !== this.activeEpochValue) {
      return {
        kind: 'Refuted',
        reason: 'stale-or-mismatched-write-epoch',
        detail: `Write epoch ${targetEpoch} != active epoch ${this.activeEpochValue}`,
      };
    }
    const keyBuf = this.epochKeys.get(targetEpoch);
    if (!keyBuf) {
      return {
        kind: 'Refuted',
        reason: 'epoch-crypto-shredded',
        detail: `Missing key bytes for epoch ${targetEpoch}`,
      };
    }

    const plaintextJson = JSON.stringify(params.plaintext);
    const plaintextDigestHex = sha256Digest(plaintextJson);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', keyBuf, iv);
    cipher.setAAD(buildAad(this.tenantId, targetEpoch, params.recordId));
    const encrypted = Buffer.concat([cipher.update(plaintextJson, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const envelopeBody = {
      tenantId: this.tenantId,
      keyEpoch: targetEpoch,
      recordId: params.recordId,
      ivHex: iv.toString('hex'),
      authTagHex: authTag.toString('hex'),
      ciphertextHex: encrypted.toString('hex'),
      plaintextDigestHex,
    };
    const envelopeMerkleHash = params.kv.putBlob('b16-rotatable-aead-envelope', envelopeBody, []);
    params.kv.pinHistoricalCut(envelopeMerkleHash);

    return {
      kind: 'Proven',
      envelope: {
        ...envelopeBody,
        envelopeMerkleHash,
      },
    };
  }

  decryptEnvelope(envelope: RotatableAeadEnvelope): KeyRotationDecryptVerdict {
    if (envelope.tenantId !== this.tenantId) {
      return {
        kind: 'Refuted',
        reason: 'tenant-aad-mismatch',
        detail: `Envelope tenant '${envelope.tenantId}' != keyring tenant '${this.tenantId}'`,
      };
    }
    if (this.shreddedEpochs.has(envelope.keyEpoch)) {
      return {
        kind: 'Refuted',
        reason: 'epoch-crypto-shredded',
        detail: `Epoch ${envelope.keyEpoch} for tenant '${this.tenantId}' was crypto-shredded`,
      };
    }
    const keyBuf = this.epochKeys.get(envelope.keyEpoch);
    if (!keyBuf) {
      return {
        kind: 'Refuted',
        reason: 'unknown-key-epoch',
        detail: `Epoch ${envelope.keyEpoch} not loaded in keyring '${this.tenantId}'`,
      };
    }

    let plaintextJson = '';
    try {
      const decipher = createDecipheriv(
        'aes-256-gcm',
        keyBuf,
        Buffer.from(envelope.ivHex, 'hex'),
      );
      decipher.setAAD(buildAad(this.tenantId, envelope.keyEpoch, envelope.recordId));
      decipher.setAuthTag(Buffer.from(envelope.authTagHex, 'hex'));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertextHex, 'hex')),
        decipher.final(),
      ]);
      plaintextJson = decrypted.toString('utf8');
    } catch (err) {
      return {
        kind: 'Refuted',
        reason: 'aead-authentication-failed',
        detail: `AES-256-GCM auth failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    const digest = sha256Digest(plaintextJson);
    return {
      kind: 'Proven',
      plaintextJson,
      plaintextDigestHex: digest,
      keyEpoch: envelope.keyEpoch,
    };
  }

  rewrapEnvelopeToActiveEpoch(params: {
    kv: ContentAddressedKvStore;
    envelope: RotatableAeadEnvelope;
  }): KeyRotationRewrapVerdict {
    if (this.activeEpochValue <= params.envelope.keyEpoch) {
      return {
        kind: 'Refuted',
        reason: 'rewrap-epoch-not-strictly-advancing',
        detail: `Active epoch ${this.activeEpochValue} does not strictly advance past envelope epoch ${params.envelope.keyEpoch}`,
      };
    }
    const dec = this.decryptEnvelope(params.envelope);
    if (dec.kind !== 'Proven') {
      return dec;
    }

    const parsedPlaintext = JSON.parse(dec.plaintextJson);
    const enc = this.encryptEnvelope({
      kv: params.kv,
      recordId: params.envelope.recordId,
      plaintext: parsedPlaintext,
      requestedWriteEpoch: this.activeEpochValue,
    });
    if (enc.kind !== 'Proven') {
      return {
        kind: 'Refuted',
        reason: 'epoch-crypto-shredded',
        detail: enc.detail,
      };
    }
    if (enc.envelope.plaintextDigestHex !== params.envelope.plaintextDigestHex) {
      throw new Error('Invariant breach: lossless rewrap mutated plaintext digest');
    }

    const rewrapReceiptHash = params.kv.putBlob(
      'b16-key-rotation-rewrap-receipt',
      {
        tenantId: this.tenantId,
        recordId: params.envelope.recordId,
        fromEpoch: params.envelope.keyEpoch,
        toEpoch: this.activeEpochValue,
        sourceEnvelopeHash: params.envelope.envelopeMerkleHash,
        targetEnvelopeHash: enc.envelope.envelopeMerkleHash,
        preservedPlaintextDigestHex: enc.envelope.plaintextDigestHex,
      },
      [params.envelope.envelopeMerkleHash, enc.envelope.envelopeMerkleHash],
    );
    params.kv.pinHistoricalCut(rewrapReceiptHash);

    return {
      kind: 'Proven',
      rewrappedEnvelope: enc.envelope,
      fromEpoch: params.envelope.keyEpoch,
      toEpoch: this.activeEpochValue,
      rewrapReceiptHash,
    };
  }

  /**
   * Cryptographic Erasure (GDPR Right-to-be-Forgotten over immutable M1 Merkle logs):
   * Physically overwrites key bytes with zeros (`Buffer.fill(0)`), evicts the epoch key,
   * and pins an immutable `M1` `CryptoShredTombstone` without breaking Merkle audit hashes.
   */
  cryptoShredEpoch(params: {
    kv: ContentAddressedKvStore;
    epoch: number;
    reason: string;
  }): CryptoShredTombstone {
    const existing = this.epochKeys.get(params.epoch);
    if (existing) {
      existing.fill(0); // Physical zeroization of transient M3 key bytes
      this.epochKeys.delete(params.epoch);
    }
    this.shreddedEpochs.add(params.epoch);

    const tombstoneMerkleHash = params.kv.putBlob(
      'b16-crypto-shred-tombstone',
      {
        tenantId: this.tenantId,
        shreddedEpoch: params.epoch,
        shredReason: params.reason,
        physicalZeroizationCompleted: true,
      },
      [],
    );
    params.kv.pinHistoricalCut(tombstoneMerkleHash);

    return {
      tenantId: this.tenantId,
      shreddedEpoch: params.epoch,
      shredReason: params.reason,
      tombstoneMerkleHash,
    };
  }

  toJSON(): never {
    throw new Error(
      `R3 ReachabilityLeakError: RotatableTenantAeadKeyRing '${this.capabilityId}' is non-serializable and cannot enter M1 persistence`,
    );
  }
}

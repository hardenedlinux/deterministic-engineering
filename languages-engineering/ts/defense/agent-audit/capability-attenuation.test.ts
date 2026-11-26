// SPDX-FileCopyrightText: 2026 hardenedlinux Linux Team and Contributors
// SPDX-License-Identifier: LGPL-2.1-or-later

import {describe, expect, test} from 'bun:test';
import {ContentAddressedKvStore} from './durable-merkle-store.ts';
import {
  CapabilityDelegationAuthority,
  DelegationRootKey,
  isPathWithinPrefix,
} from './capability-attenuation.ts';

describe('Phase 12 Cross-Trust-Boundary Delegation, Macaroon Attenuation & Cascading Revocation (10.160 / 30.05 AG66-AG70)', () => {
  test('AG66: Multi-hop monotonic attenuation chain (Coordinator -> Contractor -> ToolWorker) succeeds with full M1 custody lineage', () => {
    const kv = new ContentAddressedKvStore();
    const rootKey = new DelegationRootKey('org-alpha-root');
    const auth = new CapabilityDelegationAuthority(kv, rootKey);

    const rootCert = auth.mintRootCertificate({
      certId: 'cert-root',
      rootAuthorityId: 'human-platform-admin',
      delegateeId: 'coordinator-agent',
      caveats: {
        allowedPathPrefixes: ['/repo/src', '/repo/docs'],
        allowedActions: ['read', 'write', 'execute'],
        expiresAtEpoch: 1000,
        remainingHops: 2,
        delegatable: true,
      },
      issuedAtEpoch: 100,
    });

    const hop1 = auth.attenuateAndDelegate({
      certId: 'cert-contractor-a',
      parentCert: rootCert,
      delegateeId: 'contractor-parser-agent',
      childCaveats: {
        allowedPathPrefixes: ['/repo/src/parser'],
        allowedActions: ['read', 'write'],
        expiresAtEpoch: 500,
        remainingHops: 1,
        delegatable: true,
      },
      issuedAtEpoch: 110,
    });
    expect(hop1.kind).toBe('Delegated');
    if (hop1.kind !== 'Delegated') throw new Error('expected Delegated');

    const hop2 = auth.attenuateAndDelegate({
      certId: 'cert-tool-worker',
      parentCert: hop1.cert,
      delegateeId: 'third-party-ast-linter',
      childCaveats: {
        allowedPathPrefixes: ['/repo/src/parser/lexer'],
        allowedActions: ['read'],
        expiresAtEpoch: 300,
        remainingHops: 0,
        delegatable: false,
      },
      issuedAtEpoch: 120,
    });
    expect(hop2.kind).toBe('Delegated');
    if (hop2.kind !== 'Delegated') throw new Error('expected Delegated');

    // Authorized read within narrowed scope:
    const ok = auth.authorizeDelegatedAction({
      chain: [rootCert, hop1.cert, hop2.cert],
      callerId: 'third-party-ast-linter',
      targetPath: '/repo/src/parser/lexer/tokens.ts',
      action: 'read',
      nowEpoch: 200,
    });
    expect(ok.kind).toBe('Authorized');
    if (ok.kind === 'Authorized') {
      expect(ok.receipt.custodyLineage).toEqual([
        'human-platform-admin',
        'coordinator-agent',
        'contractor-parser-agent',
        'third-party-ast-linter',
      ]);
      expect(kv.hasBlob(ok.receipt.receiptMerkleHash)).toBe(true);
    }

    // Attempted write or sibling path escape blocked at consumption time:
    expect(
      auth.authorizeDelegatedAction({
        chain: [rootCert, hop1.cert, hop2.cert],
        callerId: 'third-party-ast-linter',
        targetPath: '/repo/src/parser/lexer/tokens.ts',
        action: 'write',
        nowEpoch: 200,
      }),
    ).toEqual({kind: 'Refuted', reason: 'action-out-of-scope'});

    // Segment-boundary prefix safety: `/repo/src/parser/lexer-evil` must NOT match `/repo/src/parser/lexer`!
    expect(isPathWithinPrefix('/repo/src/parser/lexer-evil/x.ts', '/repo/src/parser/lexer')).toBe(
      false,
    );
    expect(
      auth.authorizeDelegatedAction({
        chain: [rootCert, hop1.cert, hop2.cert],
        callerId: 'third-party-ast-linter',
        targetPath: '/repo/src/parser/lexer-evil/secrets.ts',
        action: 'read',
        nowEpoch: 200,
      }),
    ).toEqual({kind: 'Refuted', reason: 'path-out-of-scope'});
  });

  test('AG67: Privilege amplification (action/path/TTL widening, non-delegable re-delegation, hop overflow) is deterministically refused', () => {
    const kv = new ContentAddressedKvStore();
    const auth = new CapabilityDelegationAuthority(kv, new DelegationRootKey('org-beta'));

    const parent = auth.mintRootCertificate({
      certId: 'cert-parent',
      rootAuthorityId: 'admin',
      delegateeId: 'contractor',
      caveats: {
        allowedPathPrefixes: ['/repo/src/parser'],
        allowedActions: ['read'],
        expiresAtEpoch: 400,
        remainingHops: 1,
        delegatable: true,
      },
      issuedAtEpoch: 100,
    });

    // 1. Action amplification (`read` -> `write`) refused:
    expect(
      auth.attenuateAndDelegate({
        certId: 'esc-action',
        parentCert: parent,
        delegateeId: 'sub-1',
        childCaveats: {
          allowedPathPrefixes: ['/repo/src/parser'],
          allowedActions: ['read', 'write'],
          expiresAtEpoch: 300,
          remainingHops: 0,
          delegatable: false,
        },
        issuedAtEpoch: 105,
      }),
    ).toEqual({kind: 'Refuted', reason: 'scope-escalation-action'});

    // 2. Path escape (`/repo/src/parser` -> `/repo/src/parser-evil` or `/etc`) refused:
    expect(
      auth.attenuateAndDelegate({
        certId: 'esc-path',
        parentCert: parent,
        delegateeId: 'sub-2',
        childCaveats: {
          allowedPathPrefixes: ['/repo/src/parser-evil'],
          allowedActions: ['read'],
          expiresAtEpoch: 300,
          remainingHops: 0,
          delegatable: false,
        },
        issuedAtEpoch: 105,
      }),
    ).toEqual({kind: 'Refuted', reason: 'scope-escalation-path'});

    // 3. TTL widening (`400` -> `999`) refused:
    expect(
      auth.attenuateAndDelegate({
        certId: 'esc-ttl',
        parentCert: parent,
        delegateeId: 'sub-3',
        childCaveats: {
          allowedPathPrefixes: ['/repo/src/parser'],
          allowedActions: ['read'],
          expiresAtEpoch: 999,
          remainingHops: 0,
          delegatable: false,
        },
        issuedAtEpoch: 105,
      }),
    ).toEqual({kind: 'Refuted', reason: 'ttl-escalation-forbidden'});

    // 4. Non-decreasing hop budget (`1` -> `1`) refused:
    expect(
      auth.attenuateAndDelegate({
        certId: 'esc-hop',
        parentCert: parent,
        delegateeId: 'sub-4',
        childCaveats: {
          allowedPathPrefixes: ['/repo/src/parser'],
          allowedActions: ['read'],
          expiresAtEpoch: 300,
          remainingHops: 1,
          delegatable: true,
        },
        issuedAtEpoch: 105,
      }),
    ).toEqual({kind: 'Refuted', reason: 'hop-budget-exhausted'});

    // 5. Leaf with `delegatable: false` cannot re-delegate:
    const leafRes = auth.attenuateAndDelegate({
      certId: 'leaf-non-delegable',
      parentCert: parent,
      delegateeId: 'leaf-worker',
      childCaveats: {
        allowedPathPrefixes: ['/repo/src/parser'],
        allowedActions: ['read'],
        expiresAtEpoch: 300,
        remainingHops: 0,
        delegatable: false,
      },
      issuedAtEpoch: 105,
    });
    if (leafRes.kind !== 'Delegated') throw new Error('expected Delegated');
    expect(
      auth.attenuateAndDelegate({
        certId: 'illegal-re-delegate',
        parentCert: leafRes.cert,
        delegateeId: 'shadow-sub',
        childCaveats: {
          allowedPathPrefixes: ['/repo/src/parser'],
          allowedActions: ['read'],
          expiresAtEpoch: 200,
          remainingHops: 0,
          delegatable: false,
        },
        issuedAtEpoch: 106,
      }),
    ).toEqual({kind: 'Refuted', reason: 'parent-not-delegatable'});
  });

  test('AG68: Cryptographic Macaroon HMAC chain catches forged/stripped ancestor caveats & bearer-theft hijacking', () => {
    const kv = new ContentAddressedKvStore();
    const auth = new CapabilityDelegationAuthority(kv, new DelegationRootKey('org-gamma'));

    const rootCert = auth.mintRootCertificate({
      certId: 'cert-root',
      rootAuthorityId: 'admin',
      delegateeId: 'coordinator',
      caveats: {
        allowedPathPrefixes: ['/repo'],
        allowedActions: ['read', 'write'],
        expiresAtEpoch: 500,
        remainingHops: 2,
        delegatable: true,
      },
      issuedAtEpoch: 10,
    });

    const childRes = auth.attenuateAndDelegate({
      certId: 'cert-child',
      parentCert: rootCert,
      delegateeId: 'trusted-worker',
      childCaveats: {
        allowedPathPrefixes: ['/repo/docs'],
        allowedActions: ['read'],
        expiresAtEpoch: 250,
        remainingHops: 0,
        delegatable: false,
      },
      issuedAtEpoch: 15,
    });
    if (childRes.kind !== 'Delegated') throw new Error('expected Delegated');

    // 1. Bearer theft: hijacking agent presents `trusted-worker`'s certificate!
    expect(
      auth.authorizeDelegatedAction({
        chain: [rootCert, childRes.cert],
        callerId: 'malicious-peer-agent',
        targetPath: '/repo/docs/guide.md',
        action: 'read',
        nowEpoch: 50,
      }),
    ).toEqual({kind: 'Refuted', reason: 'bearer-identity-mismatch'});

    // 2. Caveat tampering: attacker mutates `allowedActions` to include `'write'` without knowing root key!
    const tamperedChild = {
      ...childRes.cert,
      caveats: {
        ...childRes.cert.caveats,
        allowedActions: ['read', 'write'] as ('read' | 'write')[],
      },
    };
    expect(
      auth.authorizeDelegatedAction({
        chain: [rootCert, tamperedChild],
        callerId: 'trusted-worker',
        targetPath: '/repo/docs/guide.md',
        action: 'write',
        nowEpoch: 50,
      }),
    ).toEqual({kind: 'Refuted', reason: 'chain-mac-tampered'});

    // 3. TTL expiry caught at consumption time:
    expect(
      auth.authorizeDelegatedAction({
        chain: [rootCert, childRes.cert],
        callerId: 'trusted-worker',
        targetPath: '/repo/docs/guide.md',
        action: 'read',
        nowEpoch: 251,
      }),
    ).toEqual({kind: 'Refuted', reason: 'capability-expired'});
  });

  test('AG69: Cascading ancestor revocation invalidates compromised downstream subtree while keeping sibling branch alive', () => {
    const kv = new ContentAddressedKvStore();
    const auth = new CapabilityDelegationAuthority(kv, new DelegationRootKey('org-delta'));

    const rootCert = auth.mintRootCertificate({
      certId: 'cert-root',
      rootAuthorityId: 'admin',
      delegateeId: 'coordinator',
      caveats: {
        allowedPathPrefixes: ['/repo'],
        allowedActions: ['read', 'write'],
        expiresAtEpoch: 1000,
        remainingHops: 3,
        delegatable: true,
      },
      issuedAtEpoch: 1,
    });

    // Branch A: Coordinator -> Contractor-A -> ToolWorker-C
    const contractorA = auth.attenuateAndDelegate({
      certId: 'cert-contractor-a',
      parentCert: rootCert,
      delegateeId: 'contractor-a',
      childCaveats: {
        allowedPathPrefixes: ['/repo/service-a'],
        allowedActions: ['read', 'write'],
        expiresAtEpoch: 800,
        remainingHops: 2,
        delegatable: true,
      },
      issuedAtEpoch: 2,
    });
    if (contractorA.kind !== 'Delegated') throw new Error('expected Delegated');

    const workerC = auth.attenuateAndDelegate({
      certId: 'cert-worker-c',
      parentCert: contractorA.cert,
      delegateeId: 'tool-worker-c',
      childCaveats: {
        allowedPathPrefixes: ['/repo/service-a/src'],
        allowedActions: ['read'],
        expiresAtEpoch: 600,
        remainingHops: 0,
        delegatable: false,
      },
      issuedAtEpoch: 3,
    });
    if (workerC.kind !== 'Delegated') throw new Error('expected Delegated');

    // Sibling Branch B: Coordinator -> Contractor-B
    const contractorB = auth.attenuateAndDelegate({
      certId: 'cert-contractor-b',
      parentCert: rootCert,
      delegateeId: 'contractor-b',
      childCaveats: {
        allowedPathPrefixes: ['/repo/service-b'],
        allowedActions: ['read'],
        expiresAtEpoch: 800,
        remainingHops: 0,
        delegatable: false,
      },
      issuedAtEpoch: 4,
    });
    if (contractorB.kind !== 'Delegated') throw new Error('expected Delegated');

    // Revoke intermediate `contractor-a` certificate in live M3 registry!
    auth.revokeCertificate(contractorA.cert.certMerkleHash);

    // Downstream `tool-worker-c` is INSTANTLY invalidated via cascading revocation!
    const revokedRes = auth.authorizeDelegatedAction({
      chain: [rootCert, contractorA.cert, workerC.cert],
      callerId: 'tool-worker-c',
      targetPath: '/repo/service-a/src/index.ts',
      action: 'read',
      nowEpoch: 50,
    });
    expect(revokedRes).toEqual({
      kind: 'Refuted',
      reason: 'ancestor-revoked-cascade',
      revokedAncestorId: 'cert-contractor-a',
    });

    // Unrelated sibling branch `contractor-b` remains 100% authorized!
    const siblingRes = auth.authorizeDelegatedAction({
      chain: [rootCert, contractorB.cert],
      callerId: 'contractor-b',
      targetPath: '/repo/service-b/main.ts',
      action: 'read',
      nowEpoch: 50,
    });
    expect(siblingRes.kind).toBe('Authorized');
  });

  test('AG70: R3 blocks accidental reachability leak of DelegationRootKey into M1 Merkle store', () => {
    const kv = new ContentAddressedKvStore();
    const rootKey = new DelegationRootKey('org-secret-root');

    expect(() => kv.putBlob('agent-handoff', {nested: {signingKey: rootKey}}, [])).toThrow(
      /R3 ReachabilityLeakError/,
    );
    expect(() => JSON.stringify(rootKey)).toThrow(/R3 ReachabilityLeakError/);
  });
});

/**
 * @module tests/protected-intent
 * @description
 * Phase 2 round-trip, tamper, and replay coverage for the encrypted-intent envelope.
 */

import { describe, expect, it } from 'vitest';

import {
  InMemoryReplayCache,
  ProtectedIntentError,
  decryptIntent,
  encryptIntent,
  generateRecipientKeyPair,
  resolveRecipientKey,
  type ProtectedIntentEnvelope,
} from '../src/protected-intent';

function buildPair() {
  const pair = generateRecipientKeyPair('tenant-alpha');
  const resolved = resolveRecipientKey(pair);
  const resolveKey = (keyId: string) => (keyId === pair.keyId ? resolved : undefined);
  return { pair, resolveKey };
}

describe('ProtectedIntent envelope', () => {
  it('round-trips plaintext through encrypt + decrypt', () => {
    const { pair, resolveKey } = buildPair();
    const plaintext = JSON.stringify({ action: 'transfer', amountUsd: 250, to: '0xabc' });

    const envelope = encryptIntent({
      recipientPublicKey: pair.publicKey,
      recipientKeyId: pair.keyId,
      plaintext,
      agentId: 'agent-1',
    });

    const { plaintext: decrypted } = decryptIntent({ envelope, resolveKey });
    expect(decrypted.toString('utf8')).toBe(plaintext);
  });

  it('rejects when the envelope version is unsupported', () => {
    const { pair, resolveKey } = buildPair();
    const envelope = encryptIntent({
      recipientPublicKey: pair.publicKey,
      recipientKeyId: pair.keyId,
      plaintext: 'hello',
      agentId: 'agent-1',
    });
    const tampered = { ...envelope, v: 99 as unknown as typeof envelope.v };

    expect(() => decryptIntent({ envelope: tampered, resolveKey })).toThrowError(
      expect.objectContaining({ code: 'version-mismatch' }) as ProtectedIntentError,
    );
  });

  it('rejects ciphertext tampering', () => {
    const { pair, resolveKey } = buildPair();
    const envelope = encryptIntent({
      recipientPublicKey: pair.publicKey,
      recipientKeyId: pair.keyId,
      plaintext: 'hello-world',
      agentId: 'agent-1',
    });
    const tampered: ProtectedIntentEnvelope = {
      ...envelope,
      ciphertext: flipFirstChar(envelope.ciphertext),
    };

    expect(() => decryptIntent({ envelope: tampered, resolveKey })).toThrowError(
      expect.objectContaining({ code: 'aead-failure' }) as ProtectedIntentError,
    );
  });

  it('rejects when plaintext hash claim is wrong', () => {
    const { pair, resolveKey } = buildPair();
    const envelope = encryptIntent({
      recipientPublicKey: pair.publicKey,
      recipientKeyId: pair.keyId,
      plaintext: 'hello-world',
      agentId: 'agent-1',
    });
    const tampered: ProtectedIntentEnvelope = {
      ...envelope,
      plaintextHash: flipFirstChar(envelope.plaintextHash),
    };

    // AAD binds the hash into AEAD so the tag no longer verifies — either
    // aead-failure or hash-mismatch is acceptable evidence of rejection.
    expect(() => decryptIntent({ envelope: tampered, resolveKey })).toThrow();
  });

  it('rejects unknown keyId', () => {
    const { pair } = buildPair();
    const envelope = encryptIntent({
      recipientPublicKey: pair.publicKey,
      recipientKeyId: pair.keyId,
      plaintext: 'hello',
      agentId: 'agent-1',
    });

    expect(() => decryptIntent({ envelope, resolveKey: () => undefined })).toThrowError(
      expect.objectContaining({ code: 'unknown-key' }) as ProtectedIntentError,
    );
  });

  it('rejects a replayed nonce', () => {
    const { pair, resolveKey } = buildPair();
    const cache = new InMemoryReplayCache();
    const envelope = encryptIntent({
      recipientPublicKey: pair.publicKey,
      recipientKeyId: pair.keyId,
      plaintext: 'hello',
      agentId: 'agent-1',
    });

    decryptIntent({ envelope, resolveKey, replayCache: cache });
    expect(() => decryptIntent({ envelope, resolveKey, replayCache: cache })).toThrowError(
      expect.objectContaining({ code: 'replay-detected' }) as ProtectedIntentError,
    );
  });

  it('rejects envelopes older than the replay window', () => {
    const { pair, resolveKey } = buildPair();
    const t0 = 1_000_000_000_000;
    const envelope = encryptIntent({
      recipientPublicKey: pair.publicKey,
      recipientKeyId: pair.keyId,
      plaintext: 'hello',
      agentId: 'agent-1',
      now: () => t0,
    });

    expect(() =>
      decryptIntent({
        envelope,
        resolveKey,
        now: () => t0 + 10 * 60_000,
        replayWindowMs: 5 * 60_000,
      }),
    ).toThrowError(expect.objectContaining({ code: 'window-expired' }) as ProtectedIntentError);
  });

  it('rejects malformed ephemeral public key', () => {
    const { pair, resolveKey } = buildPair();
    const envelope = encryptIntent({
      recipientPublicKey: pair.publicKey,
      recipientKeyId: pair.keyId,
      plaintext: 'hello',
      agentId: 'agent-1',
    });
    const tampered = { ...envelope, ephemeralPublicKey: 'AA' };
    expect(() => decryptIntent({ envelope: tampered, resolveKey })).toThrowError(ProtectedIntentError);
  });

  it('supports key rotation: old keyId still decryptable while new is published', () => {
    const oldPair = generateRecipientKeyPair('v1');
    const newPair = generateRecipientKeyPair('v2');
    const keys = new Map([
      [oldPair.keyId, resolveRecipientKey(oldPair)],
      [newPair.keyId, resolveRecipientKey(newPair)],
    ]);
    const resolveKey = (id: string) => keys.get(id);

    const oldEnvelope = encryptIntent({
      recipientPublicKey: oldPair.publicKey,
      recipientKeyId: oldPair.keyId,
      plaintext: 'grandfathered',
      agentId: 'agent-1',
    });
    const newEnvelope = encryptIntent({
      recipientPublicKey: newPair.publicKey,
      recipientKeyId: newPair.keyId,
      plaintext: 'current',
      agentId: 'agent-1',
    });

    expect(decryptIntent({ envelope: oldEnvelope, resolveKey }).plaintext.toString('utf8')).toBe(
      'grandfathered',
    );
    expect(decryptIntent({ envelope: newEnvelope, resolveKey }).plaintext.toString('utf8')).toBe(
      'current',
    );
  });
});

function flipFirstChar(input: string): string {
  const first = input[0] ?? 'A';
  const replacement = first === 'A' ? 'B' : 'A';
  return replacement + input.slice(1);
}

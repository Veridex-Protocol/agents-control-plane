/**
 * @module tests/protected-intent-ingress
 * @description
 * Phase 2 — coverage for ProtectedIntentRegistry + ControlPlaneService.submitProtectedIntent
 * + the /v1/intents/protected HTTP routes.
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  ProtectedIntentRegistry,
  encryptIntent,
  generateRecipientKeyPair,
  type ProtectedIntentEnvelope,
} from '../src/protected-intent';
import { ControlPlaneService } from '../src/service';
import { createControlPlaneApp } from '../src/server';

function makeKeys(count = 2) {
  return Array.from({ length: count }, (_, i) => generateRecipientKeyPair(`k-${i + 1}`));
}

function envelopeFor(pair: ReturnType<typeof generateRecipientKeyPair>, body: string) {
  return encryptIntent({
    recipientPublicKey: pair.publicKey,
    recipientKeyId: pair.keyId,
    plaintext: body,
    agentId: 'agent-x',
  });
}

function modexiaPaymentIntent(overrides: Record<string, unknown> = {}) {
  return {
    version: '1',
    issuedAt: new Date(Date.now() - 1_000).toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    principal: {
      humanId: 'alice@modexia-pilot-customer.com',
      agentId: 'agent-x',
      auth: 'passkey:webauthn-v2',
      did: 'did:veridex:base:0xabc',
    },
    action: {
      type: 'payment.transfer',
      rail: 'modexia.cctp',
      to: { chain: 'akash', asset: 'AKT', wallet: 'akash1pilot' },
      amount: { value: '5.10', currency: 'USDC' },
    },
    policy: {
      policyPackId: 'modexia-pilot-cctp-base-akash-v1',
      caps: { maxPerRequest: '10.00', hourlyLimit: '25.00', dailyLimit: '100.00' },
      allowList: { destinations: ['akash1pilot'], rails: ['modexia.cctp', 'x402'] },
    },
    ...overrides,
  };
}

describe('ProtectedIntentRegistry', () => {
  it('publishes registered keys with the first as primary', () => {
    const keys = makeKeys(2);
    const registry = new ProtectedIntentRegistry({ keys });

    const published = registry.publishedKeys();
    expect(published).toHaveLength(2);
    expect(published[0].primary).toBe(true);
    expect(published[1].primary).toBe(false);
    expect(registry.primaryKey().keyId).toBe(keys[0].keyId);
  });

  it('decrypts an envelope encrypted to a non-primary key', () => {
    const keys = makeKeys(2);
    const registry = new ProtectedIntentRegistry({ keys });
    const envelope = envelopeFor(keys[1], 'rotation works');

    const { plaintext } = registry.decrypt(envelope);
    expect(plaintext.toString('utf8')).toBe('rotation works');
  });

  it('rejects replays via the shared replay cache', () => {
    const keys = makeKeys(1);
    const registry = new ProtectedIntentRegistry({ keys });
    const envelope = envelopeFor(keys[0], 'one-shot');

    expect(() => registry.decrypt(envelope)).not.toThrow();
    expect(() => registry.decrypt(envelope)).toThrow(/replay/i);
  });

  it('throws when constructed with no keys', () => {
    expect(() => new ProtectedIntentRegistry({ keys: [] })).toThrow();
  });
});

describe('ControlPlaneService.submitProtectedIntent', () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'cp-protected-'));
  });

  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('returns plaintext + envelope metadata when feature is configured', async () => {
    const keys = makeKeys(1);
    const service = new ControlPlaneService({
      dataDir,
      authRequired: false,
      protectedIntent: { keys },
    });
    await service.health();
    const envelope = envelopeFor(keys[0], JSON.stringify({ tool: 'pay', amount: 100 }));

    const result = await service.submitProtectedIntent(envelope);

    expect(result.plaintext).toBe(JSON.stringify({ tool: 'pay', amount: 100 }));
    expect(result.envelope.keyId).toBe(keys[0].keyId);
    expect(result.envelope.agentId).toBe('agent-x');
    expect(result.envelope.plaintextHash).toBe(envelope.plaintextHash);
    expect(result.acceptedAt).toBeGreaterThan(0);
  });

  it('throws when the feature is not configured', async () => {
    const service = new ControlPlaneService({ dataDir, authRequired: false });
    await service.health();
    expect(service.listProtectedIntentKeys()).toEqual([]);

    const stubEnvelope = {
      v: 1 as const,
      keyId: 'unknown',
      ephemeralPublicKey: '',
      nonce: '',
      ciphertext: '',
      plaintextHash: '',
      agentId: 'a',
      submittedAt: Date.now(),
    } as ProtectedIntentEnvelope;

    await expect(service.submitProtectedIntent(stubEnvelope)).rejects.toThrow(/not configured/i);
  });

  it('lists published keys when configured', async () => {
    const keys = makeKeys(2);
    const service = new ControlPlaneService({
      dataDir,
      authRequired: false,
      protectedIntent: { keys },
    });
    await service.health();
    const published = service.listProtectedIntentKeys();
    expect(published.map((k) => k.keyId)).toEqual([keys[0].keyId, keys[1].keyId]);
    expect(published[0].primary).toBe(true);
  });

  it('preflights an approved Modexia-shaped payment intent with evidence', async () => {
    const keys = makeKeys(1);
    const service = new ControlPlaneService({
      dataDir,
      authRequired: false,
      protectedIntent: { keys },
    });
    await service.health();
    const envelope = envelopeFor(keys[0], JSON.stringify(modexiaPaymentIntent()));

    const result = await service.preflightProtectedIntent(envelope);

    expect(result.decision.verdict).toBe('approved');
    expect(result.decision.policyPackId).toBe('modexia-pilot-cctp-base-akash-v1');
    expect(result.decision.intentSummary?.rail).toBe('modexia.cctp');
    expect(result.evidenceBundle.policyDecisions).toHaveLength(1);
    expect(result.evidenceBundle.policyHash).toBeTruthy();
  });

  it('preflight rejects mismatched agent identity without calling Modexia rails', async () => {
    const keys = makeKeys(1);
    const service = new ControlPlaneService({
      dataDir,
      authRequired: false,
      protectedIntent: { keys },
    });
    await service.health();
    const intent = modexiaPaymentIntent({
      principal: {
        humanId: 'alice@modexia-pilot-customer.com',
        agentId: 'different-agent',
      },
    });
    const envelope = envelopeFor(keys[0], JSON.stringify(intent));

    const result = await service.preflightProtectedIntent(envelope);

    expect(result.decision.verdict).toBe('rejected');
    expect(result.decision.checks.find((check) => check.id === 'agent-binding')?.passed).toBe(false);
  });
});

describe('Protected-intent HTTP routes', () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), 'cp-protected-http-'));
  });

  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('GET /v1/intents/protected/keys returns published keys', async () => {
    const keys = makeKeys(1);
    const service = new ControlPlaneService({
      dataDir,
      authRequired: false,
      protectedIntent: { keys },
    });
    await service.health();
    const app = createControlPlaneApp(service);

    const res = await app.request('/v1/intents/protected/keys');
    expect(res.status).toBe(200);
    const body = (await res.json()) as { keys: Array<{ keyId: string; primary: boolean }> };
    expect(body.keys).toHaveLength(1);
    expect(body.keys[0].keyId).toBe(keys[0].keyId);
    expect(body.keys[0].primary).toBe(true);
  });

  it('POST /v1/intents/protected accepts a valid envelope and returns 202', async () => {
    const keys = makeKeys(1);
    const service = new ControlPlaneService({
      dataDir,
      authRequired: false,
      protectedIntent: { keys },
    });
    await service.health();
    const app = createControlPlaneApp(service);
    const envelope = envelopeFor(keys[0], 'execute swap');

    const res = await app.request('/v1/intents/protected', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    expect(res.status).toBe(202);
    const body = (await res.json()) as { plaintext: string; envelope: { agentId: string } };
    expect(body.plaintext).toBe('execute swap');
    expect(body.envelope.agentId).toBe('agent-x');
  });

  it('POST /v1/intents/protected/preflight returns a policy decision', async () => {
    const keys = makeKeys(1);
    const service = new ControlPlaneService({
      dataDir,
      authRequired: false,
      protectedIntent: { keys },
    });
    await service.health();
    const app = createControlPlaneApp(service);
    const envelope = envelopeFor(keys[0], JSON.stringify(modexiaPaymentIntent()));

    const res = await app.request('/v1/intents/protected/preflight', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { decision: { verdict: string }; evidenceBundle: { contentHash: string } };
    expect(body.decision.verdict).toBe('approved');
    expect(body.evidenceBundle.contentHash).toBeTruthy();
  });

  it('POST /v1/intents/protected/preflight returns rejected for policy misses', async () => {
    const keys = makeKeys(1);
    const service = new ControlPlaneService({
      dataDir,
      authRequired: false,
      protectedIntent: { keys },
    });
    await service.health();
    const app = createControlPlaneApp(service);
    const intent = modexiaPaymentIntent({
      action: {
        type: 'payment.transfer',
        rail: 'modexia.cctp',
        to: { chain: 'akash', asset: 'AKT', wallet: 'akash1attacker' },
        amount: { value: '5.10', currency: 'USDC' },
      },
    });
    const envelope = envelopeFor(keys[0], JSON.stringify(intent));

    const res = await app.request('/v1/intents/protected/preflight', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(envelope),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { decision: { verdict: string; reasons: string[] } };
    expect(body.decision.verdict).toBe('rejected');
    expect(body.decision.reasons).toContain('Destination is not in the intent allow-list');
  });

  it('returns 501 when the feature is not configured', async () => {
    const service = new ControlPlaneService({ dataDir, authRequired: false });
    await service.health();
    const app = createControlPlaneApp(service);

    const res = await app.request('/v1/intents/protected', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(501);
  });

  it('rejects a tampered envelope with 400', async () => {
    const keys = makeKeys(1);
    const service = new ControlPlaneService({
      dataDir,
      authRequired: false,
      protectedIntent: { keys },
    });
    await service.health();
    const app = createControlPlaneApp(service);
    const envelope = envelopeFor(keys[0], 'execute swap');

    // Corrupt the ciphertext.
    const tampered = { ...envelope, ciphertext: envelope.ciphertext.slice(0, -2) + 'aa' };

    const res = await app.request('/v1/intents/protected', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(tampered),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code: string };
    expect(['aead-failure', 'malformed-envelope', 'hash-mismatch']).toContain(body.code);
  });

  it('rejects a replayed envelope with 409', async () => {
    const keys = makeKeys(1);
    const service = new ControlPlaneService({
      dataDir,
      authRequired: false,
      protectedIntent: { keys },
    });
    await service.health();
    const app = createControlPlaneApp(service);
    const envelope = envelopeFor(keys[0], 'execute swap');
    const payload = JSON.stringify(envelope);

    const first = await app.request('/v1/intents/protected', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: payload,
    });
    expect(first.status).toBe(202);

    const second = await app.request('/v1/intents/protected', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: payload,
    });
    expect(second.status).toBe(409);
    const body = (await second.json()) as { code: string };
    expect(body.code).toBe('replay-detected');
  });

  it('rejects malformed JSON with 400', async () => {
    const keys = makeKeys(1);
    const service = new ControlPlaneService({
      dataDir,
      authRequired: false,
      protectedIntent: { keys },
    });
    await service.health();
    const app = createControlPlaneApp(service);

    const res = await app.request('/v1/intents/protected', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{not json',
    });
    expect(res.status).toBe(400);
  });
});

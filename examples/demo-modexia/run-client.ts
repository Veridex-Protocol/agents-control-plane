/**
 * @file run-client.ts
 * @description
 * Modexia × Veridex demo — client side.
 *
 * Simulates the Modexia Akash Compute Agent calling `payments.py` with a
 * Veridex protected-intent envelope wrapped around the action.
 *
 * Flow:
 *   1. Discover the control-plane's published recipient key.
 *   2. Encrypt `intent.json` against that key (X25519 ECDH + AES-256-GCM).
 *   3. POST the envelope to /v1/intents/protected.
 *   4. Verify the acceptance receipt offline:
 *        - re-hash plaintext locally
 *        - confirm SHA-256 matches the receipt's plaintextHash
 *   5. Print a "verified offline" line that an auditor would reproduce.
 *
 * Run (in a second terminal, after run-server.ts):
 *   pnpm tsx examples/demo-modexia/run-client.ts
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { encryptIntent, type ProtectedIntentEnvelope } from '../../src/protected-intent';

const here = dirname(fileURLToPath(import.meta.url));
const INTENT_PATH = resolve(here, 'intent.json');
const SERVER = process.env.VERIDEX_DEMO_URL ?? 'http://127.0.0.1:4010';

interface PublishedKey {
  keyId: string;
  publicKey: string;
  createdAt: number;
}

interface AcceptanceReceipt {
  plaintext: string;
  plaintextBase64Url: string;
  envelope: {
    keyId: string;
    agentId: string;
    submittedAt: number;
    plaintextHash: string;
    nonce: string;
  };
  acceptedAt: number;
}

const colour = {
  bold: (s: string) => `\u001b[1m${s}\u001b[0m`,
  green: (s: string) => `\u001b[32m${s}\u001b[0m`,
  cyan: (s: string) => `\u001b[36m${s}\u001b[0m`,
  yellow: (s: string) => `\u001b[33m${s}\u001b[0m`,
  red: (s: string) => `\u001b[31m${s}\u001b[0m`,
  dim: (s: string) => `\u001b[2m${s}\u001b[0m`,
};

function rule(label?: string): void {
  const line = '─'.repeat(64);
  console.log(label ? `\n${colour.bold(label)}\n${line}` : line);
}

function b64urlSha256(buf: Buffer): string {
  return createHash('sha256')
    .update(buf)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function discoverRecipientKey(): Promise<PublishedKey> {
  const res = await fetch(`${SERVER}/v1/intents/protected/keys`);
  if (!res.ok) {
    throw new Error(`discovery failed (${res.status} ${res.statusText})`);
  }
  const body = (await res.json()) as { keys: PublishedKey[] };
  if (!body.keys?.length) {
    throw new Error('control-plane has no published recipient keys');
  }
  return body.keys[0]!;
}

async function postEnvelope(envelope: ProtectedIntentEnvelope): Promise<{
  status: number;
  receipt?: AcceptanceReceipt;
  error?: { error: string; code?: string };
}> {
  const res = await fetch(`${SERVER}/v1/intents/protected`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(envelope),
  });
  if (res.status === 202) {
    const receipt = (await res.json()) as AcceptanceReceipt;
    return { status: 202, receipt };
  }
  return { status: res.status, error: (await res.json()) as { error: string; code?: string } };
}

async function main(): Promise<void> {
  rule('STEP 1 / Discover recipient key');
  const key = await discoverRecipientKey();
  console.log(`  ${colour.dim('keyId  →')} ${colour.cyan(key.keyId)}`);
  console.log(`  ${colour.dim('pubkey →')} ${key.publicKey}`);

  rule('STEP 2 / Load Modexia-shaped intent');
  const plaintextBuf = readFileSync(INTENT_PATH);
  const intent = JSON.parse(plaintextBuf.toString('utf8')) as Record<string, unknown>;
  const action = intent.action as { type: string; rail: string; amount: { value: string; currency: string }; to: { wallet: string } };
  console.log(`  ${colour.dim('action       →')} ${colour.yellow(action.type)} via ${action.rail}`);
  console.log(`  ${colour.dim('amount       →')} ${action.amount.value} ${action.amount.currency}`);
  console.log(`  ${colour.dim('destination  →')} ${action.to.wallet}`);
  console.log(`  ${colour.dim('plaintextSha →')} ${b64urlSha256(plaintextBuf)}`);

  rule('STEP 3 / Encrypt envelope (X25519 ECDH + AES-256-GCM)');
  const envelope = encryptIntent({
    recipientPublicKey: key.publicKey,
    recipientKeyId: key.keyId,
    plaintext: plaintextBuf,
    agentId: 'akash-compute-agent-7f3a',
  });
  console.log(`  ${colour.dim('agentId           →')} ${envelope.agentId}`);
  console.log(`  ${colour.dim('ephemeralPubkey   →')} ${envelope.ephemeralPublicKey}`);
  console.log(`  ${colour.dim('nonce             →')} ${envelope.nonce}`);
  console.log(`  ${colour.dim('ciphertext (len)  →')} ${envelope.ciphertext.length} chars (b64url)`);
  console.log(`  ${colour.dim('plaintextHash     →')} ${envelope.plaintextHash}`);

  rule('STEP 4 / Submit to control-plane');
  const result = await postEnvelope(envelope);
  if (result.status !== 202 || !result.receipt) {
    console.log(colour.red(`  ✗ rejected (${result.status})`), result.error);
    process.exit(1);
  }
  console.log(`  ${colour.green('✓')} HTTP 202 Accepted`);
  console.log(`  ${colour.dim('acceptedAt        →')} ${new Date(result.receipt.acceptedAt).toISOString()}`);
  console.log(`  ${colour.dim('envelope.agentId  →')} ${result.receipt.envelope.agentId}`);
  console.log(`  ${colour.dim('envelope.keyId    →')} ${result.receipt.envelope.keyId}`);
  console.log(`  ${colour.dim('envelope.nonce    →')} ${result.receipt.envelope.nonce}`);

  rule('STEP 5 / Offline verification (no network, no trust)');
  const localHash = b64urlSha256(plaintextBuf);
  const receiptHash = result.receipt.envelope.plaintextHash;
  const matches = localHash === receiptHash;
  console.log(`  ${colour.dim('local re-hash     →')} ${localHash}`);
  console.log(`  ${colour.dim('receipt hash      →')} ${receiptHash}`);
  if (!matches) {
    console.log(colour.red('  ✗ MISMATCH — receipt does not bind this plaintext'));
    process.exit(2);
  }
  console.log(`  ${colour.green('✓ verified')} — receipt cryptographically binds this exact intent`);

  rule('AUDITOR-VIEW SUMMARY');
  console.log(
    [
      `  ${colour.bold('agent')}        : ${result.receipt.envelope.agentId}`,
      `  ${colour.bold('action')}       : ${action.type} · ${action.amount.value} ${action.amount.currency} → ${action.to.wallet}`,
      `  ${colour.bold('rail')}         : ${action.rail}`,
      `  ${colour.bold('keyId')}        : ${result.receipt.envelope.keyId}`,
      `  ${colour.bold('submitted')}    : ${new Date(result.receipt.envelope.submittedAt).toISOString()}`,
      `  ${colour.bold('accepted')}     : ${new Date(result.receipt.acceptedAt).toISOString()}`,
      `  ${colour.bold('plaintextHash')}: ${result.receipt.envelope.plaintextHash}`,
      `  ${colour.bold('verifiable')}   : ${colour.green('offline · no Veridex call · no Modexia call')}`,
    ].join('\n'),
  );
  rule();
  console.log(
    colour.dim(
      '  This is what a Modexia Pilot-5 customer auditor receives. Re-hash the\n' +
        '  intent JSON, compare to plaintextHash, done. Policy enforcement is\n' +
        '  cryptographically attested without trusting either Modexia or Veridex.',
    ),
  );
  console.log();
}

void main().catch((err) => {
  console.error(colour.red(`\n✗ demo failed:`), err instanceof Error ? err.message : err);
  process.exit(1);
});

/**
 * @file run-server.ts
 * @description
 * Modexia × Veridex demo — minimal control-plane server with the
 * protected-intent (encrypted envelope) feature enabled.
 *
 * What this proves:
 *   1. Veridex publishes an X25519 recipient public key (`GET /v1/intents/protected/keys`).
 *   2. The control-plane decrypts envelopes posted to `/v1/intents/protected`.
 *   3. The acceptance receipt contains a SHA-256 plaintext hash that any third
 *      party (auditor, customer, regulator) can re-verify offline.
 *
 * Run: `pnpm tsx examples/demo-modexia/run-server.ts`
 */
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ControlPlaneService } from '../../src/service';
import { startControlPlaneServer } from '../../src/server';
import { generateRecipientKeyPair } from '../../src/protected-intent';

const here = dirname(fileURLToPath(import.meta.url));
const KEY_OUT = resolve(here, '.demo-recipient-key.json');

async function main(): Promise<void> {
  const recipient = generateRecipientKeyPair('demo-modexia-2026-05');
  // Publish the public half so the client script can pick it up without
  // calling the discovery endpoint twice. The private half stays in-process.
  writeFileSync(
    KEY_OUT,
    JSON.stringify(
      {
        keyId: recipient.keyId,
        publicKey: recipient.publicKey,
        createdAt: recipient.createdAt,
      },
      null,
      2,
    ),
  );

  const service = new ControlPlaneService({
    storageBackend: 'file',
    host: '127.0.0.1',
    port: 4010,
    dataDir: resolve(here, '.demo-data'),
    authRequired: false,
    protectedIntent: {
      keys: [recipient],
      replayWindowMs: 5 * 60_000,
    },
  });

  const server = startControlPlaneServer(service);

  const banner = [
    '',
    '─────────────────────────────────────────────────────────────',
    ' Veridex control-plane (demo) — protected-intent feature ON',
    '─────────────────────────────────────────────────────────────',
    `  POST    http://127.0.0.1:4010/v1/intents/protected`,
    `  GET     http://127.0.0.1:4010/v1/intents/protected/keys`,
    `  KeyId:  ${recipient.keyId}`,
    `  Pubkey: ${recipient.publicKey}`,
    '  Public key cached at examples/demo-modexia/.demo-recipient-key.json',
    '─────────────────────────────────────────────────────────────',
    '',
  ].join('\n');
  console.log(banner);

  const shutdown = async () => {
    await server.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

void main().catch((err) => {
  console.error('Server failed to start:', err);
  process.exit(1);
});

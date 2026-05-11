# Modexia × Veridex demo

Live demo for the Daniel @ Modexia call. Two terminals, ~90 seconds, ends
with a verifiable acceptance receipt the customer's auditor can re-check
offline.

## What it shows

1. Veridex publishes an X25519 recipient key (`GET /v1/intents/protected/keys`).
2. The Modexia Akash Compute Agent encrypts a Modexia-shaped intent —
   "pay 5.10 USDC via CCTP for an Akash deploy" — against that key.
3. The control-plane decrypts the envelope, returns an acceptance receipt
   carrying a SHA-256 plaintext hash bound to the agent identity.
4. The client re-hashes the plaintext locally and confirms the receipt
   binds the exact intent — no Modexia call, no Veridex call.

## Run it

Prereq: you've already run `pnpm install` at the repo root.

```bash
# Terminal 1 — control-plane with protected-intent enabled
cd packages/agents-control-plane
pnpm tsx examples/demo-modexia/run-server.ts

# Terminal 2 — Modexia agent simulator
cd packages/agents-control-plane
pnpm tsx examples/demo-modexia/run-client.ts
```

## What Daniel sees

```
STEP 1 / Discover recipient key                ← published x25519 key
STEP 2 / Load Modexia-shaped intent            ← USDC → AKT via CCTP
STEP 3 / Encrypt envelope                      ← ECDH + AES-256-GCM
STEP 4 / Submit to control-plane               ← HTTP 202 Accepted
STEP 5 / Offline verification                  ← ✓ verified, no network
AUDITOR-VIEW SUMMARY                           ← compliance artefact
```

## Files

- `intent.json` — Modexia-shaped Akash compute payment intent
  (USDC → AKT, $5.10, CCTP rail, allow-list of one destination).
- `run-server.ts` — minimal control-plane with protected-intent enabled.
- `run-client.ts` — Modexia agent simulator: encrypt, submit, verify.

## Talk-track (90 seconds)

1. **(0:00)** "Here's the Modexia Akash Compute Agent calling
   `payments.py` today — one developer key, no per-user scope, no
   offline-verifiable proof."
2. **(0:15)** Run `run-server.ts`. "Veridex publishes its recipient key."
3. **(0:25)** Run `run-client.ts`. "The agent encrypts an intent envelope
   bound to a passkey-rooted DID, posts it, gets a receipt."
4. **(0:55)** Point at STEP 5. "Auditor re-hashes the plaintext, compares
   to `plaintextHash` in the receipt — done. Policy enforcement is
   cryptographically attested without trusting either of us."
5. **(1:20)** "This envelope is the only thing that needs to flow through
   your gateway. Everything else stays Modexia. KYA ships in 4 weeks."

## Cleanup

```bash
rm -rf packages/agents-control-plane/examples/demo-modexia/.demo-data
rm -f  packages/agents-control-plane/examples/demo-modexia/.demo-recipient-key.json
```

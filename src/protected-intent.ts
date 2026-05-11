/**
 * @module ProtectedIntent
 * @description
 * Phase 2 — Encrypted-intent envelope format.
 *
 * Closes the "intent must never be plaintext on the wire" gap. Agents
 * encrypt their intent payload against the control-plane's published
 * X25519 public key. The control-plane decrypts on ingress and forwards
 * the plaintext into the existing PolicyEngine + ApprovalWorkflowEngine
 * pipeline.
 *
 * Envelope (v1):
 *   - v: version tag
 *   - keyId: which recipient keypair version the ciphertext is bound to
 *   - ephemeralPublicKey: sender's ephemeral X25519 pubkey (base64url, 32 bytes)
 *   - nonce: AES-GCM IV (base64url, 12 bytes) — also used for replay protection
 *   - ciphertext: AES-256-GCM ciphertext with authentication tag (base64url)
 *   - plaintextHash: SHA-256 of plaintext (base64url) — binds plaintext to the
 *     envelope independently of AEAD so agents can sign over the hash without
 *     revealing plaintext, and the hash can live in audit records.
 *   - agentId: who submitted the intent
 *   - submittedAt: epoch ms, used for replay TTL windowing
 *
 * AEAD key derivation:
 *   1. ECDH(ephemeralPriv, recipientPub) -> sharedSecret (32 bytes)
 *   2. HKDF-SHA256(sharedSecret, salt=nonce, info="veridex-protected-intent/v1") -> 32-byte AEAD key
 *   3. AES-256-GCM(key, nonce, plaintext, aad=canonical(envelope header)) -> ciphertext||tag
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';

export const PROTECTED_INTENT_VERSION = 1 as const;
const HKDF_INFO = Buffer.from('veridex-protected-intent/v1');
const AEAD_KEY_BYTES = 32;
const NONCE_BYTES = 12;
const X25519_PUBLIC_KEY_BYTES = 32;
const X25519_PRIVATE_KEY_BYTES = 32;
const DEFAULT_REPLAY_WINDOW_MS = 5 * 60_000;

/** Serialized envelope produced by the SDK and consumed by the control plane. */
export interface ProtectedIntentEnvelope {
  v: typeof PROTECTED_INTENT_VERSION;
  keyId: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
  plaintextHash: string;
  agentId: string;
  submittedAt: number;
}

/** X25519 keypair in raw 32-byte form, wrapped for convenience. */
export interface ProtectedIntentKeyPair {
  keyId: string;
  publicKey: string;
  privateKey: string;
  createdAt: number;
}

/** Opaque handle the control-plane holds for decryption + rotation. */
export interface ResolvedRecipientKey {
  keyId: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export class ProtectedIntentError extends Error {
  constructor(
    message: string,
    public readonly code:
      | 'version-mismatch'
      | 'unknown-key'
      | 'hash-mismatch'
      | 'aead-failure'
      | 'replay-detected'
      | 'window-expired'
      | 'malformed-envelope',
  ) {
    super(message);
    this.name = 'ProtectedIntentError';
  }
}

/** Generate a fresh recipient keypair. Call once per rotation. */
export function generateRecipientKeyPair(keyId?: string): ProtectedIntentKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  return {
    keyId: keyId ?? `k-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`,
    publicKey: b64url(publicKeyRaw(publicKey)),
    privateKey: b64url(privateKeyRaw(privateKey)),
    createdAt: Date.now(),
  };
}

/** Encode an encoded keypair into KeyObject form for the decrypt path. */
export function resolveRecipientKey(pair: ProtectedIntentKeyPair): ResolvedRecipientKey {
  const rawPriv = fromB64url(pair.privateKey);
  if (rawPriv.length !== X25519_PRIVATE_KEY_BYTES) {
    throw new ProtectedIntentError('private key length invalid', 'unknown-key');
  }
  const rawPub = fromB64url(pair.publicKey);
  if (rawPub.length !== X25519_PUBLIC_KEY_BYTES) {
    throw new ProtectedIntentError('public key length invalid', 'unknown-key');
  }
  return {
    keyId: pair.keyId,
    privateKey: privateKeyFromRaw(rawPriv),
    publicKey: publicKeyFromRaw(rawPub),
  };
}

export interface EncryptOptions {
  /** Recipient public key as published by the control-plane. */
  recipientPublicKey: string;
  /** Which recipient key version we're binding to. */
  recipientKeyId: string;
  /** Plaintext intent — arbitrary bytes. */
  plaintext: Uint8Array | string;
  /** Who is submitting. */
  agentId: string;
  /** Override clock for tests. */
  now?: () => number;
}

/** Produce an encrypted envelope the SDK can POST to /v1/intents/protected. */
export function encryptIntent(options: EncryptOptions): ProtectedIntentEnvelope {
  const rawRecipientPub = fromB64url(options.recipientPublicKey);
  if (rawRecipientPub.length !== X25519_PUBLIC_KEY_BYTES) {
    throw new ProtectedIntentError('recipient public key invalid', 'unknown-key');
  }
  const recipientPub = publicKeyFromRaw(rawRecipientPub);
  const ephemeral = generateKeyPairSync('x25519');
  const sharedSecret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipientPub });
  const nonce = randomBytes(NONCE_BYTES);
  const key = deriveKey(sharedSecret, nonce);

  const plaintextBuf =
    typeof options.plaintext === 'string' ? Buffer.from(options.plaintext, 'utf8') : Buffer.from(options.plaintext);
  const plaintextHash = sha256(plaintextBuf);

  const ephemeralPubRaw = publicKeyRaw(ephemeral.publicKey);
  const submittedAt = (options.now ?? Date.now)();

  const aad = buildAad({
    v: PROTECTED_INTENT_VERSION,
    keyId: options.recipientKeyId,
    ephemeralPublicKey: b64url(ephemeralPubRaw),
    nonce: b64url(nonce),
    plaintextHash: b64url(plaintextHash),
    agentId: options.agentId,
    submittedAt,
  });

  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    v: PROTECTED_INTENT_VERSION,
    keyId: options.recipientKeyId,
    ephemeralPublicKey: b64url(ephemeralPubRaw),
    nonce: b64url(nonce),
    ciphertext: b64url(Buffer.concat([encrypted, tag])),
    plaintextHash: b64url(plaintextHash),
    agentId: options.agentId,
    submittedAt,
  };
}

export interface DecryptOptions {
  envelope: ProtectedIntentEnvelope;
  /**
   * Return the recipient private key for the envelope's keyId, or undefined
   * if it is unknown / has been revoked.
   */
  resolveKey: (keyId: string) => ResolvedRecipientKey | undefined;
  /**
   * Replay cache: returns true if the nonce was seen recently.
   * The caller is responsible for recording the nonce after a successful decrypt.
   */
  replayCache?: {
    has: (nonce: string) => boolean;
    record: (nonce: string, ttlMs: number) => void;
  };
  /** Replay window — envelopes older than this are rejected. */
  replayWindowMs?: number;
  now?: () => number;
}

export interface DecryptedIntent {
  plaintext: Buffer;
  envelope: ProtectedIntentEnvelope;
}

export function decryptIntent(options: DecryptOptions): DecryptedIntent {
  const { envelope } = options;
  if (envelope.v !== PROTECTED_INTENT_VERSION) {
    throw new ProtectedIntentError(`unsupported envelope version ${envelope.v}`, 'version-mismatch');
  }

  const now = (options.now ?? Date.now)();
  const windowMs = options.replayWindowMs ?? DEFAULT_REPLAY_WINDOW_MS;
  if (!Number.isFinite(envelope.submittedAt) || envelope.submittedAt > now + 30_000) {
    throw new ProtectedIntentError('submittedAt is in the future', 'malformed-envelope');
  }
  if (now - envelope.submittedAt > windowMs) {
    throw new ProtectedIntentError('envelope outside replay window', 'window-expired');
  }

  if (options.replayCache?.has(envelope.nonce)) {
    throw new ProtectedIntentError('nonce replay detected', 'replay-detected');
  }

  const recipient = options.resolveKey(envelope.keyId);
  if (!recipient) {
    throw new ProtectedIntentError(`unknown keyId ${envelope.keyId}`, 'unknown-key');
  }

  const ephemeralPubRaw = fromB64url(envelope.ephemeralPublicKey);
  if (ephemeralPubRaw.length !== X25519_PUBLIC_KEY_BYTES) {
    throw new ProtectedIntentError('ephemeral public key malformed', 'malformed-envelope');
  }
  const nonce = fromB64url(envelope.nonce);
  if (nonce.length !== NONCE_BYTES) {
    throw new ProtectedIntentError('nonce malformed', 'malformed-envelope');
  }
  const ciphertextAndTag = fromB64url(envelope.ciphertext);
  if (ciphertextAndTag.length < 16) {
    throw new ProtectedIntentError('ciphertext too short', 'malformed-envelope');
  }

  const ephemeralPub = publicKeyFromRaw(ephemeralPubRaw);
  const sharedSecret = diffieHellman({ privateKey: recipient.privateKey, publicKey: ephemeralPub });
  const key = deriveKey(sharedSecret, nonce);

  const tag = ciphertextAndTag.subarray(ciphertextAndTag.length - 16);
  const body = ciphertextAndTag.subarray(0, ciphertextAndTag.length - 16);

  const aad = buildAad({
    v: envelope.v,
    keyId: envelope.keyId,
    ephemeralPublicKey: envelope.ephemeralPublicKey,
    nonce: envelope.nonce,
    plaintextHash: envelope.plaintextHash,
    agentId: envelope.agentId,
    submittedAt: envelope.submittedAt,
  });

  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
  } catch {
    throw new ProtectedIntentError('AEAD authentication failed', 'aead-failure');
  }

  const actualHash = sha256(plaintext);
  const expectedHash = fromB64url(envelope.plaintextHash);
  if (!timingSafeEqual(actualHash, expectedHash)) {
    throw new ProtectedIntentError('plaintext hash does not match envelope', 'hash-mismatch');
  }

  options.replayCache?.record(envelope.nonce, windowMs);

  return { plaintext, envelope };
}

// ── Internal helpers ──

function deriveKey(sharedSecret: Buffer, nonce: Buffer): Buffer {
  const key = hkdfSync('sha256', sharedSecret, nonce, HKDF_INFO, AEAD_KEY_BYTES);
  return Buffer.from(key);
}

function buildAad(header: {
  v: number;
  keyId: string;
  ephemeralPublicKey: string;
  nonce: string;
  plaintextHash: string;
  agentId: string;
  submittedAt: number;
}): Buffer {
  // Canonical serialization — keys alphabetised, no whitespace.
  const canonical = JSON.stringify(header, Object.keys(header).sort());
  return Buffer.from(canonical, 'utf8');
}

function sha256(data: Uint8Array | Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

function publicKeyRaw(key: KeyObject): Buffer {
  // DER export includes SPKI header; extract trailing 32 bytes for X25519.
  const der = key.export({ format: 'der', type: 'spki' });
  return Buffer.from(der.subarray(der.length - X25519_PUBLIC_KEY_BYTES));
}

function privateKeyRaw(key: KeyObject): Buffer {
  // PKCS#8 export; X25519 private key is the trailing 32 bytes inside an OCTET STRING.
  const der = key.export({ format: 'der', type: 'pkcs8' });
  return Buffer.from(der.subarray(der.length - X25519_PRIVATE_KEY_BYTES));
}

function publicKeyFromRaw(raw: Buffer): KeyObject {
  // X25519 SPKI prefix: 302a300506032b656e032100
  const spki = Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), raw]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

function privateKeyFromRaw(raw: Buffer): KeyObject {
  // X25519 PKCS#8 prefix: 302e020100300506032b656e04220420
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), raw]);
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

function b64url(buf: Uint8Array): string {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(input: string): Buffer {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

function timingSafeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i]! ^ b[i]!;
  }
  return result === 0;
}

// ── Replay cache ──

/**
 * Simple in-memory replay cache with bounded TTL. Production deployments
 * should swap this for a shared store (Redis, Postgres) so horizontally
 * scaled control-plane instances share a replay view.
 */
export class InMemoryReplayCache {
  private readonly entries = new Map<string, number>();

  constructor(private readonly maxEntries = 10_000) {}

  has(nonce: string): boolean {
    const expiry = this.entries.get(nonce);
    if (!expiry) return false;
    if (expiry < Date.now()) {
      this.entries.delete(nonce);
      return false;
    }
    return true;
  }

  record(nonce: string, ttlMs: number): void {
    this.entries.set(nonce, Date.now() + ttlMs);
    if (this.entries.size > this.maxEntries) {
      // Drop oldest entries to keep cache bounded.
      const cutoff = this.entries.size - this.maxEntries;
      let removed = 0;
      for (const key of this.entries.keys()) {
        if (removed >= cutoff) break;
        this.entries.delete(key);
        removed++;
      }
    }
  }

  size(): number {
    return this.entries.size;
  }
}

// ── Registry ──

/**
 * Holds the active recipient keypairs and replay cache for the control-plane.
 *
 * In production the keypairs come from a KMS / HSM via {@link ProtectedIntentRegistryConfig.keys}.
 * For dev/tests, callers can pass freshly generated keys via {@link generateRecipientKeyPair}.
 */
export interface ProtectedIntentRegistryConfig {
  /** Active keypairs. The first entry is treated as the "primary" published key. */
  keys: ProtectedIntentKeyPair[];
  /** Replay window for envelopes — defaults to 5 minutes. */
  replayWindowMs?: number;
  /** Override clock for deterministic tests. */
  now?: () => number;
}

/** Public-key information returned by the discovery endpoint. */
export interface PublishedRecipientKey {
  keyId: string;
  publicKey: string;
  primary: boolean;
  createdAt: number;
}

export class ProtectedIntentRegistry {
  private readonly resolved = new Map<string, ResolvedRecipientKey>();
  private readonly published: PublishedRecipientKey[];
  private readonly replayCache = new InMemoryReplayCache();
  private readonly replayWindowMs: number;
  private readonly clock: () => number;

  constructor(config: ProtectedIntentRegistryConfig) {
    if (!config.keys.length) {
      throw new ProtectedIntentError('at least one recipient keypair is required', 'unknown-key');
    }
    this.replayWindowMs = config.replayWindowMs ?? DEFAULT_REPLAY_WINDOW_MS;
    this.clock = config.now ?? (() => Date.now());
    this.published = config.keys.map((pair, index) => {
      this.resolved.set(pair.keyId, resolveRecipientKey(pair));
      return {
        keyId: pair.keyId,
        publicKey: pair.publicKey,
        primary: index === 0,
        createdAt: pair.createdAt,
      };
    });
  }

  /** Public-key listing for the discovery endpoint and SDKs. */
  publishedKeys(): PublishedRecipientKey[] {
    return this.published.map((k) => ({ ...k }));
  }

  /** Primary key — what newly-encrypting agents should target by default. */
  primaryKey(): PublishedRecipientKey {
    return { ...this.published[0]! };
  }

  /** Decrypt an envelope using the registered keypairs and shared replay cache. */
  decrypt(envelope: ProtectedIntentEnvelope): DecryptedIntent {
    return decryptIntent({
      envelope,
      resolveKey: (keyId) => this.resolved.get(keyId),
      replayCache: this.replayCache,
      replayWindowMs: this.replayWindowMs,
      now: this.clock,
    });
  }

  /** For tests — number of nonces currently held in the replay cache. */
  replayCacheSize(): number {
    return this.replayCache.size();
  }
}

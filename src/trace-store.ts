/**
 * @module TraceStore
 * @description
 * Trace ingestion and retention store for the control plane.
 *
 * Accepts trace events from agent runtimes, stores trace records,
 * and supports query, TTL-based expiry, and content hashing.
 */

import type { TraceRecord, TraceQuery } from './types';

/** Interface for pluggable trace storage backends. */
export interface TraceStoreBackend {
  put(record: TraceRecord): Promise<void>;
  get(id: string): Promise<TraceRecord | undefined>;
  query(filters: TraceQuery): Promise<TraceRecord[]>;
  delete(id: string): Promise<boolean>;
  count(): Promise<number>;
}

/** Options for creating a trace record from raw run data. */
export interface IngestOptions {
  runId: string;
  agentId: string;
  tenantId?: string;
  startedAt: number;
  completedAt?: number;
  state: TraceRecord['state'];
  turnCount: number;
  totalTokens: number;
  totalCostUSD?: number;
  events: unknown[];
  metadata?: Record<string, unknown>;
}

/**
 * Compute a SHA-256 hex hash of a string.
 * Falls back to a simple FNV-1a hash if SubtleCrypto is unavailable.
 */
async function sha256(data: string): Promise<string> {
  if (typeof globalThis.crypto?.subtle !== 'undefined') {
    const encoded = new TextEncoder().encode(data);
    const buffer = await globalThis.crypto.subtle.digest('SHA-256', encoded);
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  // Fallback: FNV-1a 32-bit
  let hash = 0x811c9dc5;
  for (let i = 0; i < data.length; i++) {
    hash ^= data.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

/**
 * In-memory trace store implementation.
 * Suitable for local/dev mode and testing.
 */
export class InMemoryTraceStore implements TraceStoreBackend {
  private records = new Map<string, TraceRecord>();

  async put(record: TraceRecord): Promise<void> {
    this.records.set(record.id, record);
  }

  async get(id: string): Promise<TraceRecord | undefined> {
    return this.records.get(id);
  }

  async query(filters: TraceQuery): Promise<TraceRecord[]> {
    let results = Array.from(this.records.values());

    if (filters.runId) results = results.filter((r) => r.runId === filters.runId);
    if (filters.agentId) results = results.filter((r) => r.agentId === filters.agentId);
    if (filters.tenantId) results = results.filter((r) => r.tenantId === filters.tenantId);
    if (filters.state) results = results.filter((r) => r.state === filters.state);
    if (filters.startAfter) results = results.filter((r) => r.startedAt >= filters.startAfter!);
    if (filters.startBefore) results = results.filter((r) => r.startedAt <= filters.startBefore!);

    // Sort by startedAt descending
    results.sort((a, b) => b.startedAt - a.startedAt);

    if (filters.offset) results = results.slice(filters.offset);
    if (filters.limit) results = results.slice(0, filters.limit);

    return results;
  }

  async delete(id: string): Promise<boolean> {
    return this.records.delete(id);
  }

  async count(): Promise<number> {
    return this.records.size;
  }
}

/**
 * TraceStore — high-level trace ingestion and query API.
 */
export class TraceStore {
  private backend: TraceStoreBackend;
  private retentionDays: number;

  constructor(backend?: TraceStoreBackend, retentionDays = 90) {
    this.backend = backend ?? new InMemoryTraceStore();
    this.retentionDays = retentionDays;
  }

  /** Ingest a completed run's trace data. */
  async ingest(options: IngestOptions): Promise<TraceRecord> {
    const eventsJson = JSON.stringify(options.events);
    const contentHash = await sha256(eventsJson);

    const record: TraceRecord = {
      id: `trace_${options.runId}`,
      runId: options.runId,
      agentId: options.agentId,
      tenantId: options.tenantId,
      startedAt: options.startedAt,
      completedAt: options.completedAt,
      state: options.state,
      turnCount: options.turnCount,
      totalTokens: options.totalTokens,
      totalCostUSD: options.totalCostUSD,
      events: options.events,
      contentHash,
      metadata: options.metadata,
    };

    await this.backend.put(record);
    return record;
  }

  /** Get a trace record by ID. */
  async get(id: string): Promise<TraceRecord | undefined> {
    return this.backend.get(id);
  }

  /** Query trace records with filters. */
  async query(filters: TraceQuery): Promise<TraceRecord[]> {
    return this.backend.query(filters);
  }

  /** Delete a trace record. */
  async delete(id: string): Promise<boolean> {
    return this.backend.delete(id);
  }

  /** Get the total count of stored traces. */
  async count(): Promise<number> {
    return this.backend.count();
  }

  /** Purge expired traces older than retention window. */
  async purgeExpired(): Promise<number> {
    const cutoff = Date.now() - this.retentionDays * 24 * 60 * 60 * 1000;
    const expired = await this.backend.query({ startBefore: cutoff });
    let purged = 0;

    for (const record of expired) {
      const deleted = await this.backend.delete(record.id);
      if (deleted) purged++;
    }

    return purged;
  }

  /** Verify a trace record's content hash integrity. */
  async verify(id: string): Promise<boolean> {
    const record = await this.backend.get(id);
    if (!record || !record.contentHash) return false;

    const eventsJson = JSON.stringify(record.events);
    const expectedHash = await sha256(eventsJson);
    return record.contentHash === expectedHash;
  }
}

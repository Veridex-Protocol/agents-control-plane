/**
 * @module ControlPlanePersistence
 * @description
 * Durable persistence backends for the remote control-plane service.
 *
 * Metadata entities are stored in an atomically rewritten JSON snapshot.
 * Trace records are stored as individual files so large traces do not force
 * a full metadata rewrite on every ingest.
 */

import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type { ActiveApproval } from './approval-workflows';
import type { TraceStoreBackend } from './trace-store';
import type {
  ApprovalWorkflow,
  ControlPlaneAuthToken,
  ControlPlaneRole,
  PolicyPack,
  Tenant,
  TraceQuery,
  TraceRecord,
} from './types';

export interface ControlPlaneMetadataSnapshot {
  version: 1;
  revision: number;
  updatedAt: number;
  authTokens: ControlPlaneAuthToken[];
  tenants: Tenant[];
  policyPacks: PolicyPack[];
  approvalWorkflows: ApprovalWorkflow[];
  activeApprovals: ActiveApproval[];
}

const EMPTY_SNAPSHOT: ControlPlaneMetadataSnapshot = {
  version: 1,
  revision: 0,
  updatedAt: 0,
  authTokens: [],
  tenants: [],
  policyPacks: [],
  approvalWorkflows: [],
  activeApprovals: [],
};

function cloneSnapshot(snapshot: ControlPlaneMetadataSnapshot): ControlPlaneMetadataSnapshot {
  return JSON.parse(JSON.stringify(snapshot)) as ControlPlaneMetadataSnapshot;
}

export interface ControlPlaneMetadataStore {
  /** Whether the backing store is shared across multiple service instances. */
  readonly shared?: boolean;
  load(): Promise<ControlPlaneMetadataSnapshot>;
  save(snapshot: ControlPlaneMetadataSnapshot, expectedRevision?: number): Promise<ControlPlaneMetadataSnapshot>;
  close?(): Promise<void>;
}

export interface TraceStoreMetricsBackend extends TraceStoreBackend {
  diskUsageBytes?(): Promise<number>;
}

/** Error raised when a concurrent writer updated the metadata revision first. */
export class MetadataConflictError extends Error {
  constructor(message = 'Control-plane metadata revision conflict') {
    super(message);
    this.name = 'MetadataConflictError';
  }
}

/** A minimal query interface — compatible with pg, postgres.js, drizzle, etc. */
export interface PostgresQueryExecutor {
  query(sql: string, params: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount?: number }>;
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function safeFileName(id: string): string {
  return id.replace(/[^a-zA-Z0-9._-]/g, '_');
}

function safeSqlIdentifier(value: string, label: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new Error(`Invalid ${label} "${value}". Only unquoted snake_case-style SQL identifiers are supported.`);
  }
  return value;
}

export class JSONFileMetadataStore implements ControlPlaneMetadataStore {
  private readonly filePath: string;
  private writeChain = Promise.resolve();

  constructor(dataDir: string, fileName = 'control-plane.json') {
    this.filePath = path.join(dataDir, fileName);
  }

  private async ensureParentDir(): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
  }

  async load(): Promise<ControlPlaneMetadataSnapshot> {
    await this.ensureParentDir();

    try {
      const raw = await readFile(this.filePath, 'utf8');
      const parsed = JSON.parse(raw) as Partial<ControlPlaneMetadataSnapshot>;
      return {
        version: 1,
        revision: typeof parsed.revision === 'number' ? parsed.revision : 0,
        updatedAt: typeof parsed.updatedAt === 'number' ? parsed.updatedAt : 0,
        authTokens: Array.isArray(parsed.authTokens) ? parsed.authTokens : [],
        tenants: Array.isArray(parsed.tenants) ? parsed.tenants : [],
        policyPacks: Array.isArray(parsed.policyPacks) ? parsed.policyPacks : [],
        approvalWorkflows: Array.isArray(parsed.approvalWorkflows) ? parsed.approvalWorkflows : [],
        activeApprovals: Array.isArray(parsed.activeApprovals) ? parsed.activeApprovals : [],
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return cloneSnapshot(EMPTY_SNAPSHOT);
      }
      throw error;
    }
  }

  async save(snapshot: ControlPlaneMetadataSnapshot): Promise<ControlPlaneMetadataSnapshot> {
    const nextSnapshot: ControlPlaneMetadataSnapshot = {
      ...cloneSnapshot(snapshot),
      version: 1,
      revision: (snapshot.revision ?? 0) + 1,
      updatedAt: Date.now(),
    };

    this.writeChain = this.writeChain.then(async () => {
      await this.ensureParentDir();
      const tempPath = `${this.filePath}.tmp`;
      await writeFile(tempPath, JSON.stringify(nextSnapshot, null, 2), 'utf8');
      await rename(tempPath, this.filePath);
    });

    await this.writeChain;
    return nextSnapshot;
  }
}

export class FileTraceStoreBackend implements TraceStoreMetricsBackend {
  private readonly directory: string;

  constructor(dataDir: string, directoryName = 'traces') {
    this.directory = path.join(dataDir, directoryName);
  }

  private async ensureDir(): Promise<void> {
    await mkdir(this.directory, { recursive: true });
  }

  private recordPath(id: string): string {
    return path.join(this.directory, `${safeFileName(id)}.json`);
  }

  async put(record: TraceRecord): Promise<void> {
    await this.ensureDir();
    const tempPath = `${this.recordPath(record.id)}.tmp`;
    await writeFile(tempPath, JSON.stringify(record, null, 2), 'utf8');
    await rename(tempPath, this.recordPath(record.id));
  }

  async get(id: string): Promise<TraceRecord | undefined> {
    await this.ensureDir();
    try {
      const raw = await readFile(this.recordPath(id), 'utf8');
      return JSON.parse(raw) as TraceRecord;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return undefined;
      }
      throw error;
    }
  }

  async query(filters: TraceQuery): Promise<TraceRecord[]> {
    await this.ensureDir();
    const files = await readdir(this.directory);
    const results: TraceRecord[] = [];

    for (const file of files) {
      if (!file.endsWith('.json')) {
        continue;
      }

      const raw = await readFile(path.join(this.directory, file), 'utf8');
      const record = JSON.parse(raw) as TraceRecord;

      if (filters.runId && record.runId !== filters.runId) continue;
      if (filters.agentId && record.agentId !== filters.agentId) continue;
      if (filters.tenantId && record.tenantId !== filters.tenantId) continue;
      if (filters.state && record.state !== filters.state) continue;
      if (typeof filters.startAfter === 'number' && record.startedAt < filters.startAfter) continue;
      if (typeof filters.startBefore === 'number' && record.startedAt > filters.startBefore) continue;

      results.push(record);
    }

    results.sort((a, b) => b.startedAt - a.startedAt);

    const offset = filters.offset ?? 0;
    const limit = filters.limit ?? results.length;
    return results.slice(offset, offset + limit);
  }

  async delete(id: string): Promise<boolean> {
    await this.ensureDir();
    try {
      await rm(this.recordPath(id));
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return false;
      }
      throw error;
    }
  }

  async count(): Promise<number> {
    await this.ensureDir();
    const files = await readdir(this.directory);
    return files.filter((file) => file.endsWith('.json')).length;
  }

  async diskUsageBytes(): Promise<number> {
    await this.ensureDir();
    const files = await readdir(this.directory);
    let total = 0;
    for (const file of files) {
      if (!file.endsWith('.json')) {
        continue;
      }
      const info = await stat(path.join(this.directory, file));
      total += info.size;
    }
    return total;
  }
}

export interface PostgresMetadataStoreConfig {
  db: PostgresQueryExecutor;
  tableName?: string;
  rowId?: string;
  autoCreateTable?: boolean;
}

export class PostgresMetadataStore implements ControlPlaneMetadataStore {
  readonly shared = true;

  private readonly db: PostgresQueryExecutor;
  private readonly tableName: string;
  private readonly rowId: string;
  private readonly autoCreate: boolean;
  private tableReady = false;

  constructor(config: PostgresMetadataStoreConfig) {
    this.db = config.db;
    this.tableName = safeSqlIdentifier(config.tableName ?? 'veridex_control_plane_metadata', 'metadata table name');
    this.rowId = config.rowId ?? 'default';
    this.autoCreate = config.autoCreateTable ?? true;
  }

  private async ensureTable(): Promise<void> {
    if (this.tableReady) {
      return;
    }
    if (this.autoCreate) {
      await this.db.query(
        `CREATE TABLE IF NOT EXISTS ${this.tableName} (
          id TEXT PRIMARY KEY,
          revision BIGINT NOT NULL,
          updated_at BIGINT NOT NULL,
          snapshot JSONB NOT NULL
        )`,
        [],
      );
    }
    this.tableReady = true;
  }

  async load(): Promise<ControlPlaneMetadataSnapshot> {
    await this.ensureTable();
    const result = await this.db.query(
      `SELECT revision, updated_at, snapshot
       FROM ${this.tableName}
       WHERE id = $1`,
      [this.rowId],
    );

    if (result.rows.length === 0) {
      return cloneSnapshot(EMPTY_SNAPSHOT);
    }

    const row = result.rows[0];
    const snapshot = typeof row.snapshot === 'string'
      ? JSON.parse(row.snapshot)
      : row.snapshot;

    return {
      version: 1,
      revision: Number(row.revision ?? (snapshot as { revision?: number }).revision ?? 0),
      updatedAt: Number(row.updated_at ?? (snapshot as { updatedAt?: number }).updatedAt ?? 0),
      authTokens: Array.isArray((snapshot as { authTokens?: unknown[] }).authTokens) ? (snapshot as { authTokens: ControlPlaneAuthToken[] }).authTokens : [],
      tenants: Array.isArray((snapshot as { tenants?: unknown[] }).tenants) ? (snapshot as { tenants: Tenant[] }).tenants : [],
      policyPacks: Array.isArray((snapshot as { policyPacks?: unknown[] }).policyPacks) ? (snapshot as { policyPacks: PolicyPack[] }).policyPacks : [],
      approvalWorkflows: Array.isArray((snapshot as { approvalWorkflows?: unknown[] }).approvalWorkflows) ? (snapshot as { approvalWorkflows: ApprovalWorkflow[] }).approvalWorkflows : [],
      activeApprovals: Array.isArray((snapshot as { activeApprovals?: unknown[] }).activeApprovals) ? (snapshot as { activeApprovals: ActiveApproval[] }).activeApprovals : [],
    };
  }

  async save(snapshot: ControlPlaneMetadataSnapshot, expectedRevision = snapshot.revision): Promise<ControlPlaneMetadataSnapshot> {
    await this.ensureTable();
    const nextSnapshot: ControlPlaneMetadataSnapshot = {
      ...cloneSnapshot(snapshot),
      version: 1,
      revision: expectedRevision + 1,
      updatedAt: Date.now(),
    };

    if (expectedRevision === 0) {
      const insert = await this.db.query(
        `INSERT INTO ${this.tableName} (id, revision, updated_at, snapshot)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (id) DO NOTHING
         RETURNING revision`,
        [this.rowId, nextSnapshot.revision, nextSnapshot.updatedAt, JSON.stringify(nextSnapshot)],
      );
      if ((insert.rowCount ?? insert.rows.length) > 0) {
        return nextSnapshot;
      }
    }

    const result = await this.db.query(
      `UPDATE ${this.tableName}
       SET revision = $2,
           updated_at = $3,
           snapshot = $4
       WHERE id = $1 AND revision = $5
       RETURNING revision`,
      [this.rowId, nextSnapshot.revision, nextSnapshot.updatedAt, JSON.stringify(nextSnapshot), expectedRevision],
    );

    if ((result.rowCount ?? result.rows.length) === 0) {
      throw new MetadataConflictError();
    }

    return nextSnapshot;
  }
}

export interface PostgresTraceStoreBackendConfig {
  db: PostgresQueryExecutor;
  tableName?: string;
  autoCreateTable?: boolean;
}

export class PostgresTraceStoreBackend implements TraceStoreMetricsBackend {
  private readonly db: PostgresQueryExecutor;
  private readonly tableName: string;
  private readonly autoCreate: boolean;
  private tableReady = false;

  constructor(config: PostgresTraceStoreBackendConfig) {
    this.db = config.db;
    this.tableName = safeSqlIdentifier(config.tableName ?? 'veridex_control_plane_traces', 'trace table name');
    this.autoCreate = config.autoCreateTable ?? true;
  }

  private async ensureTable(): Promise<void> {
    if (this.tableReady) {
      return;
    }
    if (this.autoCreate) {
      await this.db.query(
        `CREATE TABLE IF NOT EXISTS ${this.tableName} (
          id TEXT PRIMARY KEY,
          run_id TEXT NOT NULL,
          agent_id TEXT NOT NULL,
          tenant_id TEXT,
          started_at BIGINT NOT NULL,
          completed_at BIGINT,
          state TEXT NOT NULL,
          turn_count INTEGER NOT NULL,
          total_tokens INTEGER NOT NULL,
          total_cost_usd DOUBLE PRECISION,
          content_hash TEXT,
          events JSONB NOT NULL,
          metadata JSONB
        )`,
        [],
      );
      await this.db.query(`CREATE INDEX IF NOT EXISTS ${this.tableName}_run_id_idx ON ${this.tableName} (run_id)`, []);
      await this.db.query(`CREATE INDEX IF NOT EXISTS ${this.tableName}_agent_id_idx ON ${this.tableName} (agent_id)`, []);
      await this.db.query(`CREATE INDEX IF NOT EXISTS ${this.tableName}_tenant_id_idx ON ${this.tableName} (tenant_id)`, []);
      await this.db.query(`CREATE INDEX IF NOT EXISTS ${this.tableName}_started_at_idx ON ${this.tableName} (started_at DESC)`, []);
    }
    this.tableReady = true;
  }

  private rowToRecord(row: Record<string, unknown>): TraceRecord {
    const parseJson = <T>(value: unknown): T | undefined => {
      if (value === undefined || value === null) {
        return undefined;
      }
      return (typeof value === 'string' ? JSON.parse(value) : value) as T;
    };

    return {
      id: String(row.id),
      runId: String(row.run_id),
      agentId: String(row.agent_id),
      tenantId: row.tenant_id ? String(row.tenant_id) : undefined,
      startedAt: Number(row.started_at),
      completedAt: row.completed_at == null ? undefined : Number(row.completed_at),
      state: String(row.state) as TraceRecord['state'],
      turnCount: Number(row.turn_count),
      totalTokens: Number(row.total_tokens),
      totalCostUSD: row.total_cost_usd == null ? undefined : Number(row.total_cost_usd),
      contentHash: row.content_hash ? String(row.content_hash) : undefined,
      events: parseJson<unknown[]>(row.events) ?? [],
      metadata: parseJson<Record<string, unknown>>(row.metadata),
    };
  }

  async put(record: TraceRecord): Promise<void> {
    await this.ensureTable();
    await this.db.query(
      `INSERT INTO ${this.tableName}
       (id, run_id, agent_id, tenant_id, started_at, completed_at, state, turn_count, total_tokens, total_cost_usd, content_hash, events, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       ON CONFLICT (id) DO UPDATE SET
         run_id = EXCLUDED.run_id,
         agent_id = EXCLUDED.agent_id,
         tenant_id = EXCLUDED.tenant_id,
         started_at = EXCLUDED.started_at,
         completed_at = EXCLUDED.completed_at,
         state = EXCLUDED.state,
         turn_count = EXCLUDED.turn_count,
         total_tokens = EXCLUDED.total_tokens,
         total_cost_usd = EXCLUDED.total_cost_usd,
         content_hash = EXCLUDED.content_hash,
         events = EXCLUDED.events,
         metadata = EXCLUDED.metadata`,
      [
        record.id,
        record.runId,
        record.agentId,
        record.tenantId ?? null,
        record.startedAt,
        record.completedAt ?? null,
        record.state,
        record.turnCount,
        record.totalTokens,
        record.totalCostUSD ?? null,
        record.contentHash ?? null,
        JSON.stringify(record.events),
        record.metadata ? JSON.stringify(record.metadata) : null,
      ],
    );
  }

  async get(id: string): Promise<TraceRecord | undefined> {
    await this.ensureTable();
    const result = await this.db.query(
      `SELECT * FROM ${this.tableName} WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? this.rowToRecord(result.rows[0]) : undefined;
  }

  async query(filters: TraceQuery): Promise<TraceRecord[]> {
    await this.ensureTable();
    const where: string[] = [];
    const params: unknown[] = [];

    const push = (clause: string, value: unknown) => {
      params.push(value);
      where.push(clause.replace('?', `$${params.length}`));
    };

    if (filters.runId) push('run_id = ?', filters.runId);
    if (filters.agentId) push('agent_id = ?', filters.agentId);
    if (filters.tenantId) push('tenant_id = ?', filters.tenantId);
    if (filters.state) push('state = ?', filters.state);
    if (typeof filters.startAfter === 'number') push('started_at >= ?', filters.startAfter);
    if (typeof filters.startBefore === 'number') push('started_at <= ?', filters.startBefore);

    let sql = `SELECT * FROM ${this.tableName}`;
    if (where.length > 0) {
      sql += ` WHERE ${where.join(' AND ')}`;
    }
    sql += ' ORDER BY started_at DESC';

    if (typeof filters.limit === 'number') {
      params.push(filters.limit);
      sql += ` LIMIT $${params.length}`;
    }
    if (typeof filters.offset === 'number') {
      params.push(filters.offset);
      sql += ` OFFSET $${params.length}`;
    }

    const result = await this.db.query(sql, params);
    return result.rows.map((row) => this.rowToRecord(row));
  }

  async delete(id: string): Promise<boolean> {
    await this.ensureTable();
    const result = await this.db.query(
      `DELETE FROM ${this.tableName} WHERE id = $1 RETURNING id`,
      [id],
    );
    return (result.rowCount ?? result.rows.length) > 0;
  }

  async count(): Promise<number> {
    await this.ensureTable();
    const result = await this.db.query(`SELECT COUNT(*) AS count FROM ${this.tableName}`, []);
    return Number(result.rows[0]?.count ?? 0);
  }

  async diskUsageBytes(): Promise<number> {
    await this.ensureTable();
    const result = await this.db.query(
      `SELECT COALESCE(SUM(pg_column_size(events) + COALESCE(pg_column_size(metadata), 0)), 0) AS bytes FROM ${this.tableName}`,
      [],
    );
    return Number(result.rows[0]?.bytes ?? 0);
  }
}

export function createAuthTokenRecord(
  token: string,
  options?: {
    id?: string;
    name?: string;
    role?: ControlPlaneRole;
    tenantIds?: string[];
    metadata?: Record<string, unknown>;
  },
): ControlPlaneAuthToken {
  return {
    id: options?.id ?? `tok_${randomUUID()}`,
    name: options?.name ?? 'bootstrap-token',
    tokenHash: sha256Hex(token),
    role: options?.role ?? 'admin',
    tenantIds: options?.tenantIds,
    metadata: options?.metadata,
    createdAt: Date.now(),
  };
}

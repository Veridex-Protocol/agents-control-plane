/**
 * @module server-entry
 * @description
 * CLI entrypoint for running the Veridex control-plane service.
 */

import {
  PostgresMetadataStore,
  PostgresTraceStoreBackend,
  type ControlPlaneMetadataStore,
  type PostgresQueryExecutor,
  type TraceStoreMetricsBackend,
} from './persistence';
import { ControlPlaneService, type ControlPlaneServicePersistence } from './service';
import { startControlPlaneServer } from './server';
import type { ControlPlaneServiceConfig } from './types';

function parseNumber(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBootstrapTokens(raw: string | undefined) {
  if (!raw) {
    return undefined;
  }

  try {
    const parsed = JSON.parse(raw) as unknown;
    if (Array.isArray(parsed)) {
      return parsed as Array<string | { token: string; name?: string; role?: 'admin' | 'operator' | 'approver' | 'viewer'; tenantIds?: string[] }>;
    }
  } catch {
    // Fall back to comma-separated tokens.
  }

  return raw
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (!value) {
    return fallback;
  }
  const normalized = value.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(normalized)) {
    return false;
  }
  return fallback;
}

function resolveStorageBackend(): 'file' | 'postgres' {
  const configured = process.env.VERIDEX_CONTROL_PLANE_STORAGE_BACKEND?.trim().toLowerCase();
  if (configured === 'file' || configured === 'postgres') {
    return configured;
  }
  return process.env.VERIDEX_CONTROL_PLANE_POSTGRES_URL ? 'postgres' : 'file';
}

async function createPostgresPersistence(
  config: NonNullable<ControlPlaneServiceConfig['postgres']>,
): Promise<ControlPlaneServicePersistence> {
  const pgModule = await import('pg');
  const Pool = pgModule.Pool;
  const pool = new Pool({
    connectionString: config.connectionString,
    ssl: config.ssl ? { rejectUnauthorized: false } : undefined,
  });

  const executor: PostgresQueryExecutor = {
    async query(sql, params) {
      const result = await pool.query(sql, params);
      return {
        rows: result.rows as Record<string, unknown>[],
        rowCount: result.rowCount ?? undefined,
      };
    },
  };

  const metadataStore = new PostgresMetadataStore({
    db: executor,
    tableName: config.metadataTableName,
  });
  const traceBackend = new PostgresTraceStoreBackend({
    db: executor,
    tableName: config.tracesTableName,
  });

  const closePool = async () => {
    await pool.end();
  };

  const managedMetadataStore: ControlPlaneMetadataStore = {
    shared: metadataStore.shared,
    load: () => metadataStore.load(),
    save: (snapshot, expectedRevision) => metadataStore.save(snapshot, expectedRevision),
    close: closePool,
  };

  const managedTraceBackend: TraceStoreMetricsBackend = {
    put: (record) => traceBackend.put(record),
    get: (id) => traceBackend.get(id),
    query: (filters) => traceBackend.query(filters),
    delete: (id) => traceBackend.delete(id),
    count: () => traceBackend.count(),
    diskUsageBytes: () => traceBackend.diskUsageBytes(),
  };

  return {
    metadataStore: managedMetadataStore,
    traceBackend: managedTraceBackend,
  };
}

async function main(): Promise<void> {
  const storageBackend = resolveStorageBackend();
  const postgresConfig = storageBackend === 'postgres'
    ? {
        connectionString: process.env.VERIDEX_CONTROL_PLANE_POSTGRES_URL ?? '',
        ssl: parseBoolean(process.env.VERIDEX_CONTROL_PLANE_POSTGRES_SSL, false),
        metadataTableName: process.env.VERIDEX_CONTROL_PLANE_POSTGRES_METADATA_TABLE,
        tracesTableName: process.env.VERIDEX_CONTROL_PLANE_POSTGRES_TRACES_TABLE,
      }
    : undefined;

  if (storageBackend === 'postgres' && !postgresConfig?.connectionString) {
    throw new Error('VERIDEX_CONTROL_PLANE_POSTGRES_URL is required when storage backend is postgres');
  }

  const persistence = postgresConfig
    ? await createPostgresPersistence(postgresConfig)
    : undefined;

  const service = new ControlPlaneService(
    {
      storageBackend,
      host: process.env.VERIDEX_CONTROL_PLANE_HOST,
      port: parseNumber(process.env.VERIDEX_CONTROL_PLANE_PORT, 4010),
      dataDir: process.env.VERIDEX_CONTROL_PLANE_DATA_DIR ?? './data/control-plane',
      authRequired: process.env.VERIDEX_CONTROL_PLANE_AUTH_REQUIRED !== 'false',
      tenantHeader: process.env.VERIDEX_CONTROL_PLANE_TENANT_HEADER,
      bootstrapTokens: parseBootstrapTokens(process.env.VERIDEX_CONTROL_PLANE_BOOTSTRAP_TOKENS),
      approvalSweepIntervalMs: parseNumber(process.env.VERIDEX_CONTROL_PLANE_APPROVAL_SWEEP_MS, 30_000),
      tracePurgeIntervalMs: parseNumber(process.env.VERIDEX_CONTROL_PLANE_TRACE_PURGE_MS, 15 * 60_000),
      traceRetentionDays: parseNumber(process.env.VERIDEX_CONTROL_PLANE_TRACE_RETENTION_DAYS, 90),
      postgres: postgresConfig,
    },
    persistence,
  );

  const server = startControlPlaneServer(service);

  const shutdown = () => {
    void server.close().finally(() => process.exit(0));
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

void main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});

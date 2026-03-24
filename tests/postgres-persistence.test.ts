import { afterEach, describe, expect, it } from 'vitest';

import {
  ControlPlaneService,
  MetadataConflictError,
  PostgresMetadataStore,
  PostgresTraceStoreBackend,
  type ControlPlaneMetadataSnapshot,
  type PostgresQueryExecutor,
  type TraceRecord,
} from '../src';

function normalizeSql(sql: string): string {
  return sql.replace(/\s+/g, ' ').trim().toLowerCase();
}

class FakePostgresExecutor implements PostgresQueryExecutor {
  private metadataRow?: {
    id: string;
    revision: number;
    updated_at: number;
    snapshot: ControlPlaneMetadataSnapshot | string;
  };

  private readonly traces = new Map<string, Record<string, unknown>>();

  async query(sql: string, params: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount?: number }> {
    const normalized = normalizeSql(sql);

    if (normalized.startsWith('create table') || normalized.startsWith('create index')) {
      return { rows: [], rowCount: 0 };
    }

    if (normalized.startsWith('select revision, updated_at, snapshot from')) {
      if (!this.metadataRow || this.metadataRow.id !== params[0]) {
        return { rows: [], rowCount: 0 };
      }
      return {
        rows: [{
          revision: this.metadataRow.revision,
          updated_at: this.metadataRow.updated_at,
          snapshot: this.metadataRow.snapshot,
        }],
        rowCount: 1,
      };
    }

    if (normalized.startsWith('insert into') && normalized.includes('snapshot')) {
      if (this.metadataRow) {
        return { rows: [], rowCount: 0 };
      }
      this.metadataRow = {
        id: String(params[0]),
        revision: Number(params[1]),
        updated_at: Number(params[2]),
        snapshot: typeof params[3] === 'string' ? String(params[3]) : JSON.stringify(params[3]),
      };
      return { rows: [{ revision: this.metadataRow.revision }], rowCount: 1 };
    }

    if (normalized.startsWith('update') && normalized.includes('snapshot =')) {
      if (!this.metadataRow || this.metadataRow.id !== params[0] || this.metadataRow.revision !== Number(params[4])) {
        return { rows: [], rowCount: 0 };
      }
      this.metadataRow = {
        id: String(params[0]),
        revision: Number(params[1]),
        updated_at: Number(params[2]),
        snapshot: typeof params[3] === 'string' ? String(params[3]) : JSON.stringify(params[3]),
      };
      return { rows: [{ revision: this.metadataRow.revision }], rowCount: 1 };
    }

    if (normalized.startsWith('insert into') && normalized.includes('run_id')) {
      const row: Record<string, unknown> = {
        id: params[0],
        run_id: params[1],
        agent_id: params[2],
        tenant_id: params[3],
        started_at: params[4],
        completed_at: params[5],
        state: params[6],
        turn_count: params[7],
        total_tokens: params[8],
        total_cost_usd: params[9],
        content_hash: params[10],
        events: params[11],
        metadata: params[12],
      };
      this.traces.set(String(params[0]), row);
      return { rows: [], rowCount: 1 };
    }

    if (normalized.startsWith('select count(*) as count from')) {
      return { rows: [{ count: this.traces.size }], rowCount: 1 };
    }

    if (normalized.startsWith('select coalesce(sum(pg_column_size(events)')) {
      let total = 0;
      for (const trace of this.traces.values()) {
        total += Buffer.byteLength(JSON.stringify(trace.events ?? []));
        if (trace.metadata != null) {
          total += Buffer.byteLength(JSON.stringify(trace.metadata));
        }
      }
      return { rows: [{ bytes: total }], rowCount: 1 };
    }

    if (normalized.startsWith('select * from') && normalized.includes('where id = $1')) {
      const row = this.traces.get(String(params[0]));
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }

    if (normalized.startsWith('delete from') && normalized.includes('returning id')) {
      const deleted = this.traces.delete(String(params[0]));
      return { rows: deleted ? [{ id: params[0] as string }] : [], rowCount: deleted ? 1 : 0 };
    }

    if (normalized.startsWith('select * from')) {
      let rows = Array.from(this.traces.values());
      const comparisonPattern = /(run_id|agent_id|tenant_id|state|started_at)\s*(=|>=|<=)\s*\$(\d+)/g;

      for (const match of normalized.matchAll(comparisonPattern)) {
        const [, column, operator, paramIndexText] = match;
        const expected = params[Number(paramIndexText) - 1];
        rows = rows.filter((row) => {
          const actual = row[column];
          if (operator === '=') {
            return actual === expected;
          }
          if (operator === '>=') {
            return Number(actual) >= Number(expected);
          }
          return Number(actual) <= Number(expected);
        });
      }

      rows.sort((left, right) => Number(right.started_at) - Number(left.started_at));

      const limitMatch = normalized.match(/limit \$(\d+)/);
      const offsetMatch = normalized.match(/offset \$(\d+)/);
      const limit = limitMatch ? Number(params[Number(limitMatch[1]) - 1]) : rows.length;
      const offset = offsetMatch ? Number(params[Number(offsetMatch[1]) - 1]) : 0;

      return {
        rows: rows.slice(offset, offset + limit),
        rowCount: rows.length,
      };
    }

    throw new Error(`Unhandled SQL in FakePostgresExecutor: ${sql}`);
  }
}

function makeTrace(overrides: Partial<TraceRecord> = {}): TraceRecord {
  return {
    id: overrides.id ?? 'trace_1',
    runId: overrides.runId ?? 'run_1',
    agentId: overrides.agentId ?? 'agent_1',
    tenantId: overrides.tenantId,
    startedAt: overrides.startedAt ?? Date.now(),
    completedAt: overrides.completedAt,
    state: overrides.state ?? 'completed',
    turnCount: overrides.turnCount ?? 1,
    totalTokens: overrides.totalTokens ?? 25,
    totalCostUSD: overrides.totalCostUSD,
    contentHash: overrides.contentHash,
    events: overrides.events ?? [{ type: 'run_completed' }],
    metadata: overrides.metadata,
  };
}

describe('Postgres control-plane persistence', () => {
  let services: ControlPlaneService[] = [];

  afterEach(async () => {
    await Promise.all(services.map((service) => service.close()));
    services = [];
  });

  it('persists metadata snapshots with optimistic concurrency control', async () => {
    const db = new FakePostgresExecutor();
    const store = new PostgresMetadataStore({ db });

    const initial = await store.load();
    expect(initial.revision).toBe(0);

    const saved = await store.save({
      ...initial,
      tenants: [{
        id: 'tenant_1',
        name: 'Acme',
        status: 'active',
        config: {},
        createdAt: 1,
      }],
    });

    expect(saved.revision).toBe(1);
    expect((await store.load()).tenants).toHaveLength(1);
    await expect(store.save(saved, 0)).rejects.toBeInstanceOf(MetadataConflictError);
  });

  it('stores, queries, counts, and deletes traces through the Postgres backend', async () => {
    const db = new FakePostgresExecutor();
    const traces = new PostgresTraceStoreBackend({ db });

    await traces.put(makeTrace({
      id: 'trace_1',
      runId: 'run_1',
      tenantId: 'tenant_a',
      startedAt: 100,
      metadata: { plan: 'alpha' },
    }));
    await traces.put(makeTrace({
      id: 'trace_2',
      runId: 'run_2',
      tenantId: 'tenant_b',
      state: 'failed',
      startedAt: 200,
    }));

    expect(await traces.count()).toBe(2);
    expect((await traces.get('trace_1'))?.runId).toBe('run_1');
    expect(await traces.diskUsageBytes()).toBeGreaterThan(0);

    const tenantScoped = await traces.query({ tenantId: 'tenant_b' });
    expect(tenantScoped).toHaveLength(1);
    expect(tenantScoped[0].id).toBe('trace_2');

    const deleted = await traces.delete('trace_1');
    expect(deleted).toBe(true);
    expect(await traces.count()).toBe(1);
  });

  it('supports shared multi-instance services over a Postgres-style backend', async () => {
    const db = new FakePostgresExecutor();
    const config = {
      storageBackend: 'postgres' as const,
      authRequired: false,
      postgres: {
        connectionString: 'postgres://fake/veridex',
      },
    };

    const serviceA = new ControlPlaneService(config, {
      metadataStore: new PostgresMetadataStore({ db }),
      traceBackend: new PostgresTraceStoreBackend({ db }),
    });
    const serviceB = new ControlPlaneService(config, {
      metadataStore: new PostgresMetadataStore({ db }),
      traceBackend: new PostgresTraceStoreBackend({ db }),
    });
    services = [serviceA, serviceB];

    const [tenantA, tenantB] = await Promise.all([
      serviceA.createTenant({ name: 'Alpha' }),
      serviceB.createTenant({ name: 'Beta' }),
    ]);

    const tenantsA = await serviceA.listTenants();
    const tenantsB = await serviceB.listTenants();

    expect(tenantsA.map((tenant) => tenant.id).sort()).toEqual([tenantA.id, tenantB.id].sort());
    expect(tenantsB.map((tenant) => tenant.name).sort()).toEqual(['Alpha', 'Beta']);

    await serviceA.ingestTrace(makeTrace({
      id: 'trace_shared',
      runId: 'run_shared',
      tenantId: tenantA.id,
      startedAt: 300,
    }));

    const tracesFromB = await serviceB.queryTraces({ tenantId: tenantA.id });
    expect(tracesFromB).toHaveLength(1);
    expect(tracesFromB[0].id).toBe('trace_run_shared');
  });
});

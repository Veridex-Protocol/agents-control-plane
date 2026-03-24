import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ApprovalWorkflowEngine,
  ControlPlaneClient,
  InMemoryTraceStore,
  PolicyPackManager,
  TenantManager,
  TraceStore,
  exportTraces,
  generateEvidenceBundle,
} from '../src';
import type {
  ApprovalWorkflow,
  ControlPlaneConfig,
  PolicyRuleDefinition,
  TraceRecord,
} from '../src';
import type { IngestOptions } from '../src/trace-store';

// ═══════════════════════════════════════════════════════════
// PolicyPackManager
// ═══════════════════════════════════════════════════════════
describe('PolicyPackManager', () => {
  let manager: PolicyPackManager;

  const sampleRules: PolicyRuleDefinition[] = [
    { type: 'max-tokens', params: { limit: 1000 }, enabled: true },
    { type: 'block-tool', params: { toolName: 'dangerousTool' }, enabled: true, description: 'Block dangerous tool' },
  ];

  beforeEach(() => {
    manager = new PolicyPackManager();
  });

  it('creates a policy pack with valid fields', () => {
    const pack = manager.create({
      name: 'Security Pack',
      description: 'Default security policies',
      version: '1.0.0',
      rules: sampleRules,
      tags: ['security', 'default'],
    });
    expect(pack.id).toMatch(/^pp_/);
    expect(pack.name).toBe('Security Pack');
    expect(pack.description).toBe('Default security policies');
    expect(pack.version).toBe('1.0.0');
    expect(pack.rules).toHaveLength(2);
    expect(pack.tags).toEqual(['security', 'default']);
    expect(pack.immutable).toBe(false);
    expect(pack.createdAt).toBeGreaterThan(0);
    expect(pack.updatedAt).toBe(pack.createdAt);
  });

  it('generates unique IDs for each pack', () => {
    const a = manager.create({ name: 'A', description: '', version: '1.0.0', rules: [] });
    const b = manager.create({ name: 'B', description: '', version: '1.0.0', rules: [] });
    expect(a.id).not.toBe(b.id);
  });

  it('gets a pack by ID', () => {
    const pack = manager.create({ name: 'Test', description: '', version: '1.0.0', rules: sampleRules });
    expect(manager.get(pack.id)).toEqual(pack);
  });

  it('returns undefined for non-existent pack', () => {
    expect(manager.get('non-existent')).toBeUndefined();
  });

  it('lists all packs when no tag filter', () => {
    manager.create({ name: 'A', description: '', version: '1.0.0', rules: [], tags: ['security'] });
    manager.create({ name: 'B', description: '', version: '1.0.0', rules: [], tags: ['compliance'] });
    expect(manager.list()).toHaveLength(2);
  });

  it('filters packs by tags', () => {
    manager.create({ name: 'A', description: '', version: '1.0.0', rules: [], tags: ['security'] });
    manager.create({ name: 'B', description: '', version: '1.0.0', rules: [], tags: ['compliance'] });
    const filtered = manager.list(['compliance']);
    expect(filtered).toHaveLength(1);
    expect(filtered[0].name).toBe('B');
  });

  it('returns empty list for unmatched tag filter', () => {
    manager.create({ name: 'A', description: '', version: '1.0.0', rules: [], tags: ['security'] });
    expect(manager.list(['unknown'])).toHaveLength(0);
  });

  it('updates a mutable pack', () => {
    const pack = manager.create({ name: 'Test', description: '', version: '1.0.0', rules: sampleRules });
    const updated = manager.update(pack.id, { name: 'Updated', version: '2.0.0' });
    expect(updated).toBeDefined();
    expect(updated!.name).toBe('Updated');
    expect(updated!.version).toBe('2.0.0');
    expect(updated!.updatedAt).toBeGreaterThanOrEqual(pack.updatedAt);
    // Original description preserved
    expect(updated!.description).toBe('');
  });

  it('returns undefined when updating non-existent pack', () => {
    expect(manager.update('non-existent', { name: 'X' })).toBeUndefined();
  });

  it('throws when updating an immutable pack', () => {
    const pack = manager.registerSystemPack({ name: 'Sys', description: '', version: '1.0.0', rules: sampleRules });
    expect(() => manager.update(pack.id, { name: 'X' })).toThrow(/immutable/);
  });

  it('deletes a mutable pack', () => {
    const pack = manager.create({ name: 'Test', description: '', version: '1.0.0', rules: [] });
    expect(manager.delete(pack.id)).toBe(true);
    expect(manager.get(pack.id)).toBeUndefined();
    expect(manager.count()).toBe(0);
  });

  it('returns false when deleting non-existent pack', () => {
    expect(manager.delete('non-existent')).toBe(false);
  });

  it('throws when deleting an immutable pack', () => {
    const pack = manager.registerSystemPack({ name: 'Sys', description: '', version: '1.0.0', rules: [] });
    expect(() => manager.delete(pack.id)).toThrow(/immutable/);
  });

  it('registers a system (immutable) pack', () => {
    const pack = manager.registerSystemPack({ name: 'Baseline', description: 'Baseline', version: '1.0.0', rules: sampleRules });
    expect(pack.immutable).toBe(true);
    expect(manager.get(pack.id)?.immutable).toBe(true);
  });

  it('counts packs', () => {
    expect(manager.count()).toBe(0);
    manager.create({ name: 'A', description: '', version: '1.0.0', rules: [] });
    manager.create({ name: 'B', description: '', version: '1.0.0', rules: [] });
    expect(manager.count()).toBe(2);
  });

  it('clear removes only non-immutable packs', () => {
    manager.create({ name: 'Mutable', description: '', version: '1.0.0', rules: [] });
    manager.registerSystemPack({ name: 'System', description: '', version: '1.0.0', rules: [] });
    expect(manager.count()).toBe(2);
    manager.clear();
    expect(manager.count()).toBe(1);
    expect(manager.list()[0].name).toBe('System');
  });
});

// ═══════════════════════════════════════════════════════════
// InMemoryTraceStore (backend)
// ═══════════════════════════════════════════════════════════
describe('InMemoryTraceStore', () => {
  let backend: InMemoryTraceStore;

  const makeRecord = (overrides: Partial<TraceRecord> = {}): TraceRecord => ({
    id: 'trace_run1',
    runId: 'run1',
    agentId: 'agent1',
    startedAt: Date.now(),
    state: 'completed',
    turnCount: 5,
    totalTokens: 1000,
    events: [{ type: 'test' }],
    ...overrides,
  });

  beforeEach(() => {
    backend = new InMemoryTraceStore();
  });

  it('puts and gets a record', async () => {
    const record = makeRecord();
    await backend.put(record);
    expect(await backend.get(record.id)).toEqual(record);
  });

  it('returns undefined for missing record', async () => {
    expect(await backend.get('missing')).toBeUndefined();
  });

  it('overwrites record with same ID', async () => {
    await backend.put(makeRecord({ id: 'a', turnCount: 1 }));
    await backend.put(makeRecord({ id: 'a', turnCount: 99 }));
    expect((await backend.get('a'))?.turnCount).toBe(99);
    expect(await backend.count()).toBe(1);
  });

  it('deletes a record', async () => {
    await backend.put(makeRecord());
    expect(await backend.delete('trace_run1')).toBe(true);
    expect(await backend.get('trace_run1')).toBeUndefined();
  });

  it('returns false deleting non-existent record', async () => {
    expect(await backend.delete('missing')).toBe(false);
  });

  it('counts records', async () => {
    expect(await backend.count()).toBe(0);
    await backend.put(makeRecord({ id: 'a' }));
    await backend.put(makeRecord({ id: 'b' }));
    expect(await backend.count()).toBe(2);
  });

  it('queries by runId', async () => {
    await backend.put(makeRecord({ id: 'a', runId: 'run_x' }));
    await backend.put(makeRecord({ id: 'b', runId: 'run_y' }));
    const results = await backend.query({ runId: 'run_x' });
    expect(results).toHaveLength(1);
    expect(results[0].runId).toBe('run_x');
  });

  it('queries by agentId', async () => {
    await backend.put(makeRecord({ id: 'a', agentId: 'agent_1' }));
    await backend.put(makeRecord({ id: 'b', agentId: 'agent_2' }));
    expect(await backend.query({ agentId: 'agent_1' })).toHaveLength(1);
  });

  it('queries by tenantId', async () => {
    await backend.put(makeRecord({ id: 'a', tenantId: 'tenant_1' }));
    await backend.put(makeRecord({ id: 'b', tenantId: 'tenant_2' }));
    expect(await backend.query({ tenantId: 'tenant_1' })).toHaveLength(1);
  });

  it('queries by state', async () => {
    await backend.put(makeRecord({ id: 'a', state: 'completed' }));
    await backend.put(makeRecord({ id: 'b', state: 'failed' }));
    const results = await backend.query({ state: 'failed' });
    expect(results).toHaveLength(1);
    expect(results[0].state).toBe('failed');
  });

  it('queries with startAfter filter', async () => {
    await backend.put(makeRecord({ id: 'a', startedAt: 1000 }));
    await backend.put(makeRecord({ id: 'b', startedAt: 2000 }));
    await backend.put(makeRecord({ id: 'c', startedAt: 3000 }));
    expect(await backend.query({ startAfter: 1500 })).toHaveLength(2);
  });

  it('queries with startBefore filter', async () => {
    await backend.put(makeRecord({ id: 'a', startedAt: 1000 }));
    await backend.put(makeRecord({ id: 'b', startedAt: 2000 }));
    await backend.put(makeRecord({ id: 'c', startedAt: 3000 }));
    expect(await backend.query({ startBefore: 2500 })).toHaveLength(2);
  });

  it('combines multiple query filters', async () => {
    await backend.put(makeRecord({ id: 'a', agentId: 'ag1', state: 'completed', startedAt: 1000 }));
    await backend.put(makeRecord({ id: 'b', agentId: 'ag1', state: 'failed', startedAt: 2000 }));
    await backend.put(makeRecord({ id: 'c', agentId: 'ag2', state: 'completed', startedAt: 3000 }));
    const results = await backend.query({ agentId: 'ag1', state: 'completed' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('a');
  });

  it('applies limit and offset for pagination', async () => {
    for (let i = 0; i < 5; i++) {
      await backend.put(makeRecord({ id: `t${i}`, startedAt: i * 1000 }));
    }
    const page1 = await backend.query({ limit: 2 });
    expect(page1).toHaveLength(2);
    const page2 = await backend.query({ limit: 2, offset: 2 });
    expect(page2).toHaveLength(2);
    const page3 = await backend.query({ limit: 2, offset: 4 });
    expect(page3).toHaveLength(1);
  });

  it('sorts results by startedAt descending', async () => {
    await backend.put(makeRecord({ id: 'a', startedAt: 1000 }));
    await backend.put(makeRecord({ id: 'b', startedAt: 3000 }));
    await backend.put(makeRecord({ id: 'c', startedAt: 2000 }));
    const results = await backend.query({});
    expect(results.map((r) => r.startedAt)).toEqual([3000, 2000, 1000]);
  });

  it('returns empty array for no-match query', async () => {
    await backend.put(makeRecord({ id: 'a', agentId: 'ag1' }));
    expect(await backend.query({ agentId: 'nonexistent' })).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════
// TraceStore (high-level)
// ═══════════════════════════════════════════════════════════
describe('TraceStore', () => {
  let store: TraceStore;

  const makeIngestOpts = (overrides: Partial<IngestOptions> = {}): IngestOptions => ({
    runId: 'run_123',
    agentId: 'agent_test',
    startedAt: Date.now() - 60000,
    completedAt: Date.now(),
    state: 'completed',
    turnCount: 3,
    totalTokens: 500,
    events: [{ type: 'start' }, { type: 'end' }],
    metadata: { source: 'test' },
    ...overrides,
  });

  beforeEach(() => {
    vi.useRealTimers();
    store = new TraceStore(undefined, 90);
  });

  it('ingests with content hash', async () => {
    const record = await store.ingest(makeIngestOpts());
    expect(record.id).toBe('trace_run_123');
    expect(record.runId).toBe('run_123');
    expect(record.agentId).toBe('agent_test');
    expect(record.state).toBe('completed');
    expect(record.contentHash).toBeTruthy();
    expect(typeof record.contentHash).toBe('string');
  });

  it('ingests with optional tenantId', async () => {
    const record = await store.ingest(makeIngestOpts({ tenantId: 'tenant_abc' }));
    expect(record.tenantId).toBe('tenant_abc');
  });

  it('gets an ingested trace by ID', async () => {
    const record = await store.ingest(makeIngestOpts());
    expect(await store.get(record.id)).toEqual(record);
  });

  it('queries traces', async () => {
    await store.ingest(makeIngestOpts());
    await store.ingest(makeIngestOpts({ runId: 'run_456', agentId: 'other' }));
    const results = await store.query({ agentId: 'agent_test' });
    expect(results).toHaveLength(1);
    expect(results[0].agentId).toBe('agent_test');
  });

  it('deletes a trace', async () => {
    const record = await store.ingest(makeIngestOpts());
    expect(await store.delete(record.id)).toBe(true);
    expect(await store.get(record.id)).toBeUndefined();
  });

  it('counts traces', async () => {
    expect(await store.count()).toBe(0);
    await store.ingest(makeIngestOpts());
    expect(await store.count()).toBe(1);
  });

  it('verifies trace integrity (valid)', async () => {
    const record = await store.ingest(makeIngestOpts());
    expect(await store.verify(record.id)).toBe(true);
  });

  it('verify returns false for non-existent trace', async () => {
    expect(await store.verify('missing')).toBe(false);
  });

  it('purges expired traces', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

    const shortStore = new TraceStore(undefined, 1);
    await shortStore.ingest(makeIngestOpts({ runId: 'old', startedAt: Date.now() - 2 * 86400000 }));
    await shortStore.ingest(makeIngestOpts({ runId: 'new' }));

    const purged = await shortStore.purgeExpired();
    expect(purged).toBe(1);
    expect(await shortStore.count()).toBe(1);
  });

  it('purge returns 0 when nothing is expired', async () => {
    await store.ingest(makeIngestOpts());
    expect(await store.purgeExpired()).toBe(0);
  });

  it('preserves metadata on ingest', async () => {
    const record = await store.ingest(makeIngestOpts({ metadata: { env: 'test', version: 2 } }));
    expect(record.metadata).toEqual({ env: 'test', version: 2 });
  });
});

// ═══════════════════════════════════════════════════════════
// ApprovalWorkflowEngine
// ═══════════════════════════════════════════════════════════
describe('ApprovalWorkflowEngine', () => {
  let engine: ApprovalWorkflowEngine;
  let workflow: ApprovalWorkflow;

  beforeEach(() => {
    vi.useRealTimers();
    engine = new ApprovalWorkflowEngine();
    workflow = {
      id: 'wf_1',
      name: 'Standard Approval',
      description: 'Two-step approval',
      escalationChain: [
        { name: 'Team Lead', approvers: ['alice', 'bob'], timeoutSeconds: 300, minApprovals: 1 },
        { name: 'Manager', approvers: ['carol'], timeoutSeconds: 600, minApprovals: 1 },
      ],
      defaultMode: 'block',
    };
    engine.registerWorkflow(workflow);
  });

  it('registers and retrieves a workflow', () => {
    expect(engine.getWorkflow('wf_1')).toEqual(workflow);
  });

  it('lists registered workflows', () => {
    expect(engine.listWorkflows()).toHaveLength(1);
  });

  it('returns undefined for non-existent workflow', () => {
    expect(engine.getWorkflow('missing')).toBeUndefined();
  });

  it('starts an approval request', () => {
    const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Deploy contract', 0.8);
    expect(a.id).toMatch(/^approval_/);
    expect(a.workflowId).toBe('wf_1');
    expect(a.currentStep).toBe(0);
    expect(a.runId).toBe('run_1');
    expect(a.agentId).toBe('agent_1');
    expect(a.proposal).toBe('Deploy contract');
    expect(a.riskScore).toBe(0.8);
    expect(a.approvals).toEqual([]);
    expect(a.resolution).toBeUndefined();
  });

  it('throws when starting approval for non-existent workflow', () => {
    expect(() => engine.startApproval('missing', 'r', 'a', 'p', 0.5)).toThrow('not found');
  });

  it('throws when starting approval for workflow with empty escalation chain', () => {
    engine.registerWorkflow({ id: 'wf_empty', name: 'E', description: '', escalationChain: [], defaultMode: 'block' });
    expect(() => engine.startApproval('wf_empty', 'r', 'a', 'p', 0.5)).toThrow('no escalation steps');
  });

  it('approves when minimum votes are met', () => {
    const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Test', 0.5);
    const result = engine.vote(a.id, 'alice', true, 'Looks good');
    expect(result.resolution).toBe('approved');
    expect(result.approvals).toHaveLength(1);
    expect(result.approvals[0].approver).toBe('alice');
    expect(result.approvals[0].approved).toBe(true);
    expect(result.approvals[0].reason).toBe('Looks good');
    expect(result.approvals[0].votedAt).toBeGreaterThan(0);
  });

  it('denies when enough rejections make approval impossible', () => {
    const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Test', 0.5);
    engine.vote(a.id, 'alice', false, 'Too risky');
    const result = engine.vote(a.id, 'bob', false, 'Agree');
    expect(result.resolution).toBe('denied');
  });

  it('throws when voting on non-existent approval', () => {
    expect(() => engine.vote('missing', 'alice', true)).toThrow('not found');
  });

  it('throws when voting on already resolved approval', () => {
    const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Test', 0.5);
    engine.vote(a.id, 'alice', true);
    expect(() => engine.vote(a.id, 'bob', true)).toThrow('already resolved');
  });

  it('throws when unauthorized approver votes', () => {
    const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Test', 0.5);
    expect(() => engine.vote(a.id, 'eve', true)).toThrow('not an authorized approver');
  });

  it('lists pending approvals', () => {
    engine.startApproval('wf_1', 'run_1', 'agent_1', 'T1', 0.5);
    engine.startApproval('wf_1', 'run_2', 'agent_2', 'T2', 0.3);
    expect(engine.listPending()).toHaveLength(2);
  });

  it('lists resolved approvals', () => {
    const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Test', 0.5);
    engine.vote(a.id, 'alice', true);
    expect(engine.listResolved()).toHaveLength(1);
    expect(engine.listPending()).toHaveLength(0);
  });

  it('clears only resolved approvals', () => {
    const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Test', 0.5);
    engine.vote(a.id, 'alice', true);
    engine.startApproval('wf_1', 'run_2', 'agent_2', 'Test 2', 0.3);
    expect(engine.clearResolved()).toBe(1);
    expect(engine.listPending()).toHaveLength(1);
    expect(engine.listResolved()).toHaveLength(0);
  });

  it('gets an approval by ID', () => {
    const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Test', 0.5);
    expect(engine.getApproval(a.id)).toEqual(a);
  });

  it('returns undefined for non-existent approval', () => {
    expect(engine.getApproval('missing')).toBeUndefined();
  });

  describe('timeout and escalation', () => {
    it('escalates to the next step on timeout', () => {
      const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Test', 0.5);
      a.currentStepDeadline = Date.now() - 1000;
      const processed = engine.processTimeouts();
      expect(processed).toHaveLength(1);
      expect(processed[0].currentStep).toBe(1);
      expect(processed[0].resolution).toBeUndefined();
      expect(processed[0].approvals).toEqual([]); // Votes reset on escalation
    });

    it('times out when all steps exhausted (block mode)', () => {
      const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Test', 0.5);
      a.currentStep = 1;
      a.currentStepDeadline = Date.now() - 1000;
      const processed = engine.processTimeouts();
      expect(processed).toHaveLength(1);
      expect(processed[0].resolution).toBe('timed-out');
    });

    it('auto-approves after autoApproveAfterSeconds', () => {
      engine.registerWorkflow({
        id: 'wf_auto',
        name: 'Auto',
        description: 'Auto-approve test',
        escalationChain: [{ name: 'Team', approvers: ['alice'], timeoutSeconds: 10, minApprovals: 1 }],
        autoApproveAfterSeconds: 5,
        defaultMode: 'block',
      });
      const a = engine.startApproval('wf_auto', 'run_1', 'agent_1', 'Test', 0.2);
      a.createdAt = Date.now() - 10000;
      a.currentStepDeadline = Date.now() - 1000;
      const processed = engine.processTimeouts();
      expect(processed).toHaveLength(1);
      expect(processed[0].resolution).toBe('auto-approved');
    });

    it('auto-approves via defaultMode=auto-approve', () => {
      engine.registerWorkflow({
        id: 'wf_auto_d',
        name: 'AD',
        description: '',
        escalationChain: [{ name: 'Team', approvers: ['alice'], timeoutSeconds: 10, minApprovals: 1 }],
        defaultMode: 'auto-approve',
      });
      const a = engine.startApproval('wf_auto_d', 'run_1', 'agent_1', 'Test', 0.2);
      a.currentStepDeadline = Date.now() - 1000;
      const processed = engine.processTimeouts();
      expect(processed[0].resolution).toBe('auto-approved');
    });

    it('does nothing for approvals not yet timed out', () => {
      engine.startApproval('wf_1', 'run_1', 'agent_1', 'Test', 0.5);
      expect(engine.processTimeouts()).toHaveLength(0);
    });

    it('skips already-resolved approvals during timeout processing', () => {
      const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Test', 0.5);
      engine.vote(a.id, 'alice', true);
      a.currentStepDeadline = Date.now() - 1000;
      expect(engine.processTimeouts()).toHaveLength(0);
    });

    it('full escalation chain integration with fake timers', () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2026-03-24T10:00:00.000Z'));

      const a = engine.startApproval('wf_1', 'run_1', 'agent_1', 'Big transfer', 0.9);
      expect(engine.listPending()).toHaveLength(1);

      // Unauthorized voter
      expect(() => engine.vote(a.id, 'mallory', true)).toThrow(/not an authorized approver/);

      // Step 0 times out -> escalate to step 1
      vi.advanceTimersByTime(301_000);
      const processed = engine.processTimeouts();
      expect(processed[0].currentStep).toBe(1);
      expect(processed[0].resolution).toBeUndefined();

      // Carol approves at step 1
      const resolved = engine.vote(a.id, 'carol', true, 'approved');
      expect(resolved.resolution).toBe('approved');
      expect(engine.listResolved()).toHaveLength(1);
      expect(engine.clearResolved()).toBe(1);
    });
  });
});

// ═══════════════════════════════════════════════════════════
// Audit Export
// ═══════════════════════════════════════════════════════════
describe('exportTraces', () => {
  const records: TraceRecord[] = [
    {
      id: 'trace_1',
      runId: 'run_1',
      agentId: 'agent_1',
      tenantId: 'tenant_1',
      startedAt: 1700000000000,
      completedAt: 1700000060000,
      state: 'completed',
      turnCount: 5,
      totalTokens: 1000,
      totalCostUSD: 0.05,
      events: [{ type: 'start' }],
      contentHash: 'abc123',
    },
    {
      id: 'trace_2',
      runId: 'run_2',
      agentId: 'agent_2',
      startedAt: 1700000100000,
      state: 'failed',
      turnCount: 2,
      totalTokens: 300,
      events: [{ type: 'error' }],
    },
  ];

  it('exports as JSON', () => {
    const result = exportTraces(records, { format: 'json' });
    expect(result.format).toBe('json');
    expect(result.recordCount).toBe(2);
    const parsed = JSON.parse(result.data);
    expect(parsed).toHaveLength(2);
    expect(parsed[0].id).toBe('trace_1');
    expect(parsed[0].events).toBeUndefined(); // Not included by default
  });

  it('exports JSON with events included', () => {
    const result = exportTraces(records, { format: 'json', includeEvents: true });
    const parsed = JSON.parse(result.data);
    expect(parsed[0].events).toEqual([{ type: 'start' }]);
  });

  it('exports as JSONL', () => {
    const result = exportTraces(records, { format: 'jsonl' });
    expect(result.format).toBe('jsonl');
    const lines = result.data.split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).id).toBe('trace_1');
    expect(JSON.parse(lines[1]).id).toBe('trace_2');
  });

  it('exports as CSV with default fields', () => {
    const result = exportTraces(records, { format: 'csv' });
    expect(result.format).toBe('csv');
    const lines = result.data.split('\n');
    expect(lines[0]).toBe('id,runId,agentId,tenantId,startedAt,completedAt,state,turnCount,totalTokens,totalCostUSD');
    expect(lines[1]).toContain('trace_1');
    expect(lines[1]).toContain('completed');
  });

  it('exports as CSV with custom fields', () => {
    const result = exportTraces(records, { format: 'csv', csvFields: ['id', 'state'] });
    const lines = result.data.split('\n');
    expect(lines[0]).toBe('id,state');
    expect(lines[1]).toBe('trace_1,completed');
    expect(lines[2]).toBe('trace_2,failed');
  });

  it('CSV handles empty/undefined values', () => {
    const result = exportTraces(records, { format: 'csv', csvFields: ['id', 'tenantId', 'completedAt'] });
    const lines = result.data.split('\n');
    // Second record has no tenantId or completedAt
    expect(lines[2]).toBe('trace_2,,');
  });

  it('throws for unsupported format', () => {
    expect(() => exportTraces(records, { format: 'xml' as any })).toThrow('Unsupported export format');
  });

  it('sets generatedAt timestamp', () => {
    const before = Date.now();
    const result = exportTraces(records, { format: 'json' });
    expect(result.generatedAt).toBeGreaterThanOrEqual(before);
  });

  it('handles empty records array', () => {
    const result = exportTraces([], { format: 'json' });
    expect(result.recordCount).toBe(0);
    expect(JSON.parse(result.data)).toEqual([]);
  });
});

describe('generateEvidenceBundle', () => {
  const trace: TraceRecord = {
    id: 'trace_run_1',
    runId: 'run_1',
    agentId: 'agent_1',
    startedAt: Date.now(),
    state: 'completed',
    turnCount: 3,
    totalTokens: 500,
    events: [{ type: 'test_event' }],
  };

  it('generates a valid evidence bundle', async () => {
    const bundle = await generateEvidenceBundle(trace, [{ verdict: 'allow' }], [{ approved: true }]);
    expect(bundle.id).toBe('evidence_run_1');
    expect(bundle.runId).toBe('run_1');
    expect(bundle.version).toBe('1.0.0');
    expect(bundle.traceHash).toBeTruthy();
    expect(bundle.policyHash).toBeTruthy();
    expect(bundle.approvalHash).toBeTruthy();
    expect(bundle.contentHash).toBeTruthy();
    expect(bundle.traceId).toBe('trace_run_1');
    expect(bundle.policyDecisions).toEqual([{ verdict: 'allow' }]);
    expect(bundle.approvalDecisions).toEqual([{ approved: true }]);
    expect(bundle.generatedAt).toBeGreaterThan(0);
  });

  it('produces consistent hashes for same input', async () => {
    const b1 = await generateEvidenceBundle(trace, [], []);
    const b2 = await generateEvidenceBundle(trace, [], []);
    expect(b1.traceHash).toBe(b2.traceHash);
    expect(b1.contentHash).toBe(b2.contentHash);
  });

  it('produces different hashes for different inputs', async () => {
    const b1 = await generateEvidenceBundle(trace, [], []);
    const b2 = await generateEvidenceBundle({ ...trace, events: [{ type: 'different' }] }, [], []);
    expect(b1.traceHash).not.toBe(b2.traceHash);
  });

  it('produces different contentHash for different policy decisions', async () => {
    const b1 = await generateEvidenceBundle(trace, [{ verdict: 'allow' }], []);
    const b2 = await generateEvidenceBundle(trace, [{ verdict: 'deny' }], []);
    expect(b1.policyHash).not.toBe(b2.policyHash);
    expect(b1.contentHash).not.toBe(b2.contentHash);
  });
});

// ═══════════════════════════════════════════════════════════
// TenantManager
// ═══════════════════════════════════════════════════════════
describe('TenantManager', () => {
  let manager: TenantManager;

  beforeEach(() => {
    manager = new TenantManager();
  });

  it('creates a tenant with sane defaults', () => {
    const t = manager.create({ name: 'Acme Corp' });
    expect(t.id).toMatch(/^tenant_/);
    expect(t.name).toBe('Acme Corp');
    expect(t.status).toBe('active');
    expect(t.config.maxConcurrentRuns).toBe(10);
    expect(t.config.auditEnabled).toBe(true);
    expect(t.config.traceRetentionDays).toBe(90);
    expect(t.config.deploymentMode).toBe('local');
    expect(t.createdAt).toBeGreaterThan(0);
  });

  it('creates a tenant with custom config', () => {
    const t = manager.create({
      name: 'BigCo',
      config: { maxConcurrentRuns: 50, dailySpendLimitUSD: 100, deploymentMode: 'private-cloud' },
      metadata: { tier: 'enterprise' },
    });
    expect(t.config.maxConcurrentRuns).toBe(50);
    expect(t.config.dailySpendLimitUSD).toBe(100);
    expect(t.config.deploymentMode).toBe('private-cloud');
    expect(t.metadata).toEqual({ tier: 'enterprise' });
  });

  it('gets a tenant by ID', () => {
    const t = manager.create({ name: 'Test' });
    expect(manager.get(t.id)).toEqual(t);
  });

  it('returns undefined for non-existent tenant', () => {
    expect(manager.get('missing')).toBeUndefined();
  });

  it('lists all tenants', () => {
    manager.create({ name: 'A' });
    manager.create({ name: 'B' });
    expect(manager.list()).toHaveLength(2);
  });

  it('lists tenants filtered by status', () => {
    const a = manager.create({ name: 'A' });
    manager.create({ name: 'B' });
    manager.suspend(a.id);
    expect(manager.list('active')).toHaveLength(1);
    expect(manager.list('suspended')).toHaveLength(1);
  });

  it('updates tenant config (merges)', () => {
    const t = manager.create({ name: 'Test' });
    const updated = manager.updateConfig(t.id, { maxConcurrentRuns: 20 });
    expect(updated!.config.maxConcurrentRuns).toBe(20);
    expect(updated!.config.auditEnabled).toBe(true); // Preserved
  });

  it('returns undefined when updating non-existent tenant', () => {
    expect(manager.updateConfig('missing', {})).toBeUndefined();
  });

  it('suspends a tenant', () => {
    const t = manager.create({ name: 'Test' });
    expect(manager.suspend(t.id)!.status).toBe('suspended');
  });

  it('returns undefined when suspending non-existent tenant', () => {
    expect(manager.suspend('missing')).toBeUndefined();
  });

  it('activates a suspended tenant', () => {
    const t = manager.create({ name: 'Test' });
    manager.suspend(t.id);
    expect(manager.activate(t.id)!.status).toBe('active');
  });

  it('returns undefined when activating non-existent tenant', () => {
    expect(manager.activate('missing')).toBeUndefined();
  });

  it('deletes a tenant', () => {
    const t = manager.create({ name: 'Test' });
    expect(manager.delete(t.id)).toBe(true);
    expect(manager.get(t.id)).toBeUndefined();
  });

  it('returns false when deleting non-existent tenant', () => {
    expect(manager.delete('missing')).toBe(false);
  });

  it('counts tenants', () => {
    expect(manager.count()).toBe(0);
    manager.create({ name: 'A' });
    manager.create({ name: 'B' });
    expect(manager.count()).toBe(2);
    manager.delete(manager.list()[0].id);
    expect(manager.count()).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════
// ControlPlaneClient (Integration)
// ═══════════════════════════════════════════════════════════
describe('ControlPlaneClient', () => {
  let client: ControlPlaneClient;
  const config: ControlPlaneConfig = {
    mode: 'local',
    tenantId: 'default_tenant',
    traceRetentionDays: 30,
  };

  beforeEach(() => {
    vi.useRealTimers();
    client = new ControlPlaneClient(config);
  });

  it('initializes with config and sub-systems', () => {
    expect(client.config).toEqual(config);
    expect(client.policyPacks).toBeInstanceOf(PolicyPackManager);
    expect(client.traces).toBeInstanceOf(TraceStore);
    expect(client.approvalWorkflows).toBeInstanceOf(ApprovalWorkflowEngine);
    expect(client.tenants).toBeInstanceOf(TenantManager);
  });

  it('accepts a custom trace backend', () => {
    const customBackend = new InMemoryTraceStore();
    const c = new ControlPlaneClient(config, customBackend);
    expect(c.traces).toBeInstanceOf(TraceStore);
  });

  it('ingests a trace with default tenant ID from config', async () => {
    const record = await client.ingestTrace({
      runId: 'run_1',
      agentId: 'agent_1',
      startedAt: Date.now() - 5000,
      completedAt: Date.now(),
      state: 'completed',
      turnCount: 3,
      totalTokens: 500,
      events: [{ type: 'test' }],
    });
    expect(record.tenantId).toBe('default_tenant');
  });

  it('ingests a trace with explicit tenant ID override', async () => {
    const record = await client.ingestTrace({
      runId: 'run_2',
      agentId: 'agent_1',
      tenantId: 'explicit_tenant',
      startedAt: Date.now(),
      state: 'completed',
      turnCount: 1,
      totalTokens: 100,
      events: [],
    });
    expect(record.tenantId).toBe('explicit_tenant');
  });

  it('exports audit data in multiple formats', async () => {
    const record = await client.ingestTrace({
      runId: 'run_1',
      agentId: 'agent_1',
      startedAt: Date.now(),
      state: 'completed',
      turnCount: 1,
      totalTokens: 100,
      events: [],
    });

    const json = client.exportAudit([record], { format: 'json' });
    expect(json.format).toBe('json');
    expect(json.recordCount).toBe(1);

    const jsonl = client.exportAudit([record], { format: 'jsonl' });
    expect(jsonl.format).toBe('jsonl');

    const csv = client.exportAudit([record], { format: 'csv' });
    expect(csv.format).toBe('csv');
  });

  it('generates evidence bundle', async () => {
    const record = await client.ingestTrace({
      runId: 'run_1',
      agentId: 'agent_1',
      startedAt: Date.now(),
      state: 'completed',
      turnCount: 1,
      totalTokens: 100,
      events: [{ type: 'test' }],
    });
    const bundle = await client.generateEvidence(record, [{ verdict: 'allow' }], [{ approved: true }]);
    expect(bundle.runId).toBe('run_1');
    expect(bundle.contentHash).toBeTruthy();
  });

  it('verifies trace integrity', async () => {
    const record = await client.ingestTrace({
      runId: 'run_1',
      agentId: 'agent_1',
      startedAt: Date.now(),
      state: 'completed',
      turnCount: 1,
      totalTokens: 100,
      events: [{ type: 'test' }],
    });
    expect(await client.verifyTrace(record.id)).toBe(true);
  });

  it('purges expired traces', async () => {
    await client.ingestTrace({
      runId: 'run_1',
      agentId: 'agent_1',
      startedAt: Date.now(),
      state: 'completed',
      turnCount: 1,
      totalTokens: 100,
      events: [],
    });
    // Recent trace, shouldn't be purged
    expect(await client.purgeExpiredTraces()).toBe(0);
  });

  it('processes approval timeouts', () => {
    const wf: ApprovalWorkflow = {
      id: 'wf_test',
      name: 'Test',
      description: '',
      escalationChain: [{ name: 'S1', approvers: ['alice'], timeoutSeconds: 1, minApprovals: 1 }],
      defaultMode: 'block',
    };
    client.approvalWorkflows.registerWorkflow(wf);
    expect(client.processApprovalTimeouts()).toHaveLength(0);
  });

  it('end-to-end: tenant + policy pack + trace + audit + evidence', async () => {
    // Create tenant
    const tenant = client.tenants.create({ name: 'E2E Corp', config: { maxConcurrentRuns: 5 } });
    expect(tenant.status).toBe('active');

    // Create policy pack
    const pack = client.policyPacks.create({
      name: 'E2E Policy',
      description: 'End-to-end test policy',
      version: '1.0.0',
      rules: [{ type: 'max-tokens', params: { limit: 500 }, enabled: true }],
    });
    expect(pack.id).toBeTruthy();

    // Ingest trace
    const record = await client.ingestTrace({
      runId: 'e2e_run',
      agentId: 'e2e_agent',
      tenantId: tenant.id,
      startedAt: Date.now() - 1000,
      completedAt: Date.now(),
      state: 'completed',
      turnCount: 2,
      totalTokens: 250,
      events: [{ type: 'run_started' }, { type: 'run_completed' }],
    });
    expect(record.tenantId).toBe(tenant.id);

    // Verify integrity
    expect(await client.verifyTrace(record.id)).toBe(true);

    // Export
    const audit = client.exportAudit([record], { format: 'jsonl' });
    expect(audit.recordCount).toBe(1);

    // Evidence bundle
    const evidence = await client.generateEvidence(
      record,
      [{ ruleId: pack.id, verdict: 'allow' }],
      [],
    );
    expect(evidence.runId).toBe('e2e_run');
    expect(evidence.contentHash).toBeTruthy();
  });
});

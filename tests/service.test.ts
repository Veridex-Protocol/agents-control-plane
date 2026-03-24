import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  ControlPlaneService,
  RemoteControlPlaneClient,
  createControlPlaneApp,
} from '../src';

async function makeTempDir(): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), 'veridex-control-plane-'));
}

describe('ControlPlaneService persistence', () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop();
      if (dir) {
        await rm(dir, { recursive: true, force: true });
      }
    }
  });

  it('persists tenants, workflows, approvals, traces, and tokens across service restarts', async () => {
    const dataDir = await makeTempDir();
    tempDirs.push(dataDir);

    const first = new ControlPlaneService({
      dataDir,
      bootstrapTokens: ['root-secret'],
    });

    const tenant = await first.createTenant({ name: 'Acme' });
    const pack = await first.createPolicyPack({
      name: 'Baseline',
      description: 'Default controls',
      version: '1.0.0',
      rules: [{ type: 'maxRunSpendUSD', params: { limit: 25 }, enabled: true }],
    });
    await first.registerWorkflow({
      id: 'wf_main',
      name: 'Main',
      description: 'Primary approval workflow',
      escalationChain: [{ name: 'Ops', approvers: ['ops'], timeoutSeconds: 60, minApprovals: 1 }],
      defaultMode: 'block',
    });
    const approval = await first.startApproval({
      workflowId: 'wf_main',
      runId: 'run_1',
      agentId: 'agent_1',
      proposal: 'Ship deployment',
      riskScore: 0.7,
    });
    await first.ingestTrace({
      runId: 'run_1',
      agentId: 'agent_1',
      tenantId: tenant.id,
      startedAt: Date.now() - 1_000,
      completedAt: Date.now(),
      state: 'completed',
      turnCount: 2,
      totalTokens: 120,
      events: [{ type: 'run_started' }, { type: 'run_completed' }],
    });
    const issued = await first.issueToken({ name: 'operator', role: 'operator', tenantIds: [tenant.id] });

    const second = new ControlPlaneService({
      dataDir,
      bootstrapTokens: ['root-secret'],
    });

    expect((await second.getTenant(tenant.id))?.name).toBe('Acme');
    expect((await second.getPolicyPack(pack.id))?.name).toBe('Baseline');
    expect((await second.getWorkflow('wf_main'))?.name).toBe('Main');
    expect((await second.getApproval(approval.id))?.proposal).toBe('Ship deployment');
    expect((await second.getTrace('trace_run_1'))?.tenantId).toBe(tenant.id);
    expect((await second.listTokens()).some((token) => token.id === issued.record.id)).toBe(true);
  });
});

describe('remote control-plane app and client', () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop();
      if (dir) {
        await rm(dir, { recursive: true, force: true });
      }
    }
  });

  it('serves authenticated control-plane APIs and supports the remote client', async () => {
    const dataDir = await makeTempDir();
    tempDirs.push(dataDir);

    const service = new ControlPlaneService({
      dataDir,
      bootstrapTokens: ['admin-secret'],
    });
    const app = createControlPlaneApp(service);

    const fetchLike: typeof fetch = async (input, init) => app.request(input, init);
    const client = new RemoteControlPlaneClient({
      mode: 'managed',
      endpoint: 'http://control-plane.local',
      authToken: 'admin-secret',
      fetch: fetchLike,
    });

    const health = await client.health();
    expect(health.ready).toBe(true);

    const tenant = await client.createTenant({ name: 'Remote Tenant' });
    expect(tenant.name).toBe('Remote Tenant');

    await client.registerWorkflow({
      id: 'wf_remote',
      name: 'Remote Workflow',
      description: 'Workflow over HTTP',
      escalationChain: [{ name: 'Ops', approvers: ['ops'], timeoutSeconds: 60, minApprovals: 1 }],
      defaultMode: 'block',
    });

    const approval = await client.startApproval({
      workflowId: 'wf_remote',
      runId: 'run_http',
      agentId: 'agent_http',
      proposal: 'Promote deployment',
      riskScore: 0.4,
    });
    expect(approval.workflowId).toBe('wf_remote');

    await client.ingestTrace({
      runId: 'run_http',
      agentId: 'agent_http',
      tenantId: tenant.id,
      startedAt: Date.now() - 2_000,
      completedAt: Date.now(),
      state: 'completed',
      turnCount: 1,
      totalTokens: 40,
      events: [{ type: 'run_started' }, { type: 'run_completed' }],
    });

    const traces = await client.queryTraces({ tenantId: tenant.id });
    expect(traces).toHaveLength(1);
    expect(traces[0].runId).toBe('run_http');

    const evidence = await client.generateEvidence('trace_run_http', {
      policyDecisions: [{ verdict: 'pass' }],
      approvalDecisions: [{ approved: true }],
    });
    expect(evidence).toBeDefined();
  });
});

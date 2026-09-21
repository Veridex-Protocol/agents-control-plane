import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';
import {
  CHARGE_AUTHORIZATION_VERSION,
  createChargeAuthorization,
  type UnsignedChargeAuthorization,
} from '@veridex/platform-events';

import {
  ControlPlaneService,
  RemoteControlPlaneClient,
  createControlPlaneApp,
  type AgentManifest,
  type WorkspaceResource,
  type Task,
  type DeploymentRevision,
  type Incident,
  type EvalSuite,
  type EvalRun,
  type PolicyBinding,
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

// ── Workforce OS Resource CRUD ──

describe('Workforce OS CRUD', () => {
  const tempDirs: string[] = [];

  async function makeService(): Promise<ControlPlaneService> {
    const dataDir = await mkdtemp(path.join(os.tmpdir(), 'veridex-wos-'));
    tempDirs.push(dataDir);
    return new ControlPlaneService({ dataDir, bootstrapTokens: ['root'] });
  }

  afterEach(async () => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop();
      if (dir) await rm(dir, { recursive: true, force: true });
    }
  });

  // ── Agent Manifests ──

  it('registers, reads, lists, updates, and removes agent manifests', async () => {
    const svc = await makeService();

    const manifest = await svc.registerAgentManifest({
      name: 'Summariser',
      version: '1.0.0',
      status: 'active',
      capabilities: ['summarise', 'extract'],
    });
    expect(manifest.id).toMatch(/^am_/);
    expect(manifest.name).toBe('Summariser');

    const fetched = await svc.getAgentManifest(manifest.id);
    expect(fetched?.version).toBe('1.0.0');

    const all = await svc.listAgentManifests();
    expect(all).toHaveLength(1);

    const filtered = await svc.listAgentManifests('disabled');
    expect(filtered).toHaveLength(0);

    const updated = await svc.updateAgentManifest(manifest.id, { status: 'draining' });
    expect(updated?.status).toBe('draining');

    const removed = await svc.removeAgentManifest(manifest.id);
    expect(removed).toBe(true);

    expect(await svc.listAgentManifests()).toHaveLength(0);
    expect(await svc.removeAgentManifest('nonexistent')).toBe(false);
  });

  // ── Workspace Resources ──

  it('creates, reads, lists, updates, and deletes workspaces', async () => {
    const svc = await makeService();

    const workspace = await svc.createWorkspace({
      tenantId: 'tenant_1',
      name: 'Treasury Ops',
      status: 'active',
      description: 'Primary treasury workspace',
    });
    expect(workspace.id).toMatch(/^ws_/);

    const fetched = await svc.getWorkspace(workspace.id);
    expect(fetched?.name).toBe('Treasury Ops');

    expect(await svc.listWorkspaces({ tenantId: 'tenant_1' })).toHaveLength(1);

    const updated = await svc.updateWorkspace(workspace.id, { status: 'suspended' });
    expect(updated?.status).toBe('suspended');

    expect(await svc.deleteWorkspace(workspace.id)).toBe(true);
  });

  it('creates, reads, lists, updates, and deletes workspace resources', async () => {
    const svc = await makeService();

    const res = await svc.createWorkspaceResource({
      resourceType: 'config',
      name: 'api-keys',
      status: 'active',
      data: { openai: 'sk-...' },
      tags: ['secrets'],
    });
    expect(res.id).toMatch(/^wr_/);
    expect(res.version).toBe(1);

    const fetched = await svc.getWorkspaceResource(res.id);
    expect(fetched?.name).toBe('api-keys');
    expect(await svc.getWorkspaceResource(res.id, 'tenant_other')).toBeUndefined();

    await svc.createWorkspaceResource({
      resourceType: 'dataset',
      name: 'train-v1',
      status: 'active',
      data: { rows: 1000 },
      tags: ['ml'],
    });

    expect(await svc.listWorkspaceResources()).toHaveLength(2);
    expect(await svc.listWorkspaceResources({ resourceType: 'config' })).toHaveLength(1);
    expect(await svc.listWorkspaceResources({ tags: ['ml'] })).toHaveLength(1);
    expect(await svc.listWorkspaceResources({ status: 'archived' })).toHaveLength(0);

    const updated = await svc.updateWorkspaceResource(res.id, { name: 'keys-v2' });
    expect(updated?.name).toBe('keys-v2');
    expect(updated?.version).toBe(2);

    expect(await svc.deleteWorkspaceResource(res.id)).toBe(true);
    expect(await svc.deleteWorkspaceResource('nonexistent')).toBe(false);
  });

  it('stores versioned sponsorship policies with tenant isolation and authorization gates', async () => {
    const svc = await makeService();
    const basePolicy = {
      schemaVersion: 'veridex.sponsorship-policy/v1' as const,
      appId: 'app_1',
      environment: 'test' as const,
      mode: 'business_paid' as const,
      enabled: true,
      allowedChains: ['eip155:84532'],
      allowedFeeAssets: ['eip155:84532/slip44:60'],
      allowedOperations: ['transfer'],
      perTransactionLimit: '100',
      dailyLimit: '1000',
      monthlyLimit: '10000',
      subsidyBps: 10_000,
      markupBps: 0,
      requireUserAuthorization: false,
      updatedBy: 'token_admin',
    };

    const created = await svc.putSponsorshipPolicy('tenant_1', basePolicy);
    expect(created.version).toBe(1);
    expect((await svc.getSponsorshipPolicy('tenant_1', 'app_1', 'test'))?.id).toBe(created.id);
    expect(await svc.getSponsorshipPolicy('tenant_2', 'app_1', 'test')).toBeUndefined();

    const updated = await svc.putSponsorshipPolicy('tenant_1', {
      ...basePolicy,
      dailyLimit: '2000',
    });
    expect(updated.id).toBe(created.id);
    expect(updated.version).toBe(2);

    await expect(svc.putSponsorshipPolicy('tenant_1', {
      ...basePolicy,
      mode: 'user_reimburses',
      requireUserAuthorization: false,
    })).rejects.toThrow('explicit user authorization');
  });

  it('stores tenant-scoped multi-network gateway configurations', async () => {
    const svc = await makeService();
    const config = {
      schemaVersion: 'veridex.gateway-config/v1' as const,
      appId: 'app_1', environment: 'test' as const, name: 'API gateway', state: 'draft' as const,
      targets: [{
        network: 'eip155:84532', facilitatorUrl: 'https://facilitator.example.com',
        payTo: `0x${'1'.repeat(40)}`, asset: `0x${'2'.repeat(40)}`, defaultPrice: '1000',
      }], schemes: ['exact' as const],
      upstreamUrl: 'http://localhost:3000', publicBaseUrl: 'http://localhost:3005',
      allowedMethods: ['GET' as const], updatedBy: 'token_admin',
    };
    const created = await svc.createGatewayConfig('tenant_1', config);
    expect((await svc.listGatewayConfigs('tenant_1', 'app_1', 'test'))[0]?.id).toBe(created.id);
    expect(await svc.listGatewayConfigs('tenant_2', 'app_1', 'test')).toHaveLength(0);
    const updated = await svc.updateGatewayConfig('tenant_1', created.id, 'app_1', 'test', { ...config, state: 'active' });
    expect(updated?.version).toBe(2);
    const specs = await svc.getGatewayDeploymentSpecs('tenant_1', created.id, 'app_1', 'test');
    expect(specs).toHaveLength(1);
    expect(specs?.[0]?.config.network).toBe('eip155:84532');
    expect(specs?.[0]?.image).toBe('ghcr.io/veridex/multichain-gateway:0.1.0');
    expect(specs?.[0]?.requiredSecretRefs).toEqual(['DATABASE_URL', 'GATEWAY_MANAGEMENT_TOKEN']);
    expect(JSON.stringify(specs)).not.toContain('postgresql://');
    await expect(svc.createGatewayConfig('tenant_1', { ...config, environment: 'live', upstreamUrl: 'http://internal' }))
      .rejects.toThrow('HTTPS');
  });

  it('stores scoped replay-resistant charge authorizations', async () => {
    const svc = await makeService();
    const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    const signerPublicKey = Buffer.from(await crypto.subtle.exportKey('spki', keys.publicKey)).toString('base64url');
    const unsigned: UnsignedChargeAuthorization = {
      schemaVersion: CHARGE_AUTHORIZATION_VERSION,
      authorizationId: 'auth_1', quoteId: 'quote_1', tenantId: 'tenant_1', appId: 'app_1',
      environment: 'test', chain: 'eip155:84532',
      chargeAsset: 'eip155:84532/slip44:60', maximumCharge: '100', nonce: 'nonce_1',
      expiresAt: new Date(Date.now() + 60_000).toISOString(), recurring: false,
      refundPolicyHash: `0x${'11'.repeat(32)}`, termsHash: `0x${'22'.repeat(32)}`,
      signatureAlgorithm: 'ed25519', signerPublicKey,
    };
    const authorization = { ...await createChargeAuthorization(unsigned, keys.privateKey), updatedBy: 'token_admin' };
    const created = await svc.createChargeAuthorization('tenant_1', authorization);
    expect(created.resourceType).toBe('charge_authorization');
    await expect(svc.createChargeAuthorization('tenant_1', {
      ...authorization, authorizationId: 'auth_tampered', nonce: 'nonce_tampered', maximumCharge: '101',
    })).rejects.toThrow('signature is invalid');
    const signAuthorization = async (authorizationId: string, nonce: string) => ({
      ...await createChargeAuthorization({ ...unsigned, authorizationId, nonce }, keys.privateKey),
      updatedBy: 'token_admin',
    });
    await expect(svc.createChargeAuthorization('tenant_1', await signAuthorization('auth_replay', 'nonce_1')))
      .rejects.toThrow('already used');
    const [concurrentAuthorization1, concurrentAuthorization2] = await Promise.all([
      signAuthorization('auth_create_1', 'nonce_create'),
      signAuthorization('auth_create_2', 'nonce_create'),
    ]);
    const concurrentCreate = await Promise.allSettled([
      svc.createChargeAuthorization('tenant_1', concurrentAuthorization1),
      svc.createChargeAuthorization('tenant_1', concurrentAuthorization2),
    ]);
    expect(concurrentCreate.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(concurrentCreate.filter((result) => result.status === 'rejected')).toHaveLength(1);
    const consume = (
      signedAuthorization: typeof authorization,
      executionId: string,
      maximumCharge = signedAuthorization.maximumCharge,
    ) => svc.consumeChargeAuthorization(
      'tenant_1', 'app_1', signedAuthorization.authorizationId, 'quote_1', signedAuthorization.termsHash, 'test',
      signedAuthorization.chain, signedAuthorization.chargeAsset, maximumCharge, signedAuthorization.payer,
      signedAuthorization.nonce, signedAuthorization.expiresAt, signedAuthorization.recurring,
      signedAuthorization.refundPolicyHash, signedAuthorization.signatureAlgorithm,
      signedAuthorization.signerPublicKey, signedAuthorization.signature, executionId, 'relayer',
    );
    await expect(consume(authorization, 'exec_wrong', '101')).rejects.toThrow('scope mismatch');
    const consumed = await consume(authorization, 'exec_1');
    expect(consumed.data.consumedAt).toBeDefined();
    await expect(consume(authorization, 'exec_2')).rejects.toThrow('already consumed');
    const retry = await consume(authorization, 'exec_1');
    expect(retry.version).toBe(consumed.version);

    const authorization2 = await signAuthorization('auth_2', 'nonce_2');
    await svc.createChargeAuthorization('tenant_1', authorization2);
    const concurrent = await Promise.allSettled([
      consume(authorization2, 'exec_3'),
      consume(authorization2, 'exec_4'),
    ]);
    expect(concurrent.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(concurrent.filter((result) => result.status === 'rejected')).toHaveLength(1);
  });

  it('stores payment resources, publishes Bazaar state, and projects events idempotently', async () => {
    const svc = await makeService();
    const resource = await svc.createPaymentResource('tenant_1', {
      schemaVersion: 'veridex.payment-resource/v1', appId: 'app_1', environment: 'test',
      gatewayId: 'gateway_1', name: 'Weather API', path: '/weather', methods: ['GET'],
      network: 'eip155:84532', scheme: 'exact', asset: `0x${'1'.repeat(40)}`,
      amount: '1000', payTo: `0x${'2'.repeat(40)}`, bazaarStatus: 'draft', updatedBy: 'token_admin',
    });
    const published = await svc.publishPaymentResource('tenant_1', 'app_1', resource.id, 'token_admin');
    expect(published?.data.bazaarStatus).toBe('published');
    expect(await svc.listPaymentResources('tenant_2', 'app_1')).toHaveLength(0);
    const event = {
      schemaVersion: 'veridex.payment-projection/v1' as const, eventId: 'evt_1', eventType: 'payment.settled',
      tenantId: 'tenant_1', appId: 'app_1', environment: 'test' as const, paymentId: 'pay_1',
      occurredAt: new Date().toISOString(), data: { amount: '1000' },
    };
    const first = await svc.ingestPaymentProjection('tenant_1', event);
    const duplicate = await svc.ingestPaymentProjection('tenant_1', event);
    expect(duplicate.id).toBe(first.id);
  });

  it('stores app-scoped team invitations and prevents duplicate pending access', async () => {
    const svc = await makeService();
    const invitation = await svc.createTeamInvitation(
      'tenant_1', 'app_1', ' Developer@Example.com ', 'developer', 'token_admin',
    );
    expect(invitation.data.email).toBe('developer@example.com');
    expect(invitation.data.status).toBe('pending');
    expect(await svc.listTeamInvitations('tenant_1', 'app_1')).toHaveLength(1);
    expect(await svc.listTeamInvitations('tenant_1', 'app_2')).toHaveLength(0);
    await expect(svc.createTeamInvitation(
      'tenant_1', 'app_1', 'developer@example.com', 'viewer', 'token_admin',
    )).rejects.toThrow('already exists');
    const revoked = await svc.revokeTeamInvitation(
      'tenant_1', 'app_1', invitation.id, 'token_admin',
    );
    expect(revoked?.data.status).toBe('revoked');
    expect(revoked?.status).toBe('archived');
  });

  // ── Tasks ──

  it('creates, reads, lists, and updates tasks', async () => {
    const svc = await makeService();

    const task = await svc.createTask({
      title: 'Onboard customer',
      description: 'Run KYC flow',
      status: 'pending',
      priority: 'high',
    });
    expect(task.id).toMatch(/^task_/);

    const fetched = await svc.getTask(task.id);
    expect(fetched?.title).toBe('Onboard customer');

    await svc.createTask({
      title: 'Notify ops',
      description: 'Send ops alert',
      status: 'running',
      priority: 'normal',
      assigneeId: 'agent_1',
    });

    expect(await svc.listTasks()).toHaveLength(2);
    expect(await svc.listTasks({ status: 'pending' })).toHaveLength(1);
    expect(await svc.listTasks({ priority: 'high' })).toHaveLength(1);
    expect(await svc.listTasks({ assigneeId: 'agent_1' })).toHaveLength(1);

    const updated = await svc.updateTask(task.id, { status: 'completed', completedAt: Date.now() });
    expect(updated?.status).toBe('completed');
    expect(updated?.completedAt).toBeDefined();

    expect(await svc.updateTask('nonexistent', { status: 'failed' })).toBeUndefined();
  });

  it('creates, reads, lists, updates, and deletes assignments', async () => {
    const svc = await makeService();

    const task = await svc.createTask({
      title: 'Review transaction',
      description: 'Review outbound transaction',
      status: 'pending',
      priority: 'high',
    });

    const assignment = await svc.createAssignment({
      taskId: task.id,
      assigneeId: 'agent_1',
      status: 'queued',
      workspaceId: 'ws_1',
    });
    expect(assignment.id).toMatch(/^asg_/);

    const fetched = await svc.getAssignment(assignment.id);
    expect(fetched?.assigneeId).toBe('agent_1');

    expect(await svc.listAssignments({ workspaceId: 'ws_1' })).toHaveLength(1);

    const updated = await svc.updateAssignment(assignment.id, {
      status: 'leased',
      leaseOwner: 'scheduler',
    });
    expect(updated?.status).toBe('leased');

    expect(await svc.deleteAssignment(assignment.id)).toBe(true);
  });

  // ── Deployment Revisions ──

  it('creates, reads, lists, and updates deployment revisions', async () => {
    const svc = await makeService();

    const rev = await svc.createDeploymentRevision({
      agentManifestId: 'am_abc',
      revision: 1,
      status: 'pending',
    });
    expect(rev.id).toMatch(/^dr_/);

    const fetched = await svc.getDeploymentRevision(rev.id);
    expect(fetched?.revision).toBe(1);

    await svc.createDeploymentRevision({
      agentManifestId: 'am_xyz',
      revision: 1,
      status: 'active',
    });

    expect(await svc.listDeploymentRevisions()).toHaveLength(2);
    expect(await svc.listDeploymentRevisions('am_abc')).toHaveLength(1);

    const updated = await svc.updateDeploymentRevision(rev.id, { status: 'active', activatedAt: Date.now() });
    expect(updated?.status).toBe('active');
    expect(updated?.activatedAt).toBeDefined();
  });

  // ── Incidents ──

  it('creates, reads, lists, and updates incidents', async () => {
    const svc = await makeService();

    const inc = await svc.createIncident({
      title: 'Agent timeout',
      description: 'Agent did not respond within SLA',
      severity: 'high',
      status: 'open',
      agentIds: ['agent_1'],
    });
    expect(inc.id).toMatch(/^inc_/);

    const fetched = await svc.getIncident(inc.id);
    expect(fetched?.title).toBe('Agent timeout');

    await svc.createIncident({
      title: 'Policy breach',
      description: 'Spend exceeded',
      severity: 'critical',
      status: 'investigating',
    });

    expect(await svc.listIncidents()).toHaveLength(2);
    expect(await svc.listIncidents({ severity: 'critical' })).toHaveLength(1);
    expect(await svc.listIncidents({ status: 'open' })).toHaveLength(1);

    const resolved = await svc.updateIncident(inc.id, { status: 'resolved', resolvedAt: Date.now() });
    expect(resolved?.status).toBe('resolved');
  });

  // ── Eval Suites & Runs ──

  it('creates, reads, lists eval suites and runs', async () => {
    const svc = await makeService();

    const suite = await svc.createEvalSuite({
      name: 'Summarisation eval',
      description: 'Test summarisation quality',
      scenarioCount: 3,
      scenarios: [{ input: 'hello' }, { input: 'foo' }, { input: 'bar' }],
    });
    expect(suite.id).toMatch(/^es_/);
    expect(await svc.listEvalSuites()).toHaveLength(1);

    const fetched = await svc.getEvalSuite(suite.id);
    expect(fetched?.name).toBe('Summarisation eval');

    const run = await svc.createEvalRun({
      suiteId: suite.id,
      status: 'running',
      passed: 0,
      failed: 0,
      errored: 0,
      total: 3,
    });
    expect(run.id).toMatch(/^er_/);

    expect(await svc.listEvalRuns()).toHaveLength(1);
    expect(await svc.listEvalRuns(suite.id)).toHaveLength(1);
    expect(await svc.listEvalRuns('nonexistent')).toHaveLength(0);

    const fetchedRun = await svc.getEvalRun(run.id);
    expect(fetchedRun?.suiteId).toBe(suite.id);

    const updated = await svc.updateEvalRun(run.id, {
      status: 'passed',
      passed: 3,
      total: 3,
      completedAt: Date.now(),
    });
    expect(updated?.status).toBe('passed');
    expect(updated?.passed).toBe(3);
  });

  // ── Policy Bindings ──

  it('creates, lists, and removes policy bindings', async () => {
    const svc = await makeService();

    const binding = await svc.createPolicyBinding({
      policyPackId: 'pp_1',
      targetType: 'agent',
      targetId: 'am_abc',
      priority: 10,
      active: true,
    });
    expect(binding.id).toMatch(/^pb_/);

    await svc.createPolicyBinding({
      policyPackId: 'pp_2',
      targetType: 'tenant',
      targetId: 'tenant_1',
      priority: 5,
      active: true,
    });

    expect(await svc.listPolicyBindings()).toHaveLength(2);
    expect(await svc.listPolicyBindings({ targetType: 'agent' })).toHaveLength(1);
    expect(await svc.listPolicyBindings({ targetId: 'tenant_1' })).toHaveLength(1);
    expect(await svc.listPolicyBindings({ policyPackId: 'pp_1' })).toHaveLength(1);

    expect(await svc.removePolicyBinding(binding.id)).toBe(true);
    expect(await svc.removePolicyBinding('nonexistent')).toBe(false);
    expect(await svc.listPolicyBindings()).toHaveLength(1);
  });

  it('creates and updates maintenance jobs', async () => {
    const svc = await makeService();

    const job = await svc.createMaintenanceJob({
      workspaceId: 'ws_1',
      jobType: 'drift_check',
      status: 'pending',
      trigger: 'manual',
    });
    expect(job.id).toMatch(/^job_/);

    expect(await svc.listMaintenanceJobs({ workspaceId: 'ws_1' })).toHaveLength(1);

    const updated = await svc.updateMaintenanceJob(job.id, {
      status: 'completed',
      completedAt: Date.now(),
    });
    expect(updated?.status).toBe('completed');
  });

  it('proposes, reviews, and applies governed resource mutations', async () => {
    const svc = await makeService();

    const resource = await svc.createWorkspaceResource({
      workspaceId: 'ws_1',
      resourceType: 'budget_envelope',
      name: 'Primary Budget',
      status: 'active',
      data: { amount: 1000 },
    });

    const proposal = await svc.proposeResourceMutation({
      workspaceId: 'ws_1',
      resourceType: 'budget_envelope',
      resourceId: resource.id,
      operation: 'update',
      expectedVersion: resource.version,
      payload: { amount: 5000 },
      reason: 'Increase workspace budget',
      proposedBy: 'agent_1',
    });
    expect(proposal.status).toBe('pending');

    const applied = await svc.decideResourceMutation(proposal.id, {
      decidedBy: 'ops_1',
      verdict: 'approved',
      reason: 'Approved budget increase',
    });
    expect(applied?.status).toBe('applied');

    const updatedResource = await svc.getWorkspaceResource(resource.id);
    expect(updatedResource?.data.amount).toBe(5000);
    expect(updatedResource?.reviewStatus).toBe('approved');
    expect(updatedResource?.resourceVersion?.proposalId).toBe(proposal.id);
  });

  // ── Persistence across restarts ──

  it('persists workforce OS resources across service restarts', async () => {
    const dataDir = await mkdtemp(path.join(os.tmpdir(), 'veridex-wos-persist-'));
    tempDirs.push(dataDir);

    const first = new ControlPlaneService({ dataDir, bootstrapTokens: ['root'] });

    const manifest = await first.registerAgentManifest({
      name: 'Persisted Agent',
      version: '2.0.0',
      status: 'active',
      capabilities: ['persist'],
    });
    const task = await first.createTask({
      title: 'Persisted Task',
      description: 'Should survive restart',
      status: 'pending',
      priority: 'normal',
    });
    const resource = await first.createWorkspaceResource({
      resourceType: 'config',
      name: 'Persisted Config',
      status: 'active',
      data: { key: 'val' },
    });

    // Restart
    const second = new ControlPlaneService({ dataDir, bootstrapTokens: ['root'] });

    expect((await second.getAgentManifest(manifest.id))?.name).toBe('Persisted Agent');
    expect((await second.getTask(task.id))?.title).toBe('Persisted Task');
    expect((await second.getWorkspaceResource(resource.id))?.name).toBe('Persisted Config');
  });
});

/**
 * @module ControlPlaneServer
 * @description
 * Remote HTTP service for the Veridex control plane.
 */

import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';

import type { ControlPlaneService, ServiceAuthResult } from './service';
import type { AuditExportOptions, ExportFormat } from './audit-export';
import type { ControlPlaneRole, TraceQuery } from './types';

type ControlPlaneVariables = {
  auth?: ServiceAuthResult;
};

type ControlPlaneApp = Hono<{ Variables: ControlPlaneVariables }>;

function jsonError(message: string, status = 400) {
  return Response.json({ error: message }, { status });
}

function getBearerToken(header?: string | null): string | undefined {
  if (!header) {
    return undefined;
  }
  const [scheme, token] = header.split(/\s+/, 2);
  if (!scheme || !token || scheme.toLowerCase() !== 'bearer') {
    return undefined;
  }
  return token;
}

function parseTraceQuery(query: URLSearchParams): TraceQuery {
  const parseNumber = (value: string | null): number | undefined => {
    if (!value) {
      return undefined;
    }
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  };

  return {
    runId: query.get('runId') ?? undefined,
    agentId: query.get('agentId') ?? undefined,
    tenantId: query.get('tenantId') ?? undefined,
    state: (query.get('state') as TraceQuery['state']) ?? undefined,
    startAfter: parseNumber(query.get('startAfter')),
    startBefore: parseNumber(query.get('startBefore')),
    limit: parseNumber(query.get('limit')),
    offset: parseNumber(query.get('offset')),
  };
}

function requireRole(app: ControlPlaneApp, roles: ControlPlaneRole[], path: string, methods: string[] = ['*']): void {
  app.use(path, async (c, next) => {
    if (methods[0] !== '*' && !methods.includes(c.req.method)) {
      return next();
    }

    const auth = c.get('auth');
    if (!auth) {
      return jsonError('Unauthorized', 401);
    }
    if (!roles.includes(auth.token.role)) {
      return jsonError('Forbidden', 403);
    }
    return next();
  });
}

export function createControlPlaneApp(service: ControlPlaneService): ControlPlaneApp {
  const app: ControlPlaneApp = new Hono();

  app.use('*', cors());

  app.get('/health', async (c) => c.json(await service.health()));
  app.get('/ready', async (c) => c.json(await service.health()));

  app.use('/v1/*', async (c, next) => {
    try {
      const tenantId = c.req.header(service.config.tenantHeader) ?? undefined;
      const token = getBearerToken(c.req.header('authorization'));
      const auth = await service.authenticate(token, tenantId);
      if (auth) {
        c.set('auth', auth);
      }
      return next();
    } catch (error) {
      return jsonError(error instanceof Error ? error.message : 'Unauthorized', 401);
    }
  });

  requireRole(app, ['admin'], '/v1/tokens');
  requireRole(app, ['admin'], '/v1/tenants', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/workspaces', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/policy-packs', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/workflows', ['POST']);
  requireRole(app, ['admin', 'operator', 'approver'], '/v1/approvals/*', ['POST']);
  requireRole(app, ['admin', 'operator'], '/v1/traces/ingest', ['POST']);
  requireRole(app, ['admin', 'operator'], '/v1/traces/purge/expired', ['POST']);
  requireRole(app, ['admin', 'operator', 'viewer'], '/v1/audit/*');
  requireRole(app, ['admin', 'operator'], '/v1/agent-manifests', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/workspace-resources', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/tasks', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/assignments', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/deployment-revisions', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/incidents', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/eval-suites', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/eval-runs', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/policy-bindings', ['POST', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/maintenance-jobs', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator', 'approver'], '/v1/resource-mutations', ['POST', 'PATCH']);

  app.get('/v1/tokens', async (c) => c.json(await service.listTokens()));
  app.post('/v1/tokens', async (c) => {
    const body = await c.req.json();
    const issued = await service.issueToken({
      name: body.name,
      role: body.role,
      tenantIds: body.tenantIds,
      metadata: body.metadata,
      token: body.token,
    });
    return c.json(issued, 201);
  });

  app.get('/v1/tenants', async (c) => {
    const status = c.req.query('status') as 'active' | 'suspended' | 'pending' | undefined;
    return c.json(await service.listTenants(status));
  });
  app.post('/v1/tenants', async (c) => {
    const body = await c.req.json();
    return c.json(await service.createTenant(body), 201);
  });
  app.get('/v1/tenants/:id', async (c) => {
    const tenant = await service.getTenant(c.req.param('id'));
    return tenant ? c.json(tenant) : jsonError('Tenant not found', 404);
  });
  app.patch('/v1/tenants/:id', async (c) => {
    const tenant = await service.updateTenantConfig(c.req.param('id'), await c.req.json());
    return tenant ? c.json(tenant) : jsonError('Tenant not found', 404);
  });
  app.post('/v1/tenants/:id/suspend', async (c) => {
    const tenant = await service.suspendTenant(c.req.param('id'));
    return tenant ? c.json(tenant) : jsonError('Tenant not found', 404);
  });
  app.post('/v1/tenants/:id/activate', async (c) => {
    const tenant = await service.activateTenant(c.req.param('id'));
    return tenant ? c.json(tenant) : jsonError('Tenant not found', 404);
  });
  app.delete('/v1/tenants/:id', async (c) => {
    const deleted = await service.deleteTenant(c.req.param('id'));
    return deleted ? c.json({ deleted: true }) : jsonError('Tenant not found', 404);
  });

  app.get('/v1/workspaces', async (c) => c.json(await service.listWorkspaces({
    tenantId: c.req.query('tenantId') ?? undefined,
    status: c.req.query('status') as 'active' | 'suspended' | 'archived' | undefined,
  })));
  app.post('/v1/workspaces', async (c) => c.json(await service.createWorkspace(await c.req.json()), 201));
  app.get('/v1/workspaces/:id', async (c) => {
    const workspace = await service.getWorkspace(c.req.param('id'));
    return workspace ? c.json(workspace) : jsonError('Workspace not found', 404);
  });
  app.patch('/v1/workspaces/:id', async (c) => {
    const workspace = await service.updateWorkspace(c.req.param('id'), await c.req.json());
    return workspace ? c.json(workspace) : jsonError('Workspace not found', 404);
  });
  app.delete('/v1/workspaces/:id', async (c) => {
    const deleted = await service.deleteWorkspace(c.req.param('id'));
    return deleted ? c.json({ deleted: true }) : jsonError('Workspace not found', 404);
  });

  app.get('/v1/policy-packs', async (c) => {
    const tags = c.req.query('tags')?.split(',').filter(Boolean);
    return c.json(await service.listPolicyPacks(tags));
  });
  app.post('/v1/policy-packs', async (c) => c.json(await service.createPolicyPack(await c.req.json()), 201));
  app.get('/v1/policy-packs/:id', async (c) => {
    const pack = await service.getPolicyPack(c.req.param('id'));
    return pack ? c.json(pack) : jsonError('Policy pack not found', 404);
  });
  app.patch('/v1/policy-packs/:id', async (c) => {
    const pack = await service.updatePolicyPack(c.req.param('id'), await c.req.json());
    return pack ? c.json(pack) : jsonError('Policy pack not found', 404);
  });
  app.delete('/v1/policy-packs/:id', async (c) => {
    const deleted = await service.deletePolicyPack(c.req.param('id'));
    return deleted ? c.json({ deleted: true }) : jsonError('Policy pack not found', 404);
  });

  app.get('/v1/workflows', async (c) => c.json(await service.listWorkflows()));
  app.post('/v1/workflows', async (c) => c.json(await service.registerWorkflow(await c.req.json()), 201));
  app.get('/v1/workflows/:id', async (c) => {
    const workflow = await service.getWorkflow(c.req.param('id'));
    return workflow ? c.json(workflow) : jsonError('Workflow not found', 404);
  });

  app.get('/v1/approvals/pending', async (c) => c.json(await service.listPendingApprovals()));
  app.get('/v1/approvals/resolved', async (c) => c.json(await service.listResolvedApprovals()));
  app.get('/v1/approvals/:id', async (c) => {
    const approval = await service.getApproval(c.req.param('id'));
    return approval ? c.json(approval) : jsonError('Approval not found', 404);
  });
  app.post('/v1/approvals/start', async (c) => c.json(await service.startApproval(await c.req.json()), 201));
  app.post('/v1/approvals/:id/votes', async (c) => {
    const body = await c.req.json();
    return c.json(await service.voteApproval({
      approvalId: c.req.param('id'),
      approver: body.approver,
      approved: body.approved,
      reason: body.reason,
    }));
  });
  app.post('/v1/approvals/process-timeouts', async (c) => c.json(await service.processApprovalTimeouts()));

  // ── Protected-intent (encrypted envelope) ingress ──
  app.get('/v1/intents/protected/keys', async (c) =>
    c.json({ keys: service.listProtectedIntentKeys() }),
  );
  app.post('/v1/intents/protected/preflight', async (c) => {
    if (service.listProtectedIntentKeys().length === 0) {
      return jsonError('Protected-intent feature is not configured', 501);
    }
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return jsonError('Invalid JSON body', 400);
    }
    if (!body || typeof body !== 'object') {
      return jsonError('Envelope payload required', 400);
    }
    try {
      const result = await service.preflightProtectedIntent(body as Parameters<typeof service.preflightProtectedIntent>[0]);
      return c.json(result, 200);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to preflight envelope';
      const code = (err as { code?: string }).code;
      const status =
        code === 'replay-detected' || code === 'window-expired'
          ? 409
          : code === 'unknown-key' || code === 'aead-failure' || code === 'hash-mismatch'
            ? 400
            : code === 'malformed-envelope' || code === 'version-mismatch'
              ? 400
              : 400;
      return Response.json({ error: message, code }, { status });
    }
  });
  app.post('/v1/intents/protected', async (c) => {
    if (service.listProtectedIntentKeys().length === 0) {
      return jsonError('Protected-intent feature is not configured', 501);
    }
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return jsonError('Invalid JSON body', 400);
    }
    if (!body || typeof body !== 'object') {
      return jsonError('Envelope payload required', 400);
    }
    try {
      const result = await service.submitProtectedIntent(body as Parameters<typeof service.submitProtectedIntent>[0]);
      return c.json(result, 202);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to decrypt envelope';
      const code = (err as { code?: string }).code;
      const status =
        code === 'replay-detected' || code === 'window-expired'
          ? 409
          : code === 'unknown-key' || code === 'aead-failure' || code === 'hash-mismatch'
            ? 400
            : code === 'malformed-envelope' || code === 'version-mismatch'
              ? 400
              : 400;
      return Response.json({ error: message, code }, { status });
    }
  });

  app.post('/v1/traces/ingest', async (c) => c.json(await service.ingestTrace(await c.req.json()), 201));
  app.get('/v1/traces', async (c) => c.json(await service.queryTraces(parseTraceQuery(new URL(c.req.url).searchParams))));
  app.get('/v1/traces/:id', async (c) => {
    const trace = await service.getTrace(c.req.param('id'));
    return trace ? c.json(trace) : jsonError('Trace not found', 404);
  });
  app.delete('/v1/traces/:id', async (c) => {
    const deleted = await service.deleteTrace(c.req.param('id'));
    return deleted ? c.json({ deleted: true }) : jsonError('Trace not found', 404);
  });
  app.get('/v1/traces/:id/verify', async (c) => c.json({ valid: await service.verifyTrace(c.req.param('id')) }));
  app.post('/v1/traces/purge/expired', async (c) => c.json({ purged: await service.purgeExpiredTraces() }));

  app.post('/v1/audit/export', async (c) => {
    const body = await c.req.json();
    const traces = Array.isArray(body.traces)
      ? body.traces
      : await service.queryTraces(body.query ?? {});
    const options: AuditExportOptions = {
      format: (body.format ?? 'json') as ExportFormat,
      includeEvents: body.includeEvents ?? false,
      includeHashes: body.includeHashes ?? true,
      csvFields: body.csvFields,
    };
    return c.json(await service.exportAudit(traces, options));
  });
  app.post('/v1/audit/evidence/:traceId', async (c) => {
    const trace = await service.getTrace(c.req.param('traceId'));
    if (!trace) {
      return jsonError('Trace not found', 404);
    }
    const body = await c.req.json();
    return c.json(await service.generateEvidence(
      trace,
      body.policyDecisions ?? [],
      body.approvalDecisions ?? [],
    ));
  });

  app.get('/v1/agent-manifests', async (c) => c.json(await service.listAgentManifests(
    c.req.query('status') as 'active' | 'draining' | 'disabled' | 'archived' | undefined,
  )));
  app.post('/v1/agent-manifests', async (c) => c.json(await service.registerAgentManifest(await c.req.json()), 201));
  app.get('/v1/agent-manifests/:id', async (c) => {
    const manifest = await service.getAgentManifest(c.req.param('id'));
    return manifest ? c.json(manifest) : jsonError('Agent manifest not found', 404);
  });
  app.patch('/v1/agent-manifests/:id', async (c) => {
    const manifest = await service.updateAgentManifest(c.req.param('id'), await c.req.json());
    return manifest ? c.json(manifest) : jsonError('Agent manifest not found', 404);
  });
  app.delete('/v1/agent-manifests/:id', async (c) => {
    const deleted = await service.removeAgentManifest(c.req.param('id'));
    return deleted ? c.json({ deleted: true }) : jsonError('Agent manifest not found', 404);
  });

  /**
   * GET /v1/agent-manifests/lookup?name=X or ?definitionId=X
   * Find manifests by name or original AgentDefinition ID (stored in metadata).
   */
  app.get('/v1/agent-manifests/lookup', async (c) => {
    const name = c.req.query('name');
    const definitionId = c.req.query('definitionId');
    const all = await service.listAgentManifests();
    const matches = all.filter((m) => {
      if (name && m.name === name) return true;
      if (definitionId && m.metadata?.sdkDefinitionId === definitionId) return true;
      return false;
    });
    return c.json({ manifests: matches, count: matches.length });
  });

  app.get('/v1/workspace-resources', async (c) => c.json(await service.listWorkspaceResources({
    resourceType: c.req.query('resourceType') ?? undefined,
    status: c.req.query('status') as 'active' | 'archived' | 'deleted' | undefined,
    tags: c.req.query('tags')?.split(',').filter(Boolean),
  })));
  app.post('/v1/workspace-resources', async (c) => c.json(await service.createWorkspaceResource(await c.req.json()), 201));
  app.get('/v1/workspace-resources/:id', async (c) => {
    const resource = await service.getWorkspaceResource(c.req.param('id'));
    return resource ? c.json(resource) : jsonError('Workspace resource not found', 404);
  });
  app.patch('/v1/workspace-resources/:id', async (c) => {
    const resource = await service.updateWorkspaceResource(c.req.param('id'), await c.req.json());
    return resource ? c.json(resource) : jsonError('Workspace resource not found', 404);
  });
  app.delete('/v1/workspace-resources/:id', async (c) => {
    const deleted = await service.deleteWorkspaceResource(c.req.param('id'));
    return deleted ? c.json({ deleted: true }) : jsonError('Workspace resource not found', 404);
  });

  app.get('/v1/tasks', async (c) => c.json(await service.listTasks({
    status: c.req.query('status') as any,
    priority: c.req.query('priority') as any,
    assigneeId: c.req.query('assigneeId') ?? undefined,
  })));
  app.post('/v1/tasks', async (c) => c.json(await service.createTask(await c.req.json()), 201));
  app.get('/v1/tasks/:id', async (c) => {
    const task = await service.getTask(c.req.param('id'));
    return task ? c.json(task) : jsonError('Task not found', 404);
  });
  app.patch('/v1/tasks/:id', async (c) => {
    const task = await service.updateTask(c.req.param('id'), await c.req.json());
    return task ? c.json(task) : jsonError('Task not found', 404);
  });

  app.get('/v1/assignments', async (c) => c.json(await service.listAssignments({
    taskId: c.req.query('taskId') ?? undefined,
    assigneeId: c.req.query('assigneeId') ?? undefined,
    status: c.req.query('status') as any,
    workspaceId: c.req.query('workspaceId') ?? undefined,
  })));
  app.post('/v1/assignments', async (c) => c.json(await service.createAssignment(await c.req.json()), 201));
  app.get('/v1/assignments/:id', async (c) => {
    const assignment = await service.getAssignment(c.req.param('id'));
    return assignment ? c.json(assignment) : jsonError('Assignment not found', 404);
  });
  app.patch('/v1/assignments/:id', async (c) => {
    const assignment = await service.updateAssignment(c.req.param('id'), await c.req.json());
    return assignment ? c.json(assignment) : jsonError('Assignment not found', 404);
  });
  app.delete('/v1/assignments/:id', async (c) => {
    const deleted = await service.deleteAssignment(c.req.param('id'));
    return deleted ? c.json({ deleted: true }) : jsonError('Assignment not found', 404);
  });

  app.get('/v1/deployment-revisions', async (c) => c.json(await service.listDeploymentRevisions(
    c.req.query('agentManifestId') ?? undefined,
  )));
  app.post('/v1/deployment-revisions', async (c) => c.json(await service.createDeploymentRevision(await c.req.json()), 201));
  app.get('/v1/deployment-revisions/:id', async (c) => {
    const revision = await service.getDeploymentRevision(c.req.param('id'));
    return revision ? c.json(revision) : jsonError('Deployment revision not found', 404);
  });
  app.patch('/v1/deployment-revisions/:id', async (c) => {
    const revision = await service.updateDeploymentRevision(c.req.param('id'), await c.req.json());
    return revision ? c.json(revision) : jsonError('Deployment revision not found', 404);
  });

  app.get('/v1/incidents', async (c) => c.json(await service.listIncidents({
    severity: c.req.query('severity') as any,
    status: c.req.query('status') as any,
  })));
  app.post('/v1/incidents', async (c) => c.json(await service.createIncident(await c.req.json()), 201));
  app.get('/v1/incidents/:id', async (c) => {
    const incident = await service.getIncident(c.req.param('id'));
    return incident ? c.json(incident) : jsonError('Incident not found', 404);
  });
  app.patch('/v1/incidents/:id', async (c) => {
    const incident = await service.updateIncident(c.req.param('id'), await c.req.json());
    return incident ? c.json(incident) : jsonError('Incident not found', 404);
  });

  app.get('/v1/eval-suites', async (c) => c.json(await service.listEvalSuites()));
  app.post('/v1/eval-suites', async (c) => c.json(await service.createEvalSuite(await c.req.json()), 201));
  app.get('/v1/eval-suites/:id', async (c) => {
    const suite = await service.getEvalSuite(c.req.param('id'));
    return suite ? c.json(suite) : jsonError('Eval suite not found', 404);
  });

  app.get('/v1/eval-runs', async (c) => c.json(await service.listEvalRuns(c.req.query('suiteId') ?? undefined)));
  app.post('/v1/eval-runs', async (c) => c.json(await service.createEvalRun(await c.req.json()), 201));
  app.get('/v1/eval-runs/:id', async (c) => {
    const run = await service.getEvalRun(c.req.param('id'));
    return run ? c.json(run) : jsonError('Eval run not found', 404);
  });
  app.patch('/v1/eval-runs/:id', async (c) => {
    const run = await service.updateEvalRun(c.req.param('id'), await c.req.json());
    return run ? c.json(run) : jsonError('Eval run not found', 404);
  });

  app.get('/v1/policy-bindings', async (c) => c.json(await service.listPolicyBindings({
    targetType: c.req.query('targetType') as any,
    targetId: c.req.query('targetId') ?? undefined,
    policyPackId: c.req.query('policyPackId') ?? undefined,
  })));
  app.post('/v1/policy-bindings', async (c) => c.json(await service.createPolicyBinding(await c.req.json()), 201));
  app.delete('/v1/policy-bindings/:id', async (c) => {
    const deleted = await service.removePolicyBinding(c.req.param('id'));
    return deleted ? c.json({ deleted: true }) : jsonError('Policy binding not found', 404);
  });

  app.get('/v1/maintenance-jobs', async (c) => c.json(await service.listMaintenanceJobs({
    workspaceId: c.req.query('workspaceId') ?? undefined,
    status: c.req.query('status') as any,
    jobType: c.req.query('jobType') as any,
  })));
  app.post('/v1/maintenance-jobs', async (c) => c.json(await service.createMaintenanceJob(await c.req.json()), 201));
  app.get('/v1/maintenance-jobs/:id', async (c) => {
    const job = await service.getMaintenanceJob(c.req.param('id'));
    return job ? c.json(job) : jsonError('Maintenance job not found', 404);
  });
  app.patch('/v1/maintenance-jobs/:id', async (c) => {
    const job = await service.updateMaintenanceJob(c.req.param('id'), await c.req.json());
    return job ? c.json(job) : jsonError('Maintenance job not found', 404);
  });
  app.delete('/v1/maintenance-jobs/:id', async (c) => {
    const deleted = await service.deleteMaintenanceJob(c.req.param('id'));
    return deleted ? c.json({ deleted: true }) : jsonError('Maintenance job not found', 404);
  });

  app.get('/v1/resource-mutations', async (c) => c.json(await service.listResourceMutationProposals({
    workspaceId: c.req.query('workspaceId') ?? undefined,
    resourceType: c.req.query('resourceType') ?? undefined,
    status: c.req.query('status') as any,
  })));
  app.post('/v1/resource-mutations', async (c) => c.json(await service.proposeResourceMutation(await c.req.json()), 201));
  app.get('/v1/resource-mutations/:id', async (c) => {
    const proposal = await service.getResourceMutationProposal(c.req.param('id'));
    return proposal ? c.json(proposal) : jsonError('Resource mutation proposal not found', 404);
  });
  app.post('/v1/resource-mutations/:id/decisions', async (c) => {
    const proposal = await service.decideResourceMutation(c.req.param('id'), await c.req.json());
    return proposal ? c.json(proposal) : jsonError('Resource mutation proposal not found', 404);
  });

  app.onError((error) => jsonError(error instanceof Error ? error.message : 'Internal server error', 500));

  return app;
}

export function startControlPlaneServer(service: ControlPlaneService) {
  const app = createControlPlaneApp(service);

  const server = serve({
    fetch: app.fetch,
    port: service.config.port,
    hostname: service.config.host,
  });

  const approvalTimer = setInterval(() => {
    void service.processApprovalTimeouts().catch(() => undefined);
  }, service.config.approvalSweepIntervalMs);

  const retentionTimer = setInterval(() => {
    void service.purgeExpiredTraces().catch(() => undefined);
  }, service.config.tracePurgeIntervalMs);

  return {
    app,
    server,
    close: async () => {
      clearInterval(approvalTimer);
      clearInterval(retentionTimer);
      await new Promise<void>((resolve, reject) => {
        server.close((error?: Error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
      await service.close();
    },
  };
}

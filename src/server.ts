/**
 * @module ControlPlaneServer
 * @description
 * Remote HTTP service for the Veridex control plane.
 */

import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';

import { ControlPlaneService, type ServiceAuthResult } from './service';
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
  requireRole(app, ['admin', 'operator'], '/v1/policy-packs', ['POST', 'PATCH', 'DELETE']);
  requireRole(app, ['admin', 'operator'], '/v1/workflows', ['POST']);
  requireRole(app, ['admin', 'operator', 'approver'], '/v1/approvals/*', ['POST']);
  requireRole(app, ['admin', 'operator'], '/v1/traces/ingest', ['POST']);
  requireRole(app, ['admin', 'operator'], '/v1/traces/purge/expired', ['POST']);
  requireRole(app, ['admin', 'operator', 'viewer'], '/v1/audit/*');

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

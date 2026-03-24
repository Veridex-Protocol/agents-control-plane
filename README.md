# @veridex/agents-control-plane

Persistent control-plane service and client for operating Veridex agents in multi-tenant, policy-bound, approval-heavy, and audit-sensitive environments.

## Status

`@veridex/agents-control-plane` now includes a real service, a remote client, file-backed and Postgres-backed persistence, and deployment surfaces for managed environments. It is no longer just an SDK sketch, but it is still early enough that operational feedback and contribution are valuable.

## What This Package Does

Use this package when you need:

- tenant isolation
- policy pack management
- approval workflows and escalation
- trace ingestion and retention
- evidence bundle and audit export
- remote authenticated APIs
- deployable control-plane infrastructure
- shared Postgres-backed persistence for multiple service instances

## Installation

```bash
npm install @veridex/agents-control-plane @veridex/agents
```

## Core Exports

### Service and API

- `ControlPlaneService`
- `createControlPlaneApp`
- `startControlPlaneServer`
- `RemoteControlPlaneClient`

### Governance and operations

- `PolicyPackManager`
- `ApprovalWorkflowEngine`
- `TenantManager`
- `TraceStore`
- `exportTraces`
- `generateEvidenceBundle`

### Persistence

- `JSONFileMetadataStore`
- `FileTraceStoreBackend`
- `PostgresMetadataStore`
- `PostgresTraceStoreBackend`

## Local Service Example

```ts
import { ControlPlaneService } from '@veridex/agents-control-plane';

const service = new ControlPlaneService({
  dataDir: './data/control-plane',
  bootstrapTokens: ['root-secret'],
  traceRetentionDays: 90,
});

const tenant = await service.createTenant({ name: 'Acme' });

await service.registerWorkflow({
  id: 'wf_ops',
  name: 'Operations approval',
  description: 'Default approval path for risky actions',
  escalationChain: [
    {
      name: 'Ops',
      approvers: ['ops'],
      timeoutSeconds: 300,
      minApprovals: 1,
    },
  ],
  defaultMode: 'block',
});

const approval = await service.startApproval({
  workflowId: 'wf_ops',
  runId: 'run_123',
  agentId: 'treasury-agent',
  proposal: 'Transfer funds to vendor',
  riskScore: 0.82,
});

await service.ingestTrace({
  runId: 'run_123',
  agentId: 'treasury-agent',
  tenantId: tenant.id,
  startedAt: Date.now() - 1000,
  completedAt: Date.now(),
  state: 'completed',
  turnCount: 3,
  totalTokens: 180,
  events: [{ type: 'run_started' }, { type: 'run_completed' }],
});

console.log(approval.id);
```

## Remote Service and Client Example

```ts
import {
  ControlPlaneService,
  createControlPlaneApp,
  RemoteControlPlaneClient,
} from '@veridex/agents-control-plane';

const service = new ControlPlaneService({
  dataDir: './data/control-plane',
  bootstrapTokens: ['admin-secret'],
});

const app = createControlPlaneApp(service);

const client = new RemoteControlPlaneClient({
  mode: 'managed',
  endpoint: 'http://control-plane.local',
  authToken: 'admin-secret',
  fetch: async (input, init) => app.request(input, init),
});

const health = await client.health();
const tenant = await client.createTenant({ name: 'Remote Tenant' });

console.log(health.ready, tenant.id);
```

## Persistence Modes

### File-backed mode

Good for:

- local development
- single-node deployment
- testing

This mode uses:

- `JSONFileMetadataStore`
- `FileTraceStoreBackend`

### Shared Postgres mode

Good for:

- managed environments
- multiple service instances
- enterprise control-plane deployments

This mode uses:

- `PostgresMetadataStore`
- `PostgresTraceStoreBackend`

The Postgres path includes optimistic concurrency on metadata revisions so multiple service instances can coordinate against the same backing store.

## CLI and Environment Variables

The package ships a CLI entrypoint:

```bash
veridex-control-plane
```

Important environment variables:

| Variable | Purpose |
|---|---|
| `VERIDEX_CONTROL_PLANE_STORAGE_BACKEND` | `file` or `postgres` |
| `VERIDEX_CONTROL_PLANE_POSTGRES_URL` | Shared Postgres connection string |
| `VERIDEX_CONTROL_PLANE_POSTGRES_SSL` | Enable SSL for Postgres connections |
| `VERIDEX_CONTROL_PLANE_POSTGRES_METADATA_TABLE` | Optional metadata table override |
| `VERIDEX_CONTROL_PLANE_POSTGRES_TRACES_TABLE` | Optional traces table override |
| `VERIDEX_CONTROL_PLANE_DATA_DIR` | File-backed storage directory |
| `VERIDEX_CONTROL_PLANE_HOST` | Service bind host |
| `VERIDEX_CONTROL_PLANE_PORT` | Service bind port |
| `VERIDEX_CONTROL_PLANE_BOOTSTRAP_TOKENS` | Initial auth tokens |
| `VERIDEX_CONTROL_PLANE_TRACE_RETENTION_DAYS` | Trace retention window |

## How It Fits With the Runtime

Use the control plane when you want to move from:

- single-runtime local development
- to shared approvals and trace retention
- to a deployable, authenticated governance layer around many agents

Typical flow:

1. `@veridex/agents` executes runs and emits traces
2. traces and approval events are pushed into the control plane
3. operators or automated systems interact through the remote client or API
4. evidence bundles and audit exports become available for review or compliance

## Deployment Surfaces

The repo includes deployment support for:

- Docker
- Docker Compose
- Kubernetes manifests
- Render
- Koyeb

These live under `deploy/agents-control-plane/`.

## Known Rough Edges

- This package is still young enough that operational ergonomics will keep improving.
- You should still validate your own auth, retention, and escalation requirements before production rollout.
- Postgres is now supported for shared persistence, but production operators should still tune indexes, backups, monitoring, and secret management to their environment.

Contributions are especially welcome around ops guides, managed deployment examples, and tighter runtime-to-control-plane integration examples.

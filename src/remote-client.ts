/**
 * @module RemoteControlPlaneClient
 * @description
 * HTTP client for the remote Veridex control-plane service.
 */

import type {
  ActiveApproval,
} from './approval-workflows';
import type {
  CreatePolicyPackOptions,
} from './policy-packs';
import type {
  CreateTenantOptions,
} from './tenant-manager';
import type {
  IngestOptions,
} from './trace-store';
import type {
  ApprovalWorkflow,
  ControlPlaneAuthToken,
  ControlPlaneConfig,
  PolicyPack,
  Tenant,
  TenantConfig,
  TraceQuery,
  TraceRecord,
} from './types';
import type { AuditExportOptions, AuditExportResult } from './audit-export';

type FetchLike = typeof fetch;

export interface RemoteControlPlaneClientConfig extends ControlPlaneConfig {
  endpoint: string;
  authToken: string;
  fetch?: FetchLike;
  headers?: Record<string, string>;
}

function buildQuery(query: Record<string, unknown>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') {
      continue;
    }
    params.set(key, String(value));
  }
  const encoded = params.toString();
  return encoded ? `?${encoded}` : '';
}

export class RemoteControlPlaneClient {
  private readonly config: RemoteControlPlaneClientConfig;
  private readonly fetchImpl: FetchLike;

  constructor(config: RemoteControlPlaneClientConfig) {
    this.config = config;
    this.fetchImpl = config.fetch ?? globalThis.fetch.bind(globalThis);
  }

  private headers(extra?: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      Authorization: `Bearer ${this.config.authToken}`,
      ...(this.config.headers ?? {}),
      ...(extra ?? {}),
    };
    if (this.config.tenantId) {
      headers['x-veridex-tenant-id'] = this.config.tenantId;
    }
    return headers;
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await this.fetchImpl(new URL(path, this.config.endpoint).toString(), {
      ...init,
      headers: this.headers(init?.headers as Record<string, string> | undefined),
    });

    if (!response.ok) {
      let message = `Remote control plane request failed (${response.status})`;
      try {
        const body = await response.json() as { error?: string };
        if (body.error) {
          message = body.error;
        }
      } catch {
        // Ignore invalid JSON error bodies.
      }
      throw new Error(message);
    }

    if (response.status === 204) {
      return undefined as T;
    }

    return response.json() as Promise<T>;
  }

  health() {
    return this.request<{
      ready: boolean;
      tenantCount: number;
      policyPackCount: number;
      workflowCount: number;
      pendingApprovalCount: number;
      traceCount: number;
      traceDiskUsageBytes: number;
    }>('/health');
  }

  listTokens() {
    return this.request<ControlPlaneAuthToken[]>('/v1/tokens');
  }

  issueToken(input: {
    name: string;
    role?: string;
    tenantIds?: string[];
    metadata?: Record<string, unknown>;
    token?: string;
  }) {
    return this.request<{ token: string; record: ControlPlaneAuthToken }>('/v1/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    });
  }

  listTenants(status?: Tenant['status']) {
    return this.request<Tenant[]>(`/v1/tenants${buildQuery({ status })}`);
  }

  createTenant(options: CreateTenantOptions) {
    return this.request<Tenant>('/v1/tenants', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options),
    });
  }

  getTenant(id: string) {
    return this.request<Tenant>(`/v1/tenants/${id}`);
  }

  updateTenantConfig(id: string, config: Partial<TenantConfig>) {
    return this.request<Tenant>(`/v1/tenants/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
  }

  suspendTenant(id: string) {
    return this.request<Tenant>(`/v1/tenants/${id}/suspend`, { method: 'POST' });
  }

  activateTenant(id: string) {
    return this.request<Tenant>(`/v1/tenants/${id}/activate`, { method: 'POST' });
  }

  deleteTenant(id: string) {
    return this.request<{ deleted: boolean }>(`/v1/tenants/${id}`, { method: 'DELETE' });
  }

  listPolicyPacks(tags?: string[]) {
    return this.request<PolicyPack[]>(`/v1/policy-packs${buildQuery({ tags: tags?.join(',') })}`);
  }

  createPolicyPack(options: CreatePolicyPackOptions) {
    return this.request<PolicyPack>('/v1/policy-packs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options),
    });
  }

  getPolicyPack(id: string) {
    return this.request<PolicyPack>(`/v1/policy-packs/${id}`);
  }

  updatePolicyPack(
    id: string,
    updates: Partial<Pick<PolicyPack, 'name' | 'description' | 'version' | 'rules' | 'tags'>>,
  ) {
    return this.request<PolicyPack>(`/v1/policy-packs/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
  }

  deletePolicyPack(id: string) {
    return this.request<{ deleted: boolean }>(`/v1/policy-packs/${id}`, { method: 'DELETE' });
  }

  listWorkflows() {
    return this.request<ApprovalWorkflow[]>('/v1/workflows');
  }

  registerWorkflow(workflow: ApprovalWorkflow) {
    return this.request<ApprovalWorkflow>('/v1/workflows', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(workflow),
    });
  }

  getWorkflow(id: string) {
    return this.request<ApprovalWorkflow>(`/v1/workflows/${id}`);
  }

  listPendingApprovals() {
    return this.request<ActiveApproval[]>('/v1/approvals/pending');
  }

  listResolvedApprovals() {
    return this.request<ActiveApproval[]>('/v1/approvals/resolved');
  }

  getApproval(id: string) {
    return this.request<ActiveApproval>(`/v1/approvals/${id}`);
  }

  startApproval(input: {
    workflowId: string;
    runId: string;
    agentId: string;
    proposal: string;
    riskScore: number;
  }) {
    return this.request<ActiveApproval>('/v1/approvals/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    });
  }

  voteApproval(id: string, input: { approver: string; approved: boolean; reason?: string }) {
    return this.request<ActiveApproval>(`/v1/approvals/${id}/votes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    });
  }

  processApprovalTimeouts() {
    return this.request<ActiveApproval[]>('/v1/approvals/process-timeouts', { method: 'POST' });
  }

  ingestTrace(options: IngestOptions) {
    return this.request<TraceRecord>('/v1/traces/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options),
    });
  }

  queryTraces(query: TraceQuery) {
    return this.request<TraceRecord[]>(`/v1/traces${buildQuery(query as Record<string, unknown>)}`);
  }

  getTrace(id: string) {
    return this.request<TraceRecord>(`/v1/traces/${id}`);
  }

  deleteTrace(id: string) {
    return this.request<{ deleted: boolean }>(`/v1/traces/${id}`, { method: 'DELETE' });
  }

  verifyTrace(id: string) {
    return this.request<{ valid: boolean }>(`/v1/traces/${id}/verify`);
  }

  purgeExpiredTraces() {
    return this.request<{ purged: number }>('/v1/traces/purge/expired', { method: 'POST' });
  }

  exportAudit(input: { traces?: TraceRecord[]; query?: TraceQuery } & AuditExportOptions) {
    return this.request<AuditExportResult>('/v1/audit/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    });
  }

  generateEvidence(traceId: string, input: { policyDecisions?: unknown[]; approvalDecisions?: unknown[] }) {
    return this.request<unknown>(`/v1/audit/evidence/${traceId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    });
  }
}

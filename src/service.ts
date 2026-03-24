/**
 * @module ControlPlaneService
 * @description
 * Persistent remote control-plane service that composes tenancy,
 * policy packs, approval workflows, trace retention, and audit export.
 */

import { randomBytes } from 'node:crypto';

import { ApprovalWorkflowEngine, type ActiveApproval, type ApprovalVote } from './approval-workflows';
import {
  exportTraces,
  generateEvidenceBundle,
  type AuditExportOptions,
  type AuditExportResult,
} from './audit-export';
import { PolicyPackManager, type CreatePolicyPackOptions } from './policy-packs';
import {
  type ControlPlaneMetadataStore,
  JSONFileMetadataStore,
  FileTraceStoreBackend,
  type TraceStoreMetricsBackend,
  createAuthTokenRecord,
  sha256Hex,
  MetadataConflictError,
  type ControlPlaneMetadataSnapshot,
} from './persistence';
import { TenantManager, type CreateTenantOptions } from './tenant-manager';
import { TraceStore, type IngestOptions } from './trace-store';
import type {
  ApprovalWorkflow,
  ControlPlaneAuthToken,
  ControlPlaneRole,
  ControlPlaneServiceConfig,
  PolicyPack,
  Tenant,
  TenantConfig,
  TraceQuery,
  TraceRecord,
} from './types';

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

type ResolvedControlPlaneServiceConfig = {
  storageBackend: 'file' | 'postgres';
  host: string;
  port: number;
  dataDir: string;
  authRequired: boolean;
  tenantHeader: string;
  bootstrapTokens: ControlPlaneServiceConfig['bootstrapTokens'];
  approvalSweepIntervalMs: number;
  tracePurgeIntervalMs: number;
  traceRetentionDays: number;
  postgres?: NonNullable<ControlPlaneServiceConfig['postgres']>;
};

function defaultConfig(config: ControlPlaneServiceConfig): ResolvedControlPlaneServiceConfig {
  return {
    storageBackend: config.storageBackend ?? 'file',
    host: config.host ?? '0.0.0.0',
    port: config.port ?? 4010,
    dataDir: config.dataDir ?? './data/control-plane',
    authRequired: config.authRequired ?? true,
    tenantHeader: config.tenantHeader ?? 'x-veridex-tenant-id',
    bootstrapTokens: config.bootstrapTokens,
    approvalSweepIntervalMs: config.approvalSweepIntervalMs ?? 30_000,
    tracePurgeIntervalMs: config.tracePurgeIntervalMs ?? 15 * 60_000,
    traceRetentionDays: config.traceRetentionDays ?? 90,
    postgres: config.postgres,
  };
}

export interface ApprovalStartOptions {
  workflowId: string;
  runId: string;
  agentId: string;
  proposal: string;
  riskScore: number;
}

export interface ApprovalVoteOptions {
  approvalId: string;
  approver: string;
  approved: boolean;
  reason?: string;
}

export interface TokenIssueOptions {
  name: string;
  role?: ControlPlaneRole;
  tenantIds?: string[];
  metadata?: Record<string, unknown>;
  token?: string;
}

export interface ServiceAuthResult {
  token: ControlPlaneAuthToken;
  tenantId?: string;
}

export interface ControlPlaneServicePersistence {
  metadataStore?: ControlPlaneMetadataStore;
  traceBackend?: TraceStoreMetricsBackend;
}

export class ControlPlaneService {
  readonly config: ReturnType<typeof defaultConfig>;
  readonly traces: TraceStore;
  readonly policyPacks: PolicyPackManager;
  readonly approvalWorkflows: ApprovalWorkflowEngine;
  readonly tenants: TenantManager;

  private readonly metadata: ControlPlaneMetadataStore;
  private readonly traceBackend: TraceStoreMetricsBackend;
  private readonly ready: Promise<void>;
  private mutationChain = Promise.resolve<void>(undefined);
  private metadataRevision = 0;

  constructor(config: ControlPlaneServiceConfig, persistence?: ControlPlaneServicePersistence) {
    this.config = defaultConfig(config);
    this.metadata = persistence?.metadataStore ?? new JSONFileMetadataStore(this.config.dataDir);
    this.traceBackend = persistence?.traceBackend ?? new FileTraceStoreBackend(this.config.dataDir);
    this.traces = new TraceStore(this.traceBackend, this.config.traceRetentionDays);
    this.policyPacks = new PolicyPackManager();
    this.approvalWorkflows = new ApprovalWorkflowEngine();
    this.tenants = new TenantManager();
    this.ready = this.initialize();
  }

  private async initialize(): Promise<void> {
    const snapshot = await this.metadata.load();
    this.hydrate(snapshot);
    const changed = await this.ensureBootstrapTokens(snapshot);
    if (changed) {
      await this.persistMetadata();
    }
  }

  private hydrate(snapshot: ControlPlaneMetadataSnapshot): void {
    this.metadataRevision = snapshot.revision ?? 0;
    this.policyPacks.load(snapshot.policyPacks);
    this.approvalWorkflows.loadWorkflows(snapshot.approvalWorkflows);
    this.approvalWorkflows.loadApprovals(snapshot.activeApprovals);
    this.tenants.load(snapshot.tenants);
    this.authTokens = snapshot.authTokens.map((token) => ({ ...token }));
  }

  private authTokens: ControlPlaneAuthToken[] = [];

  private snapshot(): ControlPlaneMetadataSnapshot {
    return {
      version: 1,
      revision: this.metadataRevision,
      updatedAt: Date.now(),
      authTokens: this.authTokens.map((token) => ({ ...token })),
      tenants: this.tenants.snapshot(),
      policyPacks: this.policyPacks.snapshot(),
      approvalWorkflows: this.approvalWorkflows.snapshotWorkflows(),
      activeApprovals: this.approvalWorkflows.snapshotApprovals(),
    };
  }

  private async refreshState(force = false): Promise<void> {
    if (!force && !this.metadata.shared) {
      return;
    }
    const snapshot = await this.metadata.load();
    this.hydrate(snapshot);
  }

  private async persistMetadata(expectedRevision = this.metadataRevision): Promise<void> {
    const saved = await this.metadata.save(this.snapshot(), expectedRevision);
    this.hydrate(saved);
  }

  private async ensureReady(): Promise<void> {
    await this.ready;
  }

  private async queueMutation<T>(fn: () => Promise<T> | T, persist = true): Promise<T> {
    await this.ensureReady();

    let result!: T;
    const job = this.mutationChain.then(async () => {
      const maxAttempts = this.metadata.shared && persist ? 4 : 1;

      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        if (this.metadata.shared) {
          await this.refreshState(true);
        }

        const baseRevision = this.metadataRevision;
        result = await fn();

        if (!persist) {
          return;
        }

        try {
          await this.persistMetadata(baseRevision);
          return;
        } catch (error) {
          if (error instanceof MetadataConflictError && attempt < maxAttempts - 1) {
            continue;
          }
          throw error;
        }
      }
    });

    this.mutationChain = job.then(
      () => undefined,
      () => undefined,
    );

    await job;
    return result;
  }

  private async ensureBootstrapTokens(snapshot: ControlPlaneMetadataSnapshot): Promise<boolean> {
    const bootstrap = this.config.bootstrapTokens ?? [];
    if (bootstrap.length === 0) {
      return false;
    }

    let changed = false;
    for (const raw of bootstrap) {
      const normalized = typeof raw === 'string'
        ? createAuthTokenRecord(raw)
        : createAuthTokenRecord(raw.token, {
            name: raw.name,
            role: raw.role,
            tenantIds: raw.tenantIds,
          });
      const existing = this.authTokens.find((token) => token.tokenHash === normalized.tokenHash);
      if (!existing) {
        this.authTokens.push(normalized);
        changed = true;
      }
    }
    if (changed) {
      snapshot.authTokens = this.authTokens.map((token) => ({ ...token }));
    }
    return changed;
  }

  private assertTenantAccess(auth: ServiceAuthResult | undefined, tenantId?: string): void {
    if (!this.config.authRequired || !auth || !tenantId) {
      return;
    }
    if (auth.token.role === 'admin') {
      return;
    }
    const allowed = auth.token.tenantIds ?? [];
    if (!allowed.includes(tenantId)) {
      throw new Error(`Token "${auth.token.name}" does not have access to tenant "${tenantId}"`);
    }
  }

  async authenticate(rawToken?: string, tenantId?: string): Promise<ServiceAuthResult | undefined> {
    await this.ensureReady();
    await this.refreshState();

    if (!this.config.authRequired) {
      const token = this.authTokens[0];
      return token ? { token, tenantId } : undefined;
    }

    if (!rawToken) {
      throw new Error('Missing bearer token');
    }

    const tokenHash = sha256Hex(rawToken);
    const token = this.authTokens.find((candidate) => candidate.tokenHash === tokenHash);
    if (!token) {
      throw new Error('Invalid bearer token');
    }

    if (token.role !== 'admin' && (token.tenantIds?.length ?? 0) > 0 && !tenantId) {
      throw new Error('Tenant scope header is required for this token');
    }

    this.assertTenantAccess({ token, tenantId }, tenantId);

    const now = Date.now();
    if (token.lastUsedAt !== now) {
      await this.queueMutation(() => {
        token.lastUsedAt = now;
        return token;
      });
    }

    return { token: { ...token }, tenantId };
  }

  async issueToken(options: TokenIssueOptions): Promise<{ token: string; record: ControlPlaneAuthToken }> {
    const rawToken = options.token ?? randomBytes(24).toString('base64url');
    const record = createAuthTokenRecord(rawToken, {
      name: options.name,
      role: options.role ?? 'operator',
      tenantIds: options.tenantIds,
      metadata: options.metadata,
    });
    await this.queueMutation(() => {
      this.authTokens.push(record);
      return record;
    });
    return { token: rawToken, record: clone(record) };
  }

  async listTokens(): Promise<ControlPlaneAuthToken[]> {
    await this.ensureReady();
    await this.refreshState();
    return this.authTokens.map((token) => ({ ...token }));
  }

  async createTenant(options: CreateTenantOptions): Promise<Tenant> {
    return this.queueMutation(() => this.tenants.create(options));
  }

  async getTenant(id: string): Promise<Tenant | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const tenant = this.tenants.get(id);
    return tenant ? clone(tenant) : undefined;
  }

  async listTenants(status?: Tenant['status']): Promise<Tenant[]> {
    await this.ensureReady();
    await this.refreshState();
    return this.tenants.list(status).map((tenant) => clone(tenant));
  }

  async updateTenantConfig(id: string, config: Partial<TenantConfig>): Promise<Tenant | undefined> {
    return this.queueMutation(() => this.tenants.updateConfig(id, config));
  }

  async suspendTenant(id: string): Promise<Tenant | undefined> {
    return this.queueMutation(() => this.tenants.suspend(id));
  }

  async activateTenant(id: string): Promise<Tenant | undefined> {
    return this.queueMutation(() => this.tenants.activate(id));
  }

  async deleteTenant(id: string): Promise<boolean> {
    return this.queueMutation(() => this.tenants.delete(id));
  }

  async createPolicyPack(options: CreatePolicyPackOptions): Promise<PolicyPack> {
    return this.queueMutation(() => this.policyPacks.create(options));
  }

  async getPolicyPack(id: string): Promise<PolicyPack | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const pack = this.policyPacks.get(id);
    return pack ? clone(pack) : undefined;
  }

  async listPolicyPacks(tags?: string[]): Promise<PolicyPack[]> {
    await this.ensureReady();
    await this.refreshState();
    return this.policyPacks.list(tags).map((pack) => clone(pack));
  }

  async updatePolicyPack(
    id: string,
    updates: Partial<Pick<PolicyPack, 'name' | 'description' | 'version' | 'rules' | 'tags'>>,
  ): Promise<PolicyPack | undefined> {
    return this.queueMutation(() => this.policyPacks.update(id, updates));
  }

  async deletePolicyPack(id: string): Promise<boolean> {
    return this.queueMutation(() => this.policyPacks.delete(id));
  }

  async registerWorkflow(workflow: ApprovalWorkflow): Promise<ApprovalWorkflow> {
    return this.queueMutation(() => {
      this.approvalWorkflows.registerWorkflow(workflow);
      return workflow;
    });
  }

  async listWorkflows(): Promise<ApprovalWorkflow[]> {
    await this.ensureReady();
    await this.refreshState();
    return this.approvalWorkflows.listWorkflows().map((workflow) => clone(workflow));
  }

  async getWorkflow(id: string): Promise<ApprovalWorkflow | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const workflow = this.approvalWorkflows.getWorkflow(id);
    return workflow ? clone(workflow) : undefined;
  }

  async startApproval(options: ApprovalStartOptions): Promise<ActiveApproval> {
    return this.queueMutation(() =>
      this.approvalWorkflows.startApproval(
        options.workflowId,
        options.runId,
        options.agentId,
        options.proposal,
        options.riskScore,
      ),
    );
  }

  async voteApproval(options: ApprovalVoteOptions): Promise<ActiveApproval> {
    return this.queueMutation(() =>
      this.approvalWorkflows.vote(
        options.approvalId,
        options.approver,
        options.approved,
        options.reason,
      ),
    );
  }

  async getApproval(id: string): Promise<ActiveApproval | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const approval = this.approvalWorkflows.getApproval(id);
    return approval ? clone(approval) : undefined;
  }

  async listPendingApprovals(): Promise<ActiveApproval[]> {
    await this.ensureReady();
    await this.refreshState();
    return this.approvalWorkflows.listPending().map((approval) => clone(approval));
  }

  async listResolvedApprovals(): Promise<ActiveApproval[]> {
    await this.ensureReady();
    await this.refreshState();
    return this.approvalWorkflows.listResolved().map((approval) => clone(approval));
  }

  async processApprovalTimeouts(): Promise<ActiveApproval[]> {
    return this.queueMutation(() => this.approvalWorkflows.processTimeouts());
  }

  async ingestTrace(options: IngestOptions): Promise<TraceRecord> {
    await this.ensureReady();
    return this.traces.ingest(options);
  }

  async getTrace(id: string): Promise<TraceRecord | undefined> {
    await this.ensureReady();
    const record = await this.traces.get(id);
    return record ? clone(record) : undefined;
  }

  async queryTraces(filters: TraceQuery): Promise<TraceRecord[]> {
    await this.ensureReady();
    const records = await this.traces.query(filters);
    return records.map((record) => clone(record));
  }

  async deleteTrace(id: string): Promise<boolean> {
    await this.ensureReady();
    return this.traces.delete(id);
  }

  async verifyTrace(id: string): Promise<boolean> {
    await this.ensureReady();
    return this.traces.verify(id);
  }

  async countTraces(): Promise<number> {
    await this.ensureReady();
    return this.traces.count();
  }

  async purgeExpiredTraces(): Promise<number> {
    await this.ensureReady();
    const traces = await this.traces.query({});
    let purged = 0;

    for (const trace of traces) {
      const tenantRetention = trace.tenantId
        ? this.tenants.get(trace.tenantId)?.config.traceRetentionDays
        : undefined;
      const retentionDays = tenantRetention ?? this.config.traceRetentionDays;
      const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;

      if (trace.startedAt < cutoff) {
        const deleted = await this.traces.delete(trace.id);
        if (deleted) {
          purged += 1;
        }
      }
    }

    return purged;
  }

  async exportAudit(records: TraceRecord[], options: AuditExportOptions): Promise<AuditExportResult> {
    await this.ensureReady();
    return exportTraces(records, options);
  }

  async generateEvidence(
    trace: TraceRecord,
    policyDecisions: unknown[],
    approvalDecisions: unknown[] | ApprovalVote[],
  ) {
    await this.ensureReady();
    return generateEvidenceBundle(trace, policyDecisions, approvalDecisions);
  }

  async health(): Promise<{
    ready: boolean;
    tenantCount: number;
    policyPackCount: number;
    workflowCount: number;
    pendingApprovalCount: number;
    traceCount: number;
    traceDiskUsageBytes: number;
  }> {
    await this.ensureReady();
    await this.refreshState();
    return {
      ready: true,
      tenantCount: this.tenants.count(),
      policyPackCount: this.policyPacks.count(),
      workflowCount: this.approvalWorkflows.listWorkflows().length,
      pendingApprovalCount: this.approvalWorkflows.listPending().length,
      traceCount: await this.traces.count(),
      traceDiskUsageBytes: await this.traceBackend.diskUsageBytes?.() ?? 0,
    };
  }

  async close(): Promise<void> {
    await this.metadata.close?.();
  }
}

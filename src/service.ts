/**
 * @module ControlPlaneService
 * @description
 * Persistent remote control-plane service that composes tenancy,
 * policy packs, approval workflows, trace retention, and audit export.
 */

import { randomBytes } from 'node:crypto';
import { verifyChargeAuthorizationSignature, type ChargeAuthorization } from '@veridex/platform-events';

import { ApprovalWorkflowEngine, type ActiveApproval, type ApprovalVote } from './approval-workflows';
import {
  FileApprovalJournal,
  replayApprovalJournal,
  type ApprovalJournalBackend,
} from './approval-journal';
import {
  ProtectedIntentRegistry,
  type ProtectedIntentEnvelope,
  type PublishedRecipientKey,
} from './protected-intent';
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
  AgentManifest,
  Assignment,
  ApprovalWorkflow,
  ControlPlaneAuthToken,
  ControlPlaneRole,
  ControlPlaneServiceConfig,
  DeploymentRevision,
  EvidenceBundle,
  EvalRun,
  EvalSuite,
  Incident,
  MaintenanceJob,
  MutationDecision,
  PolicyBinding,
  PolicyPack,
  ResourceMutationProposal,
  Task,
  Tenant,
  TenantConfig,
  TraceQuery,
  TraceRecord,
  Workspace,
  WorkspaceResource,
  SponsorshipPolicyData,
  GatewayConfigData,
  GatewayDeploymentSpec,
  ChargeAuthorizationData,
  TeamInvitationData,
  PaymentProjectionData,
  PaymentResourceData,
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
  protectedIntent?: NonNullable<ControlPlaneServiceConfig['protectedIntent']>;
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
    protectedIntent: config.protectedIntent,
  };
}

export interface ProtectedIntentSubmission {
  /** Decrypted plaintext as a UTF-8 string. */
  plaintext: string;
  /** Plaintext as raw bytes (base64url) for binary payloads. */
  plaintextBase64Url: string;
  /** Echo of the envelope metadata for audit. */
  envelope: {
    keyId: string;
    agentId: string;
    submittedAt: number;
    plaintextHash: string;
    nonce: string;
  };
  /** Server-side timestamp when ingress accepted the envelope. */
  acceptedAt: number;
}

export type ProtectedIntentPreflightVerdict = 'approved' | 'rejected';

export interface ProtectedIntentPreflightCheck {
  id: string;
  passed: boolean;
  reason: string;
  metadata?: Record<string, unknown>;
}

export interface ProtectedIntentPreflightDecision {
  verdict: ProtectedIntentPreflightVerdict;
  reasons: string[];
  checks: ProtectedIntentPreflightCheck[];
  policyPackId?: string;
  intentSummary?: {
    humanId?: string;
    agentId?: string;
    actionType?: string;
    rail?: string;
    destination?: string;
    amount?: string;
    currency?: string;
    expiresAt?: string;
  };
}

export interface ProtectedIntentPreflightResult extends ProtectedIntentSubmission {
  decision: ProtectedIntentPreflightDecision;
  evidenceBundle: EvidenceBundle;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function readString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function readDecimal(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'string' || value.trim().length === 0) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function includesString(list: unknown, value: string | undefined): boolean {
  return !!value && Array.isArray(list) && list.some((item) => item === value);
}

function evaluateProtectedPaymentIntent(
  submission: ProtectedIntentSubmission,
  now: number,
): ProtectedIntentPreflightDecision {
  const checks: ProtectedIntentPreflightCheck[] = [];
  const addCheck = (
    id: string,
    passed: boolean,
    reason: string,
    metadata?: Record<string, unknown>,
  ) => checks.push({ id, passed, reason, metadata });

  let root: unknown;
  try {
    root = JSON.parse(submission.plaintext);
    addCheck('valid-json', true, 'Plaintext intent is valid JSON');
  } catch {
    addCheck('valid-json', false, 'Plaintext intent is not valid JSON');
    return buildPreflightDecision(checks);
  }

  if (!isRecord(root)) {
    addCheck('intent-object', false, 'Plaintext intent must be a JSON object');
    return buildPreflightDecision(checks);
  }
  addCheck('intent-object', true, 'Plaintext intent is a JSON object');

  const principal = isRecord(root.principal) ? root.principal : undefined;
  const action = isRecord(root.action) ? root.action : undefined;
  const policy = isRecord(root.policy) ? root.policy : undefined;
  const amountRecord = action && isRecord(action.amount) ? action.amount : undefined;
  const toRecord = action && isRecord(action.to) ? action.to : undefined;
  const caps = policy && isRecord(policy.caps) ? policy.caps : undefined;
  const allowList = policy && isRecord(policy.allowList) ? policy.allowList : undefined;

  const principalAgentId = readString(principal?.agentId);
  const humanId = readString(principal?.humanId);
  const actionType = readString(action?.type);
  const rail = readString(action?.rail);
  const destination = readString(toRecord?.wallet);
  const amountValue = readDecimal(amountRecord?.value);
  const amountText = readString(amountRecord?.value) ?? (amountValue !== undefined ? String(amountValue) : undefined);
  const currency = readString(amountRecord?.currency);
  const policyPackId = readString(policy?.policyPackId);
  const expiresAt = readString(root.expiresAt);
  const expiryMs = expiresAt ? Date.parse(expiresAt) : Number.NaN;

  addCheck(
    'agent-binding',
    principalAgentId === submission.envelope.agentId,
    principalAgentId === submission.envelope.agentId
      ? 'Envelope agentId matches intent principal'
      : 'Envelope agentId does not match intent principal',
    { envelopeAgentId: submission.envelope.agentId, principalAgentId },
  );
  addCheck(
    'not-expired',
    Number.isFinite(expiryMs) && expiryMs > now,
    Number.isFinite(expiryMs) && expiryMs > now
      ? 'Intent has not expired'
      : 'Intent is expired or missing expiresAt',
    { expiresAt },
  );
  addCheck(
    'payment-transfer-action',
    actionType === 'payment.transfer',
    actionType === 'payment.transfer'
      ? 'Intent action is payment.transfer'
      : 'Intent action is not payment.transfer',
    { actionType },
  );
  addCheck(
    'amount-positive',
    amountValue !== undefined && amountValue > 0,
    amountValue !== undefined && amountValue > 0
      ? 'Payment amount is positive'
      : 'Payment amount is missing, invalid, or non-positive',
    { amount: amountText, currency },
  );

  const maxPerRequest = readDecimal(caps?.maxPerRequest);
  addCheck(
    'max-per-request',
    amountValue !== undefined && maxPerRequest !== undefined && amountValue <= maxPerRequest,
    amountValue !== undefined && maxPerRequest !== undefined && amountValue <= maxPerRequest
      ? 'Payment is within maxPerRequest cap'
      : 'Payment exceeds maxPerRequest cap or cap is missing',
    { amount: amountText, maxPerRequest: caps?.maxPerRequest },
  );

  const hourlyLimit = readDecimal(caps?.hourlyLimit);
  if (hourlyLimit !== undefined) {
    addCheck(
      'hourly-limit-static-bound',
      amountValue !== undefined && amountValue <= hourlyLimit,
      amountValue !== undefined && amountValue <= hourlyLimit
        ? 'Payment is within declared hourlyLimit'
        : 'Payment exceeds declared hourlyLimit',
      { amount: amountText, hourlyLimit: caps?.hourlyLimit },
    );
  }

  const dailyLimit = readDecimal(caps?.dailyLimit);
  if (dailyLimit !== undefined) {
    addCheck(
      'daily-limit-static-bound',
      amountValue !== undefined && amountValue <= dailyLimit,
      amountValue !== undefined && amountValue <= dailyLimit
        ? 'Payment is within declared dailyLimit'
        : 'Payment exceeds declared dailyLimit',
      { amount: amountText, dailyLimit: caps?.dailyLimit },
    );
  }

  addCheck(
    'destination-allowlist',
    includesString(allowList?.destinations, destination),
    includesString(allowList?.destinations, destination)
      ? 'Destination is in the intent allow-list'
      : 'Destination is not in the intent allow-list',
    { destination },
  );
  addCheck(
    'rail-allowlist',
    includesString(allowList?.rails, rail),
    includesString(allowList?.rails, rail)
      ? 'Rail is in the intent allow-list'
      : 'Rail is not in the intent allow-list',
    { rail },
  );
  addCheck(
    'policy-pack-present',
    !!policyPackId,
    policyPackId ? 'Intent declares a policy pack' : 'Intent is missing policy.policyPackId',
    { policyPackId },
  );

  return buildPreflightDecision(checks, {
    policyPackId,
    intentSummary: {
      humanId,
      agentId: principalAgentId,
      actionType,
      rail,
      destination,
      amount: amountText,
      currency,
      expiresAt,
    },
  });
}

function buildPreflightDecision(
  checks: ProtectedIntentPreflightCheck[],
  extras: Pick<ProtectedIntentPreflightDecision, 'policyPackId' | 'intentSummary'> = {},
): ProtectedIntentPreflightDecision {
  const failed = checks.filter((check) => !check.passed);
  return {
    verdict: failed.length === 0 ? 'approved' : 'rejected',
    reasons: failed.length === 0
      ? ['All protected intent preflight checks passed']
      : failed.map((check) => check.reason),
    checks,
    ...extras,
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
  approvalJournal?: ApprovalJournalBackend;
}

export class ControlPlaneService {
  readonly config: ReturnType<typeof defaultConfig>;
  readonly traces: TraceStore;
  readonly policyPacks: PolicyPackManager;
  readonly approvalWorkflows: ApprovalWorkflowEngine;
  readonly tenants: TenantManager;
  readonly protectedIntent?: ProtectedIntentRegistry;

  private readonly metadata: ControlPlaneMetadataStore;
  private readonly traceBackend: TraceStoreMetricsBackend;
  private readonly approvalJournal: ApprovalJournalBackend;
  private readonly ready: Promise<void>;
  private mutationChain = Promise.resolve<void>(undefined);
  private metadataRevision = 0;

  constructor(config: ControlPlaneServiceConfig, persistence?: ControlPlaneServicePersistence) {
    this.config = defaultConfig(config);
    this.metadata = persistence?.metadataStore ?? new JSONFileMetadataStore(this.config.dataDir);
    this.traceBackend = persistence?.traceBackend ?? new FileTraceStoreBackend(this.config.dataDir);
    this.approvalJournal =
      persistence?.approvalJournal ?? new FileApprovalJournal(this.config.dataDir);
    this.traces = new TraceStore(this.traceBackend, this.config.traceRetentionDays);
    this.policyPacks = new PolicyPackManager();
    this.approvalWorkflows = new ApprovalWorkflowEngine();
    this.tenants = new TenantManager();
    if (this.config.protectedIntent && this.config.protectedIntent.keys.length > 0) {
      this.protectedIntent = new ProtectedIntentRegistry({
        keys: this.config.protectedIntent.keys,
        replayWindowMs: this.config.protectedIntent.replayWindowMs,
      });
    }
    this.ready = this.initialize();
  }

  private async initialize(): Promise<void> {
    const snapshot = await this.metadata.load();
    this.hydrate(snapshot);
    // Replay any journal events that were written but not yet reflected in
    // the main snapshot (crash between journal append and snapshot save).
    const journalEvents = await this.approvalJournal.read();
    const applied = replayApprovalJournal(journalEvents, this.approvalWorkflows);
    if (applied > 0) {
      // Persist recovered state and compact journal.
      await this.persistMetadata();
      await this.approvalJournal.truncate();
    }
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
    this._workspaces = snapshot.workspaces ?? [];
    this.authTokens = snapshot.authTokens.map((token) => ({ ...token }));
    this._agentManifests = snapshot.agentManifests ?? [];
    this._workspaceResources = snapshot.workspaceResources ?? [];
    this._tasks = snapshot.tasks ?? [];
    this._deploymentRevisions = snapshot.deploymentRevisions ?? [];
    this._incidents = snapshot.incidents ?? [];
    this._evalSuites = snapshot.evalSuites ?? [];
    this._evalRuns = snapshot.evalRuns ?? [];
    this._policyBindings = snapshot.policyBindings ?? [];
    this._assignments = snapshot.assignments ?? [];
    this._maintenanceJobs = snapshot.maintenanceJobs ?? [];
    this._resourceMutationProposals = snapshot.resourceMutationProposals ?? [];
  }

  private authTokens: ControlPlaneAuthToken[] = [];

  // Workforce OS resource storage (managed by future sub-managers)
  private _agentManifests: AgentManifest[] = [];
  private _workspaces: Workspace[] = [];
  private _workspaceResources: WorkspaceResource[] = [];
  private _tasks: Task[] = [];
  private _deploymentRevisions: DeploymentRevision[] = [];
  private _incidents: Incident[] = [];
  private _evalSuites: EvalSuite[] = [];
  private _evalRuns: EvalRun[] = [];
  private _policyBindings: PolicyBinding[] = [];
  private _assignments: Assignment[] = [];
  private _maintenanceJobs: MaintenanceJob[] = [];
  private _resourceMutationProposals: ResourceMutationProposal[] = [];

  private snapshot(): ControlPlaneMetadataSnapshot {
    return {
      version: 1,
      revision: this.metadataRevision,
      updatedAt: Date.now(),
      authTokens: this.authTokens.map((token) => ({ ...token })),
      tenants: this.tenants.snapshot(),
      workspaces: clone(this._workspaces),
      policyPacks: this.policyPacks.snapshot(),
      approvalWorkflows: this.approvalWorkflows.snapshotWorkflows(),
      activeApprovals: this.approvalWorkflows.snapshotApprovals(),
      agentManifests: clone(this._agentManifests),
      workspaceResources: clone(this._workspaceResources),
      tasks: clone(this._tasks),
      deploymentRevisions: clone(this._deploymentRevisions),
      incidents: clone(this._incidents),
      evalSuites: clone(this._evalSuites),
      evalRuns: clone(this._evalRuns),
      policyBindings: clone(this._policyBindings),
      assignments: clone(this._assignments),
      maintenanceJobs: clone(this._maintenanceJobs),
      resourceMutationProposals: clone(this._resourceMutationProposals),
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
    // Journal has been incorporated into the committed snapshot; safe to truncate.
    await this.approvalJournal.truncate();
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

  // ── Workspace CRUD ──

  async createWorkspace(
    options: Omit<Workspace, 'id' | 'createdAt' | 'updatedAt'>,
  ): Promise<Workspace> {
    return this.queueMutation(() => {
      const now = Date.now();
      const workspace: Workspace = {
        ...options,
        id: `ws_${randomBytes(12).toString('hex')}`,
        createdAt: now,
        updatedAt: now,
      };
      this._workspaces.push(workspace);
      return clone(workspace);
    });
  }

  async getWorkspace(id: string): Promise<Workspace | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const workspace = this._workspaces.find((entry) => entry.id === id);
    return workspace ? clone(workspace) : undefined;
  }

  async listWorkspaces(filter?: {
    tenantId?: string;
    status?: Workspace['status'];
  }): Promise<Workspace[]> {
    await this.ensureReady();
    await this.refreshState();
    let list = this._workspaces;
    if (filter?.tenantId) {
      list = list.filter((entry) => entry.tenantId === filter.tenantId);
    }
    if (filter?.status) {
      list = list.filter((entry) => entry.status === filter.status);
    }
    return list.map((entry) => clone(entry));
  }

  async updateWorkspace(
    id: string,
    updates: Partial<Pick<Workspace, 'name' | 'status' | 'description' | 'config' | 'metadata'>>,
  ): Promise<Workspace | undefined> {
    return this.queueMutation(() => {
      const workspace = this._workspaces.find((entry) => entry.id === id);
      if (!workspace) return undefined;
      Object.assign(workspace, updates);
      workspace.updatedAt = Date.now();
      return clone(workspace);
    });
  }

  async deleteWorkspace(id: string): Promise<boolean> {
    return this.queueMutation(() => {
      const idx = this._workspaces.findIndex((entry) => entry.id === id);
      if (idx === -1) return false;
      this._workspaces.splice(idx, 1);
      return true;
    });
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
    return this.queueMutation(async () => {
      const approval = this.approvalWorkflows.startApproval(
        options.workflowId,
        options.runId,
        options.agentId,
        options.proposal,
        options.riskScore,
      );
      await this.approvalJournal.append({
        type: 'start',
        at: Date.now(),
        approval: { ...approval, approvals: [...approval.approvals] },
      });
      return approval;
    });
  }

  async voteApproval(options: ApprovalVoteOptions): Promise<ActiveApproval> {
    return this.queueMutation(async () => {
      const approval = this.approvalWorkflows.vote(
        options.approvalId,
        options.approver,
        options.approved,
        options.reason,
      );
      const latestVote = approval.approvals[approval.approvals.length - 1];
      if (latestVote) {
        await this.approvalJournal.append({
          type: 'vote',
          at: Date.now(),
          approvalId: approval.id,
          vote: { ...latestVote },
          resolution: approval.resolution,
        });
      }
      return approval;
    });
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
    return this.queueMutation(async () => {
      const processed = this.approvalWorkflows.processTimeouts();
      for (const approval of processed) {
        await this.approvalJournal.append({
          type: 'timeout',
          at: Date.now(),
          approvalId: approval.id,
          newStep: approval.resolution ? undefined : approval.currentStep,
          newDeadline: approval.resolution ? undefined : approval.currentStepDeadline,
          resolution: approval.resolution,
        });
      }
      return processed;
    });
  }

  async ingestTrace(options: IngestOptions): Promise<TraceRecord> {
    await this.ensureReady();
    return this.traces.ingest(options);
  }

  /**
   * Discovery endpoint payload — public keys clients use to encrypt envelopes.
   * Returns an empty list when the protected-intent feature is not configured.
   */
  listProtectedIntentKeys(): PublishedRecipientKey[] {
    return this.protectedIntent ? this.protectedIntent.publishedKeys() : [];
  }

  /**
   * Decrypt and accept a protected-intent envelope. Throws when the feature is
   * not configured or when decryption / replay / hash verification fails.
   *
   * The decrypted plaintext is returned to the caller; downstream PolicyEngine
   * + approval pipeline integration is intentionally left to the caller so the
   * ingress layer can stay thin and observable.
   */
  async submitProtectedIntent(envelope: ProtectedIntentEnvelope): Promise<ProtectedIntentSubmission> {
    await this.ensureReady();
    if (!this.protectedIntent) {
      throw new Error('protected-intent feature is not configured on this control-plane');
    }
    const decrypted = this.protectedIntent.decrypt(envelope);
    return {
      plaintext: decrypted.plaintext.toString('utf8'),
      plaintextBase64Url: decrypted.plaintext
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, ''),
      envelope: {
        keyId: decrypted.envelope.keyId,
        agentId: decrypted.envelope.agentId,
        submittedAt: decrypted.envelope.submittedAt,
        plaintextHash: decrypted.envelope.plaintextHash,
        nonce: decrypted.envelope.nonce,
      },
      acceptedAt: Date.now(),
    };
  }

  /**
   * Pilot preflight for payment intents submitted through the protected-intent
   * path. This is intentionally deterministic and stateless: it validates the
   * envelope, checks the intent's declared policy caps / allow-list / expiry,
   * and returns an evidence bundle Modexia can attach to its settlement record.
   */
  async preflightProtectedIntent(envelope: ProtectedIntentEnvelope): Promise<ProtectedIntentPreflightResult> {
    const submission = await this.submitProtectedIntent(envelope);
    const decision = evaluateProtectedPaymentIntent(submission, Date.now());
    const trace: TraceRecord = {
      id: `trace_${submission.envelope.plaintextHash.slice(0, 16)}`,
      runId: `protected_${submission.envelope.plaintextHash.slice(0, 16)}`,
      agentId: submission.envelope.agentId,
      startedAt: submission.envelope.submittedAt,
      completedAt: submission.acceptedAt,
      state: decision.verdict === 'approved' ? 'completed' : 'failed',
      turnCount: 1,
      totalTokens: 0,
      events: [
        {
          type: 'protected_intent_preflight',
          plaintextHash: submission.envelope.plaintextHash,
          agentId: submission.envelope.agentId,
          decision,
        },
      ],
      metadata: {
        protectedIntent: true,
        plaintextHash: submission.envelope.plaintextHash,
        policyPackId: decision.policyPackId,
      },
    };
    const evidenceBundle = await generateEvidenceBundle(trace, [decision], []);

    return {
      ...submission,
      decision,
      evidenceBundle,
    };
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

  // ── Agent Manifest CRUD ──

  async registerAgentManifest(
    options: Omit<AgentManifest, 'id' | 'registeredAt'>,
  ): Promise<AgentManifest> {
    return this.queueMutation(() => {
      const manifest: AgentManifest = {
        ...options,
        id: `am_${randomBytes(12).toString('hex')}`,
        registeredAt: Date.now(),
        manifestRevision: options.manifestRevision ?? 1,
      };
      this._agentManifests.push(manifest);
      return clone(manifest);
    });
  }

  async getAgentManifest(id: string): Promise<AgentManifest | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const manifest = this._agentManifests.find((m) => m.id === id);
    return manifest ? clone(manifest) : undefined;
  }

  async listAgentManifests(status?: AgentManifest['status']): Promise<AgentManifest[]> {
    await this.ensureReady();
    await this.refreshState();
    const list = status
      ? this._agentManifests.filter((m) => m.status === status)
      : this._agentManifests;
    return list.map((m) => clone(m));
  }

  async updateAgentManifest(
    id: string,
    updates: Partial<Pick<AgentManifest, 'name' | 'version' | 'status' | 'capabilities' | 'modelLabel' | 'policyPackIds' | 'metadata' | 'lastHeartbeatAt'>>,
  ): Promise<AgentManifest | undefined> {
    return this.queueMutation(() => {
      const manifest = this._agentManifests.find((m) => m.id === id);
      if (!manifest) return undefined;
      Object.assign(manifest, updates);
      manifest.manifestRevision = (manifest.manifestRevision ?? 1) + 1;
      return clone(manifest);
    });
  }

  async removeAgentManifest(id: string): Promise<boolean> {
    return this.queueMutation(() => {
      const idx = this._agentManifests.findIndex((m) => m.id === id);
      if (idx === -1) return false;
      this._agentManifests.splice(idx, 1);
      return true;
    });
  }

  // ── Workspace Resource CRUD ──

  async createWorkspaceResource(
    options: Omit<WorkspaceResource, 'id' | 'version' | 'createdAt' | 'updatedAt'>,
  ): Promise<WorkspaceResource> {
    return this.queueMutation(() => {
      const now = Date.now();
      const resource: WorkspaceResource = {
        ...options,
        id: `wr_${randomBytes(12).toString('hex')}`,
        version: 1,
        resourceVersion: {
          version: 1,
          updatedAt: now,
          updatedBy: options.createdBy,
        },
        createdAt: now,
        updatedAt: now,
      };
      this._workspaceResources.push(resource);
      return clone(resource);
    });
  }

  async getWorkspaceResource(id: string, tenantId?: string): Promise<WorkspaceResource | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const resource = this._workspaceResources.find((r) =>
      r.id === id && (!tenantId || r.tenantId === tenantId)
    );
    return resource ? clone(resource) : undefined;
  }

  async listWorkspaceResources(
    filter?: {
      tenantId?: string;
      workspaceId?: string;
      resourceType?: string;
      status?: WorkspaceResource['status'];
      tags?: string[];
    },
  ): Promise<WorkspaceResource[]> {
    await this.ensureReady();
    await this.refreshState();
    let list = this._workspaceResources;
    if (filter?.tenantId) {
      list = list.filter((r) => r.tenantId === filter.tenantId);
    }
    if (filter?.workspaceId) {
      list = list.filter((r) => r.workspaceId === filter.workspaceId);
    }
    if (filter?.resourceType) {
      list = list.filter((r) => r.resourceType === filter.resourceType);
    }
    if (filter?.status) {
      list = list.filter((r) => r.status === filter.status);
    }
    if (filter?.tags && filter.tags.length > 0) {
      list = list.filter((r) => filter.tags?.some((t) => r.tags?.includes(t)));
    }
    return list.map((r) => clone(r));
  }

  async getSponsorshipPolicy(
    tenantId: string,
    appId: string,
    environment: 'test' | 'live',
  ): Promise<WorkspaceResource | undefined> {
    const policies = await this.listWorkspaceResources({
      tenantId,
      resourceType: 'sponsorship_policy',
      status: 'active',
    });
    return policies.find((resource) =>
      resource.data.appId === appId && resource.data.environment === environment
    );
  }

  async putSponsorshipPolicy(
    tenantId: string,
    policy: SponsorshipPolicyData,
  ): Promise<WorkspaceResource> {
    validateSponsorshipPolicy(policy);
    const existing = await this.getSponsorshipPolicy(tenantId, policy.appId, policy.environment);
    if (existing) {
      const updated = await this.updateWorkspaceResource(existing.id, {
        data: policy as unknown as Record<string, unknown>,
        updatedBy: policy.updatedBy,
        reviewStatus: policy.environment === 'live' ? 'review_required' : 'unreviewed',
      });
      if (!updated) throw new Error('Sponsorship policy disappeared during update');
      return updated;
    }
    return this.createWorkspaceResource({
      tenantId,
      resourceType: 'sponsorship_policy',
      name: `${policy.appId}:${policy.environment}`,
      status: 'active',
      data: policy as unknown as Record<string, unknown>,
      tags: ['sponsorship', policy.environment, policy.appId],
      createdBy: policy.updatedBy,
      updatedBy: policy.updatedBy,
      reviewStatus: policy.environment === 'live' ? 'review_required' : 'unreviewed',
    });
  }

  async listGatewayConfigs(
    tenantId: string,
    appId: string,
    environment: 'test' | 'live',
  ): Promise<WorkspaceResource[]> {
    const resources = await this.listWorkspaceResources({
      tenantId,
      resourceType: 'gateway_config',
    });
    return resources.filter((resource) =>
      resource.data.appId === appId && resource.data.environment === environment
    );
  }

  async createGatewayConfig(tenantId: string, config: GatewayConfigData): Promise<WorkspaceResource> {
    validateGatewayConfig(config);
    return this.createWorkspaceResource({
      tenantId,
      resourceType: 'gateway_config',
      name: config.name,
      status: config.state === 'disabled' ? 'archived' : 'active',
      data: config as unknown as Record<string, unknown>,
      tags: ['gateway', config.environment, config.appId, ...config.targets.map((target) => target.network)],
      createdBy: config.updatedBy,
      updatedBy: config.updatedBy,
      reviewStatus: config.environment === 'live' || config.state === 'active' ? 'review_required' : 'unreviewed',
    });
  }

  async updateGatewayConfig(
    tenantId: string,
    gatewayId: string,
    appId: string,
    environment: 'test' | 'live',
    config: GatewayConfigData,
  ): Promise<WorkspaceResource | undefined> {
    validateGatewayConfig(config);
    if (config.appId !== appId || config.environment !== environment) throw new Error('Gateway scope cannot change');
    const existing = await this.getWorkspaceResource(gatewayId, tenantId);
    if (!existing || existing.resourceType !== 'gateway_config'
      || existing.data.appId !== appId || existing.data.environment !== environment) return undefined;
    return this.updateWorkspaceResource(gatewayId, {
      name: config.name,
      status: config.state === 'disabled' ? 'archived' : 'active',
      data: config as unknown as Record<string, unknown>,
      tags: ['gateway', config.environment, config.appId, ...config.targets.map((target) => target.network)],
      updatedBy: config.updatedBy,
      reviewStatus: config.environment === 'live' || config.state === 'active' ? 'review_required' : 'unreviewed',
    }, tenantId);
  }

  async getGatewayDeploymentSpecs(
    tenantId: string,
    gatewayId: string,
    appId: string,
    environment: 'test' | 'live',
  ): Promise<GatewayDeploymentSpec[] | undefined> {
    const resource = await this.getWorkspaceResource(gatewayId, tenantId);
    if (!resource || resource.resourceType !== 'gateway_config'
      || resource.data.appId !== appId || resource.data.environment !== environment) return undefined;
    const config = resource.data as unknown as GatewayConfigData;
    validateGatewayConfig(config);
    return config.targets.map((target, index) => ({
      gatewayId,
      targetId: `${gatewayId}:${index}`,
      appId,
      environment,
      state: config.state,
      image: target.network.startsWith('stellar:')
        ? 'ghcr.io/veridex/stellar-x402-gateway:0.1.0'
        : 'ghcr.io/veridex/multichain-gateway:0.1.0',
      config: {
        id: `${gatewayId}-${index}`,
        upstream: config.upstreamUrl,
        publicBaseUrl: config.publicBaseUrl,
        facilitatorUrl: target.facilitatorUrl,
        payTo: target.payTo,
        network: target.network,
        asset: target.asset,
        price: target.defaultPrice,
        state: config.state,
        routes: config.routes?.length
          ? config.routes.map((route) => ({ path: route.path, methods: route.methods, price: route.price }))
          : [{ path: '/*', methods: config.allowedMethods }],
      },
      requiredSecretRefs: ['DATABASE_URL', 'GATEWAY_MANAGEMENT_TOKEN'],
      environmentVariables: {
        GATEWAY_TENANT_ID: tenantId,
        GATEWAY_APP_ID: appId,
        GATEWAY_ENVIRONMENT: environment,
        PLATFORM_EVENT_URL: '/v1/platform-events',
      },
    }));
  }

  async createChargeAuthorization(tenantId: string, authorization: ChargeAuthorizationData): Promise<WorkspaceResource> {
    validateChargeAuthorization(tenantId, authorization);
    const { updatedBy: _updatedBy, ...signedAuthorization } = authorization;
    if (!await verifyChargeAuthorizationSignature(signedAuthorization as ChargeAuthorization)) {
      throw new Error('Charge authorization signature is invalid');
    }
    return this.queueMutation(() => {
      if (this._workspaceResources.some((resource) => resource.tenantId === tenantId
        && resource.resourceType === 'charge_authorization'
        && (resource.data.nonce === authorization.nonce
          || resource.data.authorizationId === authorization.authorizationId))) {
        throw new Error('Charge authorization nonce or ID already used');
      }
      const now = Date.now();
      const resource: WorkspaceResource = {
        id: `wr_${randomBytes(12).toString('hex')}`,
        tenantId,
        resourceType: 'charge_authorization',
        name: authorization.authorizationId,
        status: 'active',
        data: authorization as unknown as Record<string, unknown>,
        tags: ['charge-authorization', authorization.appId, authorization.environment, authorization.chain],
        createdBy: authorization.updatedBy,
        updatedBy: authorization.updatedBy,
        reviewStatus: authorization.environment === 'live' ? 'review_required' : 'unreviewed',
        version: 1,
        resourceVersion: { version: 1, updatedAt: now, updatedBy: authorization.updatedBy },
        createdAt: now,
        updatedAt: now,
      };
      this._workspaceResources.push(resource);
      return clone(resource);
    });
  }

  async consumeChargeAuthorization(
    tenantId: string,
    appId: string,
    authorizationId: string,
    quoteId: string,
    termsHash: string,
    environment: 'test' | 'live',
    chain: string,
    chargeAsset: string,
    maximumCharge: string,
    payer: string,
    nonce: string,
    expiresAt: string,
    recurring: boolean,
    refundPolicyHash: string,
    signatureAlgorithm: 'ed25519',
    signerPublicKey: string,
    signature: string,
    executionId: string,
    consumedBy: string,
  ): Promise<WorkspaceResource> {
    return this.queueMutation(() => {
      const resource = this._workspaceResources.find((candidate) =>
        candidate.tenantId === tenantId
        && candidate.resourceType === 'charge_authorization'
        && candidate.status === 'active'
        && candidate.data.authorizationId === authorizationId
      );
      if (!resource
        || resource.data.appId !== appId
        || resource.data.quoteId !== quoteId
        || resource.data.termsHash !== termsHash
        || resource.data.environment !== environment
        || resource.data.chain !== chain
        || resource.data.chargeAsset !== chargeAsset
        || resource.data.maximumCharge !== maximumCharge
        || resource.data.payer !== payer
        || resource.data.nonce !== nonce
        || resource.data.expiresAt !== expiresAt
        || resource.data.recurring !== recurring
        || resource.data.refundPolicyHash !== refundPolicyHash
        || resource.data.signatureAlgorithm !== signatureAlgorithm
        || resource.data.signerPublicKey !== signerPublicKey
        || resource.data.signature !== signature) {
        throw new Error('Charge authorization scope mismatch');
      }
      if (resource.data.consumedExecutionId === executionId) return clone(resource);
      if (resource.data.consumedAt && resource.data.recurring !== true) throw new Error('Charge authorization already consumed');
      if (Date.parse(String(resource.data.expiresAt)) <= Date.now()) throw new Error('Charge authorization expired');
      resource.data = { ...resource.data, consumedAt: Date.now(), consumedBy, consumedExecutionId: executionId };
      resource.updatedBy = consumedBy;
      resource.version += 1;
      resource.updatedAt = Date.now();
      resource.resourceVersion = { version: resource.version, updatedAt: resource.updatedAt, updatedBy: consumedBy };
      return clone(resource);
    });
  }

  async listTeamInvitations(tenantId: string, appId: string): Promise<WorkspaceResource[]> {
    const now = Date.now();
    return (await this.listWorkspaceResources({ tenantId, resourceType: 'team_invitation' }))
      .filter((resource) => resource.data.appId === appId)
      .map((resource) => {
        if (resource.data.status === 'pending' && Date.parse(String(resource.data.expiresAt)) <= now) {
          return { ...resource, data: { ...resource.data, status: 'expired' } };
        }
        return resource;
      });
  }

  async createTeamInvitation(
    tenantId: string,
    appId: string,
    email: string,
    role: TeamInvitationData['role'],
    invitedBy: string,
  ): Promise<WorkspaceResource> {
    const normalizedEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(normalizedEmail)) throw new Error('Valid invitation email required');
    if (!['admin', 'operator', 'developer', 'viewer'].includes(role)) throw new Error('Invalid invitation role');
    return this.queueMutation(() => {
      const duplicate = this._workspaceResources.some((resource) =>
        resource.tenantId === tenantId
        && resource.resourceType === 'team_invitation'
        && resource.data.appId === appId
        && resource.data.email === normalizedEmail
        && resource.data.status === 'pending'
        && Date.parse(String(resource.data.expiresAt)) > Date.now()
      );
      if (duplicate) throw new Error('A pending invitation already exists for this email');
      const now = Date.now();
      const data: TeamInvitationData = {
        schemaVersion: 'veridex.team-invitation/v1',
        appId,
        email: normalizedEmail,
        role,
        status: 'pending',
        expiresAt: new Date(now + 7 * 24 * 60 * 60 * 1_000).toISOString(),
        invitedBy,
      };
      const resource: WorkspaceResource = {
        id: `wr_${randomBytes(12).toString('hex')}`,
        tenantId,
        resourceType: 'team_invitation',
        name: normalizedEmail,
        status: 'active',
        data: data as unknown as Record<string, unknown>,
        tags: ['team-invitation', appId, role],
        createdBy: invitedBy,
        updatedBy: invitedBy,
        reviewStatus: role === 'admin' ? 'review_required' : 'auto_accepted',
        version: 1,
        resourceVersion: { version: 1, updatedAt: now, updatedBy: invitedBy },
        createdAt: now,
        updatedAt: now,
      };
      this._workspaceResources.push(resource);
      return clone(resource);
    });
  }

  async revokeTeamInvitation(
    tenantId: string,
    appId: string,
    invitationId: string,
    revokedBy: string,
  ): Promise<WorkspaceResource | undefined> {
    return this.queueMutation(() => {
      const resource = this._workspaceResources.find((candidate) =>
        candidate.id === invitationId
        && candidate.tenantId === tenantId
        && candidate.resourceType === 'team_invitation'
        && candidate.data.appId === appId
      );
      if (!resource) return undefined;
      resource.data = { ...resource.data, status: 'revoked', revokedAt: new Date().toISOString(), revokedBy };
      resource.status = 'archived';
      resource.updatedBy = revokedBy;
      resource.version += 1;
      resource.updatedAt = Date.now();
      resource.resourceVersion = { version: resource.version, updatedAt: resource.updatedAt, updatedBy: revokedBy };
      return clone(resource);
    });
  }

  async listPaymentResources(tenantId: string, appId: string, environment?: 'test' | 'live') {
    return (await this.listWorkspaceResources({ tenantId, resourceType: 'payment_resource' }))
      .filter((resource) => resource.data.appId === appId
        && (environment === undefined || resource.data.environment === environment));
  }

  async createPaymentResource(tenantId: string, resource: PaymentResourceData): Promise<WorkspaceResource> {
    validatePaymentResource(resource);
    return this.createWorkspaceResource({
      tenantId,
      resourceType: 'payment_resource',
      name: resource.name,
      status: 'active',
      data: resource as unknown as Record<string, unknown>,
      tags: ['payment-resource', resource.appId, resource.environment, resource.network, resource.bazaarStatus],
      createdBy: resource.updatedBy,
      updatedBy: resource.updatedBy,
      reviewStatus: resource.environment === 'live' ? 'review_required' : 'unreviewed',
    });
  }

  async publishPaymentResource(tenantId: string, appId: string, resourceId: string, updatedBy: string) {
    const resource = await this.getWorkspaceResource(resourceId, tenantId);
    if (!resource || resource.resourceType !== 'payment_resource' || resource.data.appId !== appId) return undefined;
    const data = { ...resource.data, bazaarStatus: 'published', updatedBy };
    return this.updateWorkspaceResource(resourceId, {
      data,
      tags: (resource.tags ?? []).filter((tag) => tag !== 'draft').concat('published'),
      updatedBy,
      reviewStatus: resource.data.environment === 'live' ? 'review_required' : 'auto_accepted',
    }, tenantId);
  }

  async ingestPaymentProjection(tenantId: string, projection: PaymentProjectionData): Promise<WorkspaceResource> {
    if (projection.tenantId !== tenantId) throw new Error('Payment projection tenant mismatch');
    if (!projection.eventId || !projection.appId || !Number.isFinite(Date.parse(projection.occurredAt))) {
      throw new Error('Payment projection identity is invalid');
    }
    const existing = (await this.listWorkspaceResources({ tenantId, resourceType: 'payment_projection' }))
      .find((resource) => resource.data.eventId === projection.eventId);
    if (existing) return existing;
    return this.createWorkspaceResource({
      tenantId,
      resourceType: 'payment_projection',
      name: projection.eventId,
      status: 'active',
      data: projection as unknown as Record<string, unknown>,
      tags: ['payment', projection.appId, projection.environment, projection.eventType],
      createdBy: 'platform-event-consumer',
      reviewStatus: 'auto_accepted',
    });
  }

  async listPaymentProjections(tenantId: string, appId: string) {
    return (await this.listWorkspaceResources({ tenantId, resourceType: 'payment_projection' }))
      .filter((resource) => resource.data.appId === appId)
      .sort((left, right) => String(right.data.occurredAt).localeCompare(String(left.data.occurredAt)));
  }

  async updateWorkspaceResource(
    id: string,
    updates: Partial<Pick<WorkspaceResource, 'name' | 'status' | 'data' | 'tags' | 'metadata' | 'updatedBy' | 'reviewStatus' | 'evidenceRefs' | 'confidence'>>,
    tenantId?: string,
  ): Promise<WorkspaceResource | undefined> {
    return this.queueMutation(() => {
      const resource = this._workspaceResources.find((r) =>
        r.id === id && (!tenantId || r.tenantId === tenantId)
      );
      if (!resource) return undefined;
      Object.assign(resource, updates);
      resource.version += 1;
      resource.updatedAt = Date.now();
      resource.resourceVersion = {
        version: resource.version,
        updatedAt: resource.updatedAt,
        updatedBy: updates.updatedBy ?? resource.updatedBy,
      };
      if (updates.updatedBy) {
        resource.updatedBy = updates.updatedBy;
      }
      return clone(resource);
    });
  }

  async deleteWorkspaceResource(id: string, tenantId?: string): Promise<boolean> {
    return this.queueMutation(() => {
      const idx = this._workspaceResources.findIndex((r) =>
        r.id === id && (!tenantId || r.tenantId === tenantId)
      );
      if (idx === -1) return false;
      this._workspaceResources.splice(idx, 1);
      return true;
    });
  }

  // ── Task CRUD ──

  async createTask(
    options: Omit<Task, 'id' | 'createdAt' | 'updatedAt'>,
  ): Promise<Task> {
    return this.queueMutation(() => {
      const now = Date.now();
      const task: Task = {
        ...options,
        id: `task_${randomBytes(12).toString('hex')}`,
        version: options.version ?? 1,
        createdAt: now,
        updatedAt: now,
      };
      this._tasks.push(task);
      return clone(task);
    });
  }

  async getTask(id: string): Promise<Task | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const task = this._tasks.find((t) => t.id === id);
    return task ? clone(task) : undefined;
  }

  async listTasks(
    filter?: { status?: Task['status']; priority?: Task['priority']; assigneeId?: string },
  ): Promise<Task[]> {
    await this.ensureReady();
    await this.refreshState();
    let list = this._tasks;
    if (filter?.status) {
      list = list.filter((t) => t.status === filter.status);
    }
    if (filter?.priority) {
      list = list.filter((t) => t.priority === filter.priority);
    }
    if (filter?.assigneeId) {
      list = list.filter((t) => t.assigneeId === filter.assigneeId);
    }
    return list.map((t) => clone(t));
  }

  async updateTask(
    id: string,
    updates: Partial<Pick<Task, 'title' | 'description' | 'status' | 'priority' | 'assigneeId' | 'output' | 'error' | 'tags' | 'metadata' | 'completedAt'>>,
  ): Promise<Task | undefined> {
    return this.queueMutation(() => {
      const task = this._tasks.find((t) => t.id === id);
      if (!task) return undefined;
      Object.assign(task, updates);
      task.updatedAt = Date.now();
      task.version = (task.version ?? 1) + 1;
      return clone(task);
    });
  }

  // ── Assignment CRUD ──

  async createAssignment(
    options: Omit<Assignment, 'id' | 'createdAt' | 'updatedAt'>,
  ): Promise<Assignment> {
    return this.queueMutation(() => {
      const now = Date.now();
      const assignment: Assignment = {
        ...options,
        id: `asg_${randomBytes(12).toString('hex')}`,
        createdAt: now,
        updatedAt: now,
      };
      this._assignments.push(assignment);
      return clone(assignment);
    });
  }

  async getAssignment(id: string): Promise<Assignment | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const assignment = this._assignments.find((entry) => entry.id === id);
    return assignment ? clone(assignment) : undefined;
  }

  async listAssignments(filter?: {
    taskId?: string;
    assigneeId?: string;
    status?: Assignment['status'];
    workspaceId?: string;
  }): Promise<Assignment[]> {
    await this.ensureReady();
    await this.refreshState();
    let list = this._assignments;
    if (filter?.taskId) {
      list = list.filter((entry) => entry.taskId === filter.taskId);
    }
    if (filter?.assigneeId) {
      list = list.filter((entry) => entry.assigneeId === filter.assigneeId);
    }
    if (filter?.status) {
      list = list.filter((entry) => entry.status === filter.status);
    }
    if (filter?.workspaceId) {
      list = list.filter((entry) => entry.workspaceId === filter.workspaceId);
    }
    return list.map((entry) => clone(entry));
  }

  async updateAssignment(
    id: string,
    updates: Partial<Pick<Assignment, 'status' | 'leaseOwner' | 'leaseExpiresAt' | 'retryCount' | 'metadata' | 'completedAt'>>,
  ): Promise<Assignment | undefined> {
    return this.queueMutation(() => {
      const assignment = this._assignments.find((entry) => entry.id === id);
      if (!assignment) return undefined;
      Object.assign(assignment, updates);
      assignment.updatedAt = Date.now();
      return clone(assignment);
    });
  }

  async deleteAssignment(id: string): Promise<boolean> {
    return this.queueMutation(() => {
      const idx = this._assignments.findIndex((entry) => entry.id === id);
      if (idx === -1) return false;
      this._assignments.splice(idx, 1);
      return true;
    });
  }

  // ── Deployment Revision CRUD ──

  async createDeploymentRevision(
    options: Omit<DeploymentRevision, 'id' | 'createdAt'>,
  ): Promise<DeploymentRevision> {
    return this.queueMutation(() => {
      const revision: DeploymentRevision = {
        ...options,
        id: `dr_${randomBytes(12).toString('hex')}`,
        version: options.version ?? 1,
        createdAt: Date.now(),
      };
      this._deploymentRevisions.push(revision);
      return clone(revision);
    });
  }

  async getDeploymentRevision(id: string): Promise<DeploymentRevision | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const revision = this._deploymentRevisions.find((r) => r.id === id);
    return revision ? clone(revision) : undefined;
  }

  async listDeploymentRevisions(agentManifestId?: string): Promise<DeploymentRevision[]> {
    await this.ensureReady();
    await this.refreshState();
    const list = agentManifestId
      ? this._deploymentRevisions.filter((r) => r.agentManifestId === agentManifestId)
      : this._deploymentRevisions;
    return list.map((r) => clone(r));
  }

  async updateDeploymentRevision(
    id: string,
    updates: Partial<Pick<DeploymentRevision, 'status' | 'activatedAt' | 'rolledBackAt' | 'metadata'>>,
  ): Promise<DeploymentRevision | undefined> {
    return this.queueMutation(() => {
      const revision = this._deploymentRevisions.find((r) => r.id === id);
      if (!revision) return undefined;
      Object.assign(revision, updates);
      revision.version = (revision.version ?? 1) + 1;
      return clone(revision);
    });
  }

  // ── Incident CRUD ──

  async createIncident(
    options: Omit<Incident, 'id' | 'createdAt' | 'updatedAt'>,
  ): Promise<Incident> {
    return this.queueMutation(() => {
      const now = Date.now();
      const incident: Incident = {
        ...options,
        id: `inc_${randomBytes(12).toString('hex')}`,
        version: options.version ?? 1,
        createdAt: now,
        updatedAt: now,
      };
      this._incidents.push(incident);
      return clone(incident);
    });
  }

  async getIncident(id: string): Promise<Incident | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const incident = this._incidents.find((i) => i.id === id);
    return incident ? clone(incident) : undefined;
  }

  async listIncidents(
    filter?: { severity?: Incident['severity']; status?: Incident['status'] },
  ): Promise<Incident[]> {
    await this.ensureReady();
    await this.refreshState();
    let list = this._incidents;
    if (filter?.severity) {
      list = list.filter((i) => i.severity === filter.severity);
    }
    if (filter?.status) {
      list = list.filter((i) => i.status === filter.status);
    }
    return list.map((i) => clone(i));
  }

  async updateIncident(
    id: string,
    updates: Partial<Pick<Incident, 'title' | 'description' | 'severity' | 'status' | 'assigneeId' | 'tags' | 'metadata' | 'resolvedAt'>>,
  ): Promise<Incident | undefined> {
    return this.queueMutation(() => {
      const incident = this._incidents.find((i) => i.id === id);
      if (!incident) return undefined;
      Object.assign(incident, updates);
      incident.updatedAt = Date.now();
      incident.version = (incident.version ?? 1) + 1;
      return clone(incident);
    });
  }

  // ── Eval Suite CRUD ──

  async createEvalSuite(
    options: Omit<EvalSuite, 'id' | 'createdAt' | 'updatedAt'>,
  ): Promise<EvalSuite> {
    return this.queueMutation(() => {
      const now = Date.now();
      const suite: EvalSuite = {
        ...options,
        id: `es_${randomBytes(12).toString('hex')}`,
        version: options.version ?? 1,
        createdAt: now,
        updatedAt: now,
      };
      this._evalSuites.push(suite);
      return clone(suite);
    });
  }

  async getEvalSuite(id: string): Promise<EvalSuite | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const suite = this._evalSuites.find((s) => s.id === id);
    return suite ? clone(suite) : undefined;
  }

  async listEvalSuites(): Promise<EvalSuite[]> {
    await this.ensureReady();
    await this.refreshState();
    return this._evalSuites.map((s) => clone(s));
  }

  // ── Eval Run CRUD ──

  async createEvalRun(
    options: Omit<EvalRun, 'id' | 'createdAt'>,
  ): Promise<EvalRun> {
    return this.queueMutation(() => {
      const run: EvalRun = {
        ...options,
        id: `er_${randomBytes(12).toString('hex')}`,
        version: options.version ?? 1,
        createdAt: Date.now(),
      };
      this._evalRuns.push(run);
      return clone(run);
    });
  }

  async getEvalRun(id: string): Promise<EvalRun | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const run = this._evalRuns.find((r) => r.id === id);
    return run ? clone(run) : undefined;
  }

  async listEvalRuns(suiteId?: string): Promise<EvalRun[]> {
    await this.ensureReady();
    await this.refreshState();
    const list = suiteId
      ? this._evalRuns.filter((r) => r.suiteId === suiteId)
      : this._evalRuns;
    return list.map((r) => clone(r));
  }

  async updateEvalRun(
    id: string,
    updates: Partial<Pick<EvalRun, 'status' | 'passed' | 'failed' | 'errored' | 'total' | 'results' | 'metadata' | 'completedAt'>>,
  ): Promise<EvalRun | undefined> {
    return this.queueMutation(() => {
      const run = this._evalRuns.find((r) => r.id === id);
      if (!run) return undefined;
      Object.assign(run, updates);
      run.version = (run.version ?? 1) + 1;
      return clone(run);
    });
  }

  // ── Policy Binding CRUD ──

  async createPolicyBinding(
    options: Omit<PolicyBinding, 'id' | 'createdAt'>,
  ): Promise<PolicyBinding> {
    return this.queueMutation(() => {
      const binding: PolicyBinding = {
        ...options,
        id: `pb_${randomBytes(12).toString('hex')}`,
        createdAt: Date.now(),
      };
      this._policyBindings.push(binding);
      return clone(binding);
    });
  }

  async listPolicyBindings(
    filter?: { targetType?: PolicyBinding['targetType']; targetId?: string; policyPackId?: string },
  ): Promise<PolicyBinding[]> {
    await this.ensureReady();
    await this.refreshState();
    let list = this._policyBindings;
    if (filter?.targetType) {
      list = list.filter((b) => b.targetType === filter.targetType);
    }
    if (filter?.targetId) {
      list = list.filter((b) => b.targetId === filter.targetId);
    }
    if (filter?.policyPackId) {
      list = list.filter((b) => b.policyPackId === filter.policyPackId);
    }
    return list.map((b) => clone(b));
  }

  async removePolicyBinding(id: string): Promise<boolean> {
    return this.queueMutation(() => {
      const idx = this._policyBindings.findIndex((b) => b.id === id);
      if (idx === -1) return false;
      this._policyBindings.splice(idx, 1);
      return true;
    });
  }

  // ── Maintenance Job CRUD ──

  async createMaintenanceJob(
    options: Omit<MaintenanceJob, 'id' | 'createdAt' | 'updatedAt'>,
  ): Promise<MaintenanceJob> {
    return this.queueMutation(() => {
      const now = Date.now();
      const job: MaintenanceJob = {
        ...options,
        id: `job_${randomBytes(12).toString('hex')}`,
        createdAt: now,
        updatedAt: now,
      };
      this._maintenanceJobs.push(job);
      return clone(job);
    });
  }

  async getMaintenanceJob(id: string): Promise<MaintenanceJob | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const job = this._maintenanceJobs.find((entry) => entry.id === id);
    return job ? clone(job) : undefined;
  }

  async listMaintenanceJobs(filter?: {
    workspaceId?: string;
    status?: MaintenanceJob['status'];
    jobType?: MaintenanceJob['jobType'];
  }): Promise<MaintenanceJob[]> {
    await this.ensureReady();
    await this.refreshState();
    let list = this._maintenanceJobs;
    if (filter?.workspaceId) {
      list = list.filter((entry) => entry.workspaceId === filter.workspaceId);
    }
    if (filter?.status) {
      list = list.filter((entry) => entry.status === filter.status);
    }
    if (filter?.jobType) {
      list = list.filter((entry) => entry.jobType === filter.jobType);
    }
    return list.map((entry) => clone(entry));
  }

  async updateMaintenanceJob(
    id: string,
    updates: Partial<Pick<MaintenanceJob, 'status' | 'metadata' | 'completedAt' | 'schedule'>>,
  ): Promise<MaintenanceJob | undefined> {
    return this.queueMutation(() => {
      const job = this._maintenanceJobs.find((entry) => entry.id === id);
      if (!job) return undefined;
      Object.assign(job, updates);
      job.updatedAt = Date.now();
      return clone(job);
    });
  }

  async deleteMaintenanceJob(id: string): Promise<boolean> {
    return this.queueMutation(() => {
      const idx = this._maintenanceJobs.findIndex((entry) => entry.id === id);
      if (idx === -1) return false;
      this._maintenanceJobs.splice(idx, 1);
      return true;
    });
  }

  // ── Resource Mutation Review ──

  async proposeResourceMutation(
    options: Omit<ResourceMutationProposal, 'id' | 'status' | 'decisions' | 'createdAt' | 'updatedAt'>,
  ): Promise<ResourceMutationProposal> {
    return this.queueMutation(() => {
      const now = Date.now();
      const proposal: ResourceMutationProposal = {
        ...options,
        id: `rmp_${randomBytes(12).toString('hex')}`,
        status: 'pending',
        decisions: [],
        createdAt: now,
        updatedAt: now,
      };
      this._resourceMutationProposals.push(proposal);
      return clone(proposal);
    });
  }

  async getResourceMutationProposal(id: string): Promise<ResourceMutationProposal | undefined> {
    await this.ensureReady();
    await this.refreshState();
    const proposal = this._resourceMutationProposals.find((entry) => entry.id === id);
    return proposal ? clone(proposal) : undefined;
  }

  async listResourceMutationProposals(filter?: {
    workspaceId?: string;
    resourceType?: string;
    status?: ResourceMutationProposal['status'];
  }): Promise<ResourceMutationProposal[]> {
    await this.ensureReady();
    await this.refreshState();
    let list = this._resourceMutationProposals;
    if (filter?.workspaceId) {
      list = list.filter((entry) => entry.workspaceId === filter.workspaceId);
    }
    if (filter?.resourceType) {
      list = list.filter((entry) => entry.resourceType === filter.resourceType);
    }
    if (filter?.status) {
      list = list.filter((entry) => entry.status === filter.status);
    }
    return list.map((entry) => clone(entry));
  }

  async decideResourceMutation(
    id: string,
    decision: Omit<MutationDecision, 'id' | 'proposalId' | 'createdAt'>,
  ): Promise<ResourceMutationProposal | undefined> {
    return this.queueMutation(() => {
      const proposal = this._resourceMutationProposals.find((entry) => entry.id === id);
      if (!proposal) return undefined;

      const mutationDecision = {
        ...decision,
        id: `md_${randomBytes(12).toString('hex')}`,
        proposalId: id,
        createdAt: Date.now(),
      };
      proposal.decisions.push(mutationDecision);
      proposal.status = decision.verdict === 'approved'
        ? 'approved'
        : decision.verdict === 'rejected'
          ? 'rejected'
          : 'pending';
      proposal.updatedAt = Date.now();

      if (decision.verdict === 'approved') {
        if (proposal.operation === 'create') {
          const now = Date.now();
          this._workspaceResources.push({
            id: proposal.resourceId ?? `wr_${randomBytes(12).toString('hex')}`,
            tenantId: proposal.tenantId,
            workspaceId: proposal.workspaceId,
            resourceType: proposal.resourceType,
            name: String(proposal.payload?.name ?? proposal.resourceType),
            status: 'active',
            version: 1,
            resourceVersion: {
              version: 1,
              updatedAt: now,
              updatedBy: decision.decidedBy,
              proposalId: proposal.id,
            },
            data: { ...(proposal.payload ?? {}) },
            metadata: proposal.metadata ? { ...proposal.metadata } : undefined,
            createdAt: now,
            updatedAt: now,
            createdBy: proposal.proposedBy,
            updatedBy: decision.decidedBy,
            reviewStatus: 'approved',
          });
        } else if (proposal.resourceId) {
          const resource = this._workspaceResources.find((entry) => entry.id === proposal.resourceId);
          if (resource) {
            if (proposal.expectedVersion !== undefined && resource.version !== proposal.expectedVersion) {
              proposal.status = 'rejected';
              proposal.decisions.push({
                id: `md_${randomBytes(12).toString('hex')}`,
                proposalId: id,
                decidedBy: 'system',
                verdict: 'rejected',
                reason: `Expected resource version ${proposal.expectedVersion}, found ${resource.version}`,
                createdAt: Date.now(),
              });
              return clone(proposal);
            }

            if (proposal.operation === 'delete') {
              resource.status = 'deleted';
            } else if (proposal.payload) {
              resource.data = { ...resource.data, ...proposal.payload };
              if (typeof proposal.payload.name === 'string') {
                resource.name = proposal.payload.name;
              }
            }
            resource.version += 1;
            resource.updatedAt = Date.now();
            resource.updatedBy = decision.decidedBy;
            resource.reviewStatus = 'approved';
            resource.resourceVersion = {
              version: resource.version,
              updatedAt: resource.updatedAt,
              updatedBy: decision.decidedBy,
              proposalId: proposal.id,
            };
          }
        }

        proposal.status = 'applied';
      }

      return clone(proposal);
    });
  }

  // ── Health & Lifecycle ──

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

function validateSponsorshipPolicy(policy: SponsorshipPolicyData): void {
  if (policy.schemaVersion !== 'veridex.sponsorship-policy/v1') throw new Error('Unsupported sponsorship policy version');
  for (const [field, value] of [
    ['perTransactionLimit', policy.perTransactionLimit],
    ['dailyLimit', policy.dailyLimit],
    ['monthlyLimit', policy.monthlyLimit],
  ] as const) {
    if (!/^(0|[1-9]\d*)$/.test(value)) throw new Error(`${field} must be a canonical atomic amount`);
  }
  if (!Number.isInteger(policy.subsidyBps) || policy.subsidyBps < 0 || policy.subsidyBps > 10_000) {
    throw new Error('subsidyBps must be between 0 and 10000');
  }
  if (!Number.isInteger(policy.markupBps) || policy.markupBps < 0 || policy.markupBps > 10_000) {
    throw new Error('markupBps must be between 0 and 10000');
  }
  if ((policy.mode === 'user_reimburses' || policy.mode === 'hybrid') && !policy.requireUserAuthorization) {
    throw new Error('User reimbursement requires explicit user authorization');
  }
}

function validateGatewayConfig(config: GatewayConfigData): void {
  if (config.schemaVersion !== 'veridex.gateway-config/v1') throw new Error('Unsupported gateway config version');
  if (!config.appId || !config.name.trim()) throw new Error('Gateway appId and name are required');
  if (config.targets.length === 0 || config.targets.some((target) => !/^[-a-z0-9]{3,12}:[-_a-zA-Z0-9.]{1,64}$/.test(target.network))) {
    throw new Error('Gateway targets must use valid network identifiers');
  }
  if (config.schemes.length === 0 || config.allowedMethods.length === 0) {
    throw new Error('Gateway schemes and allowedMethods are required');
  }
  let upstream: URL;
  let publicBase: URL;
  try {
    upstream = new URL(config.upstreamUrl);
    publicBase = new URL(config.publicBaseUrl);
  } catch {
    throw new Error('Gateway upstreamUrl and publicBaseUrl must be valid URLs');
  }
  if (upstream.protocol !== 'https:' && !(config.environment === 'test' && upstream.protocol === 'http:')) {
    throw new Error('Gateway upstreamUrl must use HTTPS outside test environments');
  }
  if (publicBase.protocol !== 'https:' && !(config.environment === 'test' && publicBase.protocol === 'http:')) {
    throw new Error('Gateway publicBaseUrl must use HTTPS outside test environments');
  }
  for (const target of config.targets) {
    if (!target.payTo || !target.asset || !/^[1-9]\d*$/.test(target.defaultPrice)) {
      throw new Error('Gateway targets require payTo, asset, and a positive atomic defaultPrice');
    }
    const facilitator = new URL(target.facilitatorUrl);
    if (facilitator.protocol !== 'https:' && !(config.environment === 'test' && facilitator.protocol === 'http:')) {
      throw new Error('Gateway facilitatorUrl must use HTTPS outside test environments');
    }
  }
}

function validateChargeAuthorization(tenantId: string, authorization: ChargeAuthorizationData): void {
  if (authorization.schemaVersion !== 'veridex.charge-authorization/v1') throw new Error('Unsupported charge authorization version');
  if (authorization.tenantId !== tenantId) throw new Error('Charge authorization tenant mismatch');
  if (!authorization.appId || !authorization.authorizationId || !authorization.quoteId || !authorization.payer) {
    throw new Error('Charge authorization identity fields are required');
  }
  if (!/^(0|[1-9]\d*)$/.test(authorization.maximumCharge)) throw new Error('maximumCharge must be a canonical atomic amount');
  if (!authorization.nonce || !authorization.signature) throw new Error('Charge authorization nonce and signature are required');
  if (authorization.signatureAlgorithm !== 'ed25519' || !authorization.signerPublicKey) {
    throw new Error('Charge authorization signature metadata is required');
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(authorization.termsHash)
    || !/^0x[0-9a-fA-F]{64}$/.test(authorization.refundPolicyHash)) {
    throw new Error('Charge authorization hashes must be bytes32 hex');
  }
  if (Date.parse(authorization.expiresAt) <= Date.now()) throw new Error('Charge authorization expired');
}

function validatePaymentResource(resource: PaymentResourceData): void {
  if (resource.schemaVersion !== 'veridex.payment-resource/v1') throw new Error('Unsupported payment resource version');
  if (!resource.appId || !resource.gatewayId || !resource.name || !resource.path.startsWith('/')) {
    throw new Error('Payment resource identity and path are required');
  }
  if (!/^[1-9]\d*$/.test(resource.amount)) throw new Error('Payment resource amount must be a positive atomic amount');
  if (!resource.network.includes(':') || !resource.asset || !resource.payTo || resource.methods.length === 0) {
    throw new Error('Payment resource network, asset, payTo and methods are required');
  }
}

/**
 * @module ControlPlaneTypes
 * @description
 * Type definitions for the Veridex control plane — policy packs,
 * trace retention, tenant governance, deployment policy.
 */

// ── Tenant and Deployment ──

/** A tenant in the multi-tenant control plane. */
export interface Tenant {
  /** Unique tenant identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Tenant status */
  status: 'active' | 'suspended' | 'pending';
  /** Tenant configuration */
  config: TenantConfig;
  /** Metadata */
  metadata?: Record<string, unknown>;
  /** Creation timestamp */
  createdAt: number;
}

/** Tenant-level configuration. */
export interface TenantConfig {
  /** Maximum concurrent agent runs */
  maxConcurrentRuns?: number;
  /** Daily spending limit in USD */
  dailySpendLimitUSD?: number;
  /** Allowed model providers */
  allowedProviders?: string[];
  /** Whether audit export is enabled */
  auditEnabled?: boolean;
  /** Trace retention days */
  traceRetentionDays?: number;
  /** Deployment mode */
  deploymentMode?: DeploymentMode;
}

// ── Workspace ──

/** A workspace scoped beneath a tenant. */
export interface Workspace {
  /** Unique workspace identifier */
  id: string;
  /** Parent tenant */
  tenantId?: string;
  /** Human-readable name */
  name: string;
  /** Lifecycle status */
  status: 'active' | 'suspended' | 'archived';
  /** Optional description */
  description?: string;
  /** Workspace configuration */
  config?: Record<string, unknown>;
  /** Metadata */
  metadata?: Record<string, unknown>;
  /** Creation timestamp */
  createdAt: number;
  /** Last update timestamp */
  updatedAt: number;
}

/** Supported deployment modes. */
export type DeploymentMode =
  | 'local'
  | 'self-hosted'
  | 'private-cloud'
  | 'managed';

/** Access roles for remote control-plane operators and services. */
export type ControlPlaneRole =
  | 'admin'
  | 'operator'
  | 'approver'
  | 'viewer';

// ── Policy Packs ──

/** A policy pack — a named set of policy rules that can be applied to tenants/agents. */
export interface PolicyPack {
  /** Unique pack identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description of what this policy pack enforces */
  description: string;
  /** Policy pack version */
  version: string;
  /** The serialized policy rules in this pack */
  rules: PolicyRuleDefinition[];
  /** Tags for categorization */
  tags?: string[];
  /** Whether this pack is immutable (system-defined) */
  immutable?: boolean;
  /** Creation timestamp */
  createdAt: number;
  /** Last updated timestamp */
  updatedAt: number;
}

/** A serializable policy rule definition for storage/transport. */
export interface PolicyRuleDefinition {
  /** Rule type identifier */
  type: string;
  /** Rule parameters */
  params: Record<string, unknown>;
  /** Whether this rule is enabled */
  enabled: boolean;
  /** Description */
  description?: string;
}

// ── Trace Retention ──

/** A stored trace record for a completed run. */
export interface TraceRecord {
  /** Unique trace ID */
  id: string;
  /** Run ID */
  runId: string;
  /** Agent ID */
  agentId: string;
  /** Tenant ID (if multi-tenant) */
  tenantId?: string;
  /** Run start timestamp */
  startedAt: number;
  /** Run end timestamp */
  completedAt?: number;
  /** Final run state */
  state: 'completed' | 'failed' | 'cancelled';
  /** Number of turns */
  turnCount: number;
  /** Total tokens used */
  totalTokens: number;
  /** Total cost in USD (estimated) */
  totalCostUSD?: number;
  /** Serialized trace events */
  events: unknown[];
  /** Content hash for integrity */
  contentHash?: string;
  /** Metadata */
  metadata?: Record<string, unknown>;
}

/** Query filters for trace retention store. */
export interface TraceQuery {
  /** Filter by run ID */
  runId?: string;
  /** Filter by agent ID */
  agentId?: string;
  /** Filter by tenant ID */
  tenantId?: string;
  /** Filter by state */
  state?: TraceRecord['state'];
  /** Start time range (epoch ms) */
  startAfter?: number;
  /** End time range (epoch ms) */
  startBefore?: number;
  /** Maximum results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

// ── Approval Workflows ──

/** An approval workflow definition for enterprise use. */
export interface ApprovalWorkflow {
  /** Unique workflow ID */
  id: string;
  /** Workflow name */
  name: string;
  /** Description */
  description: string;
  /** Escalation chain — ordered list of approver groups */
  escalationChain: ApprovalEscalationStep[];
  /** Auto-approve after timeout (seconds), or null for no auto-approve */
  autoApproveAfterSeconds?: number;
  /** Default mode when no escalation matches */
  defaultMode: 'block' | 'flag' | 'auto-approve';
}

/** A step in an escalation chain. */
export interface ApprovalEscalationStep {
  /** Step name */
  name: string;
  /** Approver identifiers (user IDs, group names, etc.) */
  approvers: string[];
  /** Timeout before escalating to next step (seconds) */
  timeoutSeconds: number;
  /** Minimum approvals required at this step */
  minApprovals: number;
}

// ── Evidence Bundles ──

/** An evidence bundle — cryptographically attestable record of a run. */
export interface EvidenceBundle {
  /** Bundle ID */
  id: string;
  /** Associated run ID */
  runId: string;
  /** Bundle version format */
  version: string;
  /** SHA-256 hash of the trace events */
  traceHash: string;
  /** SHA-256 hash of policy decisions */
  policyHash: string;
  /** SHA-256 hash of approval decisions */
  approvalHash: string;
  /** Combined content hash */
  contentHash: string;
  /** Optional signature (if attested) */
  signature?: string;
  /** Signer identity */
  signedBy?: string;
  /** Generated timestamp */
  generatedAt: number;
  /** The trace record reference */
  traceId: string;
  /** Policy decisions included */
  policyDecisions: unknown[];
  /** Approval decisions included */
  approvalDecisions: unknown[];
}

// ── Service Auth and Remote Deployment ──

/** Persisted API token metadata for remote control-plane access. */
export interface ControlPlaneAuthToken {
  /** Unique token identifier */
  id: string;
  /** Human-readable token name */
  name: string;
  /** SHA-256 hash of the bearer token */
  tokenHash: string;
  /** Access role */
  role: ControlPlaneRole;
  /** Optional tenant allow-list */
  tenantIds?: string[];
  /** Optional metadata */
  metadata?: Record<string, unknown>;
  /** Creation timestamp */
  createdAt: number;
  /** Last use timestamp */
  lastUsedAt?: number;
}

/** Config for the remote control-plane service process. */
export interface ControlPlaneServiceConfig {
  /** Persistence backend for metadata and traces. */
  storageBackend?: 'file' | 'postgres';
  /** Host interface to bind the HTTP server to. */
  host?: string;
  /** HTTP port to listen on. */
  port?: number;
  /** Directory used for persistent metadata and traces. */
  dataDir?: string;
  /** Require bearer auth for all routes except health checks. */
  authRequired?: boolean;
  /** Header name used to pass tenant scope. */
  tenantHeader?: string;
  /** Bootstrap tokens that are accepted before tokens are provisioned in storage. */
  bootstrapTokens?: Array<
    | string
    | {
        token: string;
        name?: string;
        role?: ControlPlaneRole;
        tenantIds?: string[];
      }
  >;
  /** Interval for approval timeout processing. */
  approvalSweepIntervalMs?: number;
  /** Interval for trace retention sweeps. */
  tracePurgeIntervalMs?: number;
  /** Default trace retention window for ingested traces. */
  traceRetentionDays?: number;
  /** Postgres configuration for managed multi-instance deployments. */
  postgres?: {
    connectionString: string;
    ssl?: boolean;
    metadataTableName?: string;
    tracesTableName?: string;
  };
  /**
   * Protected-intent (encrypted envelope) configuration. When provided,
   * the control-plane exposes `/v1/intents/protected` for agents that submit
   * encrypted intents instead of plaintext.
   */
  protectedIntent?: {
    /** Active recipient keypairs. First entry is treated as the primary. */
    keys: import('./protected-intent').ProtectedIntentKeyPair[];
    /** Replay window in ms — envelopes older than this are rejected. */
    replayWindowMs?: number;
  };
}

// ── Control Plane Client ──

/** Configuration for the control plane client. */
export interface ControlPlaneConfig {
  /** Deployment mode */
  mode: DeploymentMode;
  /** Tenant ID (required for multi-tenant modes) */
  tenantId?: string;
  /** Control plane API endpoint (for remote modes) */
  endpoint?: string;
  /** Authentication token */
  authToken?: string;
  /** Whether to enable local trace retention */
  localTraceRetention?: boolean;
  /** Trace retention TTL in days (local mode) */
  traceRetentionDays?: number;
}

// ══════════════════════════════════════════════════════════════════
// Workforce OS Resource Types
// ══════════════════════════════════════════════════════════════════

// ── Agent Manifest ──

/** Status of an agent in the fleet registry. */
export type AgentManifestStatus = 'active' | 'draining' | 'disabled' | 'archived';

/** A registered agent manifest in the fleet registry. */
export interface AgentManifest {
  /** Unique agent identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Agent version */
  version: string;
  /** Status in the fleet */
  status: AgentManifestStatus;
  /** Tenant this manifest belongs to */
  tenantId?: string;
  /** Workspace scope when pinned below tenant level */
  workspaceId?: string;
  /** Capabilities this agent advertises */
  capabilities: string[];
  /** Model configuration label */
  modelLabel?: string;
  /** Policy pack IDs bound to this agent */
  policyPackIds?: string[];

  // ── Identity & Integrity (OIDC-A / A-JWT) ──

  /** Issuer — the organization or platform that deployed this agent */
  issuer?: string;
  /** Audience — intended consumers of this agent's outputs */
  audience?: string[];
  /** Authorized scopes */
  scopes?: string[];
  /** Maximum delegation depth (0 = cannot delegate) */
  maxDelegationDepth?: number;
  /** Parent agent ID if spawned by another agent */
  parentAgentId?: string;
  /** SHA-256 checksum of the agent definition + tool manifest */
  agentChecksum?: string;
  /** SHA-256 hash of the agent definition */
  definitionHash?: string;
  /** SHA-256 hash of the tool manifest */
  toolManifestHash?: string;
  /** Timestamp the checksum was last computed */
  checksumComputedAt?: number;

  /** Metadata */
  metadata?: Record<string, unknown>;
  /** Registration timestamp */
  registeredAt: number;
  /** Last heartbeat timestamp */
  lastHeartbeatAt?: number;
  /** Optimistic revision for updates */
  manifestRevision?: number;
}

// ── Workspace Resource ──

/** Status of a generic workspace resource. */
export type WorkspaceResourceStatus = 'active' | 'archived' | 'deleted';

export type SponsorshipMode =
  | 'disabled'
  | 'business_paid'
  | 'user_reimburses'
  | 'hybrid'
  | 'veridex_credits'
  | 'postpaid_invoice';

export interface SponsorshipPolicyData {
  schemaVersion: 'veridex.sponsorship-policy/v1';
  appId: string;
  environment: 'test' | 'live';
  mode: SponsorshipMode;
  enabled: boolean;
  allowedChains: string[];
  allowedFeeAssets: string[];
  allowedOperations: string[];
  perTransactionLimit: string;
  dailyLimit: string;
  monthlyLimit: string;
  subsidyBps: number;
  markupBps: number;
  requireUserAuthorization: boolean;
  updatedBy: string;
}

export interface GatewayConfigData {
  schemaVersion: 'veridex.gateway-config/v1';
  appId: string;
  environment: 'test' | 'live';
  name: string;
  state: 'draft' | 'active' | 'paused' | 'disabled';
  targets: Array<{
    network: string;
    facilitatorUrl: string;
    payTo: string;
    asset: string;
    defaultPrice: string;
  }>;
  schemes: Array<'exact' | 'upto' | 'batch-settlement'>;
  upstreamUrl: string;
  publicBaseUrl: string;
  allowedMethods: Array<'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'>;
  routes?: Array<{
    id: string;
    path: string;
    methods: Array<'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'>;
    price: string;
    name?: string;
    resourceId?: string;
  }>;
  updatedBy: string;
}

export interface PaymentResourceData {
  schemaVersion: 'veridex.payment-resource/v1';
  appId: string;
  environment: 'test' | 'live';
  gatewayId: string;
  name: string;
  path: string;
  methods: string[];
  network: string;
  scheme: 'exact' | 'upto' | 'batch-settlement';
  asset: string;
  amount: string;
  payTo: string;
  bazaarStatus: 'draft' | 'published' | 'rejected';
  updatedBy: string;
}

export interface PaymentProjectionData {
  schemaVersion: 'veridex.payment-projection/v1';
  eventId: string;
  eventType: string;
  tenantId: string;
  appId: string;
  environment: 'test' | 'live';
  paymentId?: string;
  executionId?: string;
  occurredAt: string;
  data: Record<string, unknown>;
}

export interface GatewayDeploymentSpec {
  gatewayId: string;
  targetId: string;
  appId: string;
  environment: 'test' | 'live';
  state: GatewayConfigData['state'];
  image: string;
  config: {
    id: string;
    upstream: string;
    publicBaseUrl: string;
    facilitatorUrl: string;
    payTo: string;
    network: string;
    asset: string;
    price: string;
    state: GatewayConfigData['state'];
    routes: Array<{ path: string; methods: GatewayConfigData['allowedMethods'] }>;
  };
  requiredSecretRefs: ['DATABASE_URL', 'GATEWAY_MANAGEMENT_TOKEN'];
  environmentVariables?: Record<string, string>;
}

export interface ChargeAuthorizationData {
  schemaVersion: 'veridex.charge-authorization/v1';
  authorizationId: string;
  quoteId: string;
  tenantId: string;
  appId: string;
  environment: 'test' | 'live';
  payer: string;
  chain: string;
  chargeAsset: string;
  maximumCharge: string;
  nonce: string;
  expiresAt: string;
  recurring: boolean;
  refundPolicyHash: string;
  termsHash: string;
  signatureAlgorithm: 'ed25519';
  signerPublicKey: string;
  signature: string;
  updatedBy: string;
}

export interface TeamInvitationData {
  schemaVersion: 'veridex.team-invitation/v1';
  appId: string;
  email: string;
  role: 'admin' | 'operator' | 'developer' | 'viewer';
  status: 'pending' | 'accepted' | 'revoked' | 'expired';
  expiresAt: string;
  invitedBy: string;
}

export interface ResourceVersion {
  version: number;
  updatedAt: number;
  updatedBy?: string;
  proposalId?: string;
}

/** A typed workspace resource managed by the control plane. */
export interface WorkspaceResource {
  /** Unique resource identifier */
  id: string;
  /** Resource type (e.g., 'config', 'secret_ref', 'dataset', 'model_endpoint') */
  resourceType: string;
  /** Human-readable name */
  name: string;
  /** Current status */
  status: WorkspaceResourceStatus;
  /** Tenant scope */
  tenantId?: string;
  /** Workspace scope */
  workspaceId?: string;
  /** Version or revision counter */
  version: number;
  /** Structured version metadata for optimistic concurrency and review flows */
  resourceVersion?: ResourceVersion;
  /** Structured payload — schema depends on resourceType */
  data: Record<string, unknown>;
  /** Tags for filtering */
  tags?: string[];
  /** Metadata */
  metadata?: Record<string, unknown>;
  /** Attached evidence references */
  evidenceRefs?: Array<Record<string, unknown>>;
  /** Confidence score if this resource was machine-derived */
  confidence?: number;
  /** Review status for governed mutation flows */
  reviewStatus?: 'unreviewed' | 'auto_accepted' | 'review_required' | 'approved' | 'rejected';
  /** Actor that created the resource */
  createdBy?: string;
  /** Actor that last updated the resource */
  updatedBy?: string;
  /** Creation timestamp */
  createdAt: number;
  /** Last update timestamp */
  updatedAt: number;
}

// ── Task ──

/** Task lifecycle states. */
export type TaskStatus =
  | 'pending'
  | 'assigned'
  | 'running'
  | 'blocked'
  | 'completed'
  | 'failed'
  | 'cancelled';

/** Priority levels for tasks. */
export type TaskPriority = 'critical' | 'high' | 'normal' | 'low';

/** A decomposed unit of work assigned to an agent or human. */
export interface Task {
  /** Unique task identifier */
  id: string;
  /** Parent task ID for sub-tasks */
  parentId?: string;
  /** Tenant scope */
  tenantId?: string;
  /** Workspace scope */
  workspaceId?: string;
  /** Task title */
  title: string;
  /** Task description / instructions */
  description: string;
  /** Current status */
  status: TaskStatus;
  /** Priority level */
  priority: TaskPriority;
  /** Assigned agent or operator identifier */
  assigneeId?: string;
  /** Lease owner for deterministic queue handling */
  leaseOwner?: string;
  /** Lease expiry timestamp */
  leaseExpiresAt?: number;
  /** Idempotency key for upstream enqueue/retry safety */
  idempotencyKey?: string;
  /** Task IDs this task depends on */
  dependsOn?: string[];
  /** Deadline timestamp */
  deadlineAt?: number;
  /** Optional SLA target in milliseconds */
  slaMs?: number;
  /** Input data for the task */
  input?: Record<string, unknown>;
  /** Output data produced by the task */
  output?: Record<string, unknown>;
  /** Error message if failed */
  error?: string;
  /** Tags for filtering */
  tags?: string[];
  /** Metadata */
  metadata?: Record<string, unknown>;
  /** Optimistic version */
  version?: number;
  /** Creation timestamp */
  createdAt: number;
  /** Last update timestamp */
  updatedAt: number;
  /** Completion timestamp */
  completedAt?: number;
}

// ── Deployment Revision ──

/** Deployment status. */
export type DeploymentStatus =
  | 'pending'
  | 'deploying'
  | 'active'
  | 'rolling_back'
  | 'rolled_back'
  | 'failed';

/** A deployment revision tracking agent/config rollouts. */
export interface DeploymentRevision {
  /** Unique revision identifier */
  id: string;
  /** Tenant scope */
  tenantId?: string;
  /** Workspace scope */
  workspaceId?: string;
  /** Agent manifest ID being deployed */
  agentManifestId: string;
  /** Revision number (monotonically increasing per agent) */
  revision: number;
  /** Current status */
  status: DeploymentStatus;
  /** Policy pack IDs applied at this revision */
  policyPackIds?: string[];
  /** Configuration snapshot for this deployment */
  config?: Record<string, unknown>;
  /** Who initiated this deployment */
  initiatedBy?: string;
  /** Reason for this deployment */
  reason?: string;
  /** Metadata */
  metadata?: Record<string, unknown>;
  /** Optimistic version */
  version?: number;
  /** Creation timestamp */
  createdAt: number;
  /** When the deployment became active */
  activatedAt?: number;
  /** When a rollback completed, if applicable */
  rolledBackAt?: number;
}

// ── Incident ──

/** Incident severity levels. */
export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low';

/** Incident lifecycle states. */
export type IncidentStatus =
  | 'open'
  | 'investigating'
  | 'mitigated'
  | 'resolved'
  | 'closed';

/** An operational incident tracked by the control plane. */
export interface Incident {
  /** Unique incident identifier */
  id: string;
  /** Tenant scope */
  tenantId?: string;
  /** Workspace scope */
  workspaceId?: string;
  /** Incident title */
  title: string;
  /** Incident description */
  description: string;
  /** Severity */
  severity: IncidentSeverity;
  /** Current status */
  status: IncidentStatus;
  /** Agent IDs involved */
  agentIds?: string[];
  /** Related run IDs */
  runIds?: string[];
  /** Related task IDs */
  taskIds?: string[];
  /** Assigned operator */
  assigneeId?: string;
  /** Linked deployment revisions */
  deploymentRevisionIds?: string[];
  /** Linked workspace resources */
  workspaceResourceIds?: string[];
  /** Tags */
  tags?: string[];
  /** Metadata */
  metadata?: Record<string, unknown>;
  /** Optimistic version */
  version?: number;
  /** Creation timestamp */
  createdAt: number;
  /** Last update timestamp */
  updatedAt: number;
  /** Resolution timestamp */
  resolvedAt?: number;
}

// ── Eval Suite / Eval Run ──

/** Status of an eval run. */
export type EvalRunStatus = 'pending' | 'running' | 'passed' | 'failed' | 'errored';

/** An evaluation suite definition. */
export interface EvalSuite {
  /** Unique suite identifier */
  id: string;
  /** Tenant scope */
  tenantId?: string;
  /** Workspace scope */
  workspaceId?: string;
  /** Suite name */
  name: string;
  /** Suite description */
  description: string;
  /** Number of scenarios in this suite */
  scenarioCount: number;
  /** Scenario definitions (opaque to the control plane) */
  scenarios: Record<string, unknown>[];
  /** Tags */
  tags?: string[];
  /** Metadata */
  metadata?: Record<string, unknown>;
  /** Optimistic version */
  version?: number;
  /** Creation timestamp */
  createdAt: number;
  /** Last update timestamp */
  updatedAt: number;
}

/** A single evaluation run against a suite. */
export interface EvalRun {
  /** Unique run identifier */
  id: string;
  /** Tenant scope */
  tenantId?: string;
  /** Workspace scope */
  workspaceId?: string;
  /** Suite this run belongs to */
  suiteId: string;
  /** Agent manifest ID being evaluated */
  agentManifestId?: string;
  /** Current status */
  status: EvalRunStatus;
  /** Number of scenarios passed */
  passed: number;
  /** Number of scenarios failed */
  failed: number;
  /** Number of scenarios errored */
  errored: number;
  /** Total scenarios executed */
  total: number;
  /** Per-scenario results (opaque to the control plane) */
  results?: Record<string, unknown>[];
  /** Metadata */
  metadata?: Record<string, unknown>;
  /** Optimistic version */
  version?: number;
  /** Creation timestamp */
  createdAt: number;
  /** Completion timestamp */
  completedAt?: number;
}

// ── Policy Binding ──

/** Binds a policy pack to an agent, deployment, or tenant scope. */
export interface PolicyBinding {
  /** Unique binding identifier */
  id: string;
  /** Policy pack ID */
  policyPackId: string;
  /** Target type this binding applies to */
  targetType: 'agent' | 'deployment' | 'tenant';
  /** Target identifier */
  targetId: string;
  /** Workspace scope when applicable */
  workspaceId?: string;
  /** Binding priority (higher = checked first) */
  priority: number;
  /** Whether this binding is active */
  active: boolean;
  /** Metadata */
  metadata?: Record<string, unknown>;
  /** Creation timestamp */
  createdAt: number;
}

// ── Assignment ──

export type AssignmentStatus =
  | 'queued'
  | 'leased'
  | 'accepted'
  | 'running'
  | 'completed'
  | 'failed'
  | 'released';

export interface Assignment {
  id: string;
  tenantId?: string;
  workspaceId?: string;
  taskId: string;
  assigneeId: string;
  status: AssignmentStatus;
  queue?: string;
  retryCount?: number;
  leaseOwner?: string;
  leaseExpiresAt?: number;
  idempotencyKey?: string;
  deadlineAt?: number;
  slaMs?: number;
  metadata?: Record<string, unknown>;
  createdAt: number;
  updatedAt: number;
  completedAt?: number;
}

// ── Maintenance Jobs ──

export type MaintenanceJobStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled';

export interface MaintenanceJob {
  id: string;
  tenantId?: string;
  workspaceId?: string;
  jobType: 'extraction' | 'reconciliation' | 'compaction' | 'drift_check' | 'recap_generation' | 'custom';
  status: MaintenanceJobStatus;
  trigger: 'manual' | 'cron' | 'system';
  targetResourceIds?: string[];
  schedule?: string;
  metadata?: Record<string, unknown>;
  createdAt: number;
  updatedAt: number;
  completedAt?: number;
}

// ── Resource Mutation Review ──

export interface MutationDecision {
  id: string;
  proposalId: string;
  decidedBy: string;
  verdict: 'approved' | 'rejected' | 'needs_revision';
  reason?: string;
  createdAt: number;
}

export interface ResourceMutationProposal {
  id: string;
  tenantId?: string;
  workspaceId?: string;
  resourceType: string;
  resourceId?: string;
  operation: 'create' | 'update' | 'delete';
  expectedVersion?: number;
  payload?: Record<string, unknown>;
  reason: string;
  proposedBy?: string;
  status: 'pending' | 'approved' | 'rejected' | 'applied';
  reviewMode?: 'auto' | 'policy' | 'human';
  decisions: MutationDecision[];
  metadata?: Record<string, unknown>;
  createdAt: number;
  updatedAt: number;
}

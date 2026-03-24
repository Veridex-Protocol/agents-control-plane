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

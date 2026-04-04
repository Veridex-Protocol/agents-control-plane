/**
 * @packageDocumentation
 * @module @veridex/agents-control-plane
 * @description
 * Enterprise control plane SDK for the Veridex Agent Runtime.
 *
 * Provides:
 * - Policy pack management
 * - Trace ingestion and retention
 * - Multi-step approval workflows with escalation
 * - Audit export (JSON, JSONL, CSV)
 * - Evidence bundle generation
 * - Multi-tenant governance
 * - Unified control plane client
 */

// ── Types ──
export type {
  Tenant,
  TenantConfig,
  Workspace,
  DeploymentMode,
  ControlPlaneRole,
  PolicyPack,
  PolicyRuleDefinition,
  TraceRecord,
  TraceQuery,
  ApprovalWorkflow,
  ApprovalEscalationStep,
  EvidenceBundle,
  ControlPlaneAuthToken,
  ControlPlaneConfig,
  ControlPlaneServiceConfig,
  // Workforce OS resources
  AgentManifest,
  AgentManifestStatus,
  ResourceVersion,
  WorkspaceResource,
  WorkspaceResourceStatus,
  Task,
  TaskStatus,
  TaskPriority,
  DeploymentRevision,
  DeploymentStatus,
  Incident,
  IncidentSeverity,
  IncidentStatus,
  EvalSuite,
  EvalRun,
  EvalRunStatus,
  PolicyBinding,
  Assignment,
  AssignmentStatus,
  MaintenanceJob,
  MaintenanceJobStatus,
  MutationDecision,
  ResourceMutationProposal,
} from './types';

// ── Policy Packs ──
export { PolicyPackManager } from './policy-packs';
export type { CreatePolicyPackOptions } from './policy-packs';

// ── Trace Store ──
export { TraceStore, InMemoryTraceStore } from './trace-store';
export type { TraceStoreBackend, IngestOptions } from './trace-store';
export {
  JSONFileMetadataStore,
  FileTraceStoreBackend,
  PostgresMetadataStore,
  PostgresTraceStoreBackend,
  MetadataConflictError,
  createAuthTokenRecord,
  sha256Hex,
} from './persistence';
export type {
  ControlPlaneMetadataSnapshot,
  ControlPlaneMetadataStore,
  TraceStoreMetricsBackend,
  PostgresMetadataStoreConfig,
  PostgresTraceStoreBackendConfig,
  PostgresQueryExecutor,
} from './persistence';

// ── Approval Workflows ──
export { ApprovalWorkflowEngine } from './approval-workflows';
export type { ActiveApproval, ApprovalVote } from './approval-workflows';

// ── Audit Export ──
export { exportTraces, generateEvidenceBundle } from './audit-export';
export type {
  ExportFormat,
  AuditExportOptions,
  AuditExportResult,
} from './audit-export';

// ── Tenant Management ──
export { TenantManager } from './tenant-manager';
export type { CreateTenantOptions } from './tenant-manager';

// ── Control Plane Client ──
export { ControlPlaneClient } from './control-plane';
export { ControlPlaneService } from './service';
export type {
  ApprovalStartOptions,
  ApprovalVoteOptions,
  TokenIssueOptions,
  ServiceAuthResult,
  ControlPlaneServicePersistence,
} from './service';
export { createControlPlaneApp, startControlPlaneServer } from './server';
export { RemoteControlPlaneClient } from './remote-client';
export type { RemoteControlPlaneClientConfig } from './remote-client';

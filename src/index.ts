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
  DeploymentMode,
  PolicyPack,
  PolicyRuleDefinition,
  TraceRecord,
  TraceQuery,
  ApprovalWorkflow,
  ApprovalEscalationStep,
  EvidenceBundle,
  ControlPlaneConfig,
} from './types';

// ── Policy Packs ──
export { PolicyPackManager } from './policy-packs';
export type { CreatePolicyPackOptions } from './policy-packs';

// ── Trace Store ──
export { TraceStore, InMemoryTraceStore } from './trace-store';
export type { TraceStoreBackend, IngestOptions } from './trace-store';

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

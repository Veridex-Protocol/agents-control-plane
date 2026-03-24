/**
 * @module ControlPlaneClient
 * @description
 * High-level control plane client that ties together policy packs,
 * trace store, approval workflows, audit export, and tenant management.
 *
 * Provides a unified API for enterprise operations.
 */

import type { ControlPlaneConfig, TraceRecord } from './types';
import { PolicyPackManager } from './policy-packs';
import { TraceStore, type TraceStoreBackend, type IngestOptions } from './trace-store';
import { ApprovalWorkflowEngine } from './approval-workflows';
import { TenantManager } from './tenant-manager';
import {
  exportTraces,
  generateEvidenceBundle,
  type AuditExportOptions,
  type AuditExportResult,
} from './audit-export';

/**
 * ControlPlaneClient — the unified entry point for enterprise operations.
 */
export class ControlPlaneClient {
  readonly config: ControlPlaneConfig;
  readonly policyPacks: PolicyPackManager;
  readonly traces: TraceStore;
  readonly approvalWorkflows: ApprovalWorkflowEngine;
  readonly tenants: TenantManager;

  constructor(
    config: ControlPlaneConfig,
    traceBackend?: TraceStoreBackend,
  ) {
    this.config = config;
    this.policyPacks = new PolicyPackManager();
    this.traces = new TraceStore(
      traceBackend,
      config.traceRetentionDays ?? 90,
    );
    this.approvalWorkflows = new ApprovalWorkflowEngine();
    this.tenants = new TenantManager();
  }

  /** Ingest trace data from a completed agent run. */
  async ingestTrace(options: IngestOptions): Promise<TraceRecord> {
    return this.traces.ingest({
      ...options,
      tenantId: options.tenantId ?? this.config.tenantId,
    });
  }

  /** Export audit data for a set of trace records. */
  exportAudit(
    records: TraceRecord[],
    options: AuditExportOptions,
  ): AuditExportResult {
    return exportTraces(records, options);
  }

  /** Generate an evidence bundle for a trace record. */
  async generateEvidence(
    trace: TraceRecord,
    policyDecisions: unknown[],
    approvalDecisions: unknown[],
  ) {
    return generateEvidenceBundle(trace, policyDecisions, approvalDecisions);
  }

  /** Verify a trace record's integrity. */
  async verifyTrace(traceId: string): Promise<boolean> {
    return this.traces.verify(traceId);
  }

  /** Purge expired traces based on retention policy. */
  async purgeExpiredTraces(): Promise<number> {
    return this.traces.purgeExpired();
  }

  /** Process all pending approval timeouts/escalations. */
  processApprovalTimeouts() {
    return this.approvalWorkflows.processTimeouts();
  }
}

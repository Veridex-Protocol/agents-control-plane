/**
 * @module AuditExporter
 * @description
 * Enterprise audit export for the control plane.
 *
 * Exports trace records, policy decisions, and approval decisions
 * in enterprise-friendly formats (JSON, JSONL, CSV). Supports
 * evidence bundle generation with cryptographic attestation.
 */

import type { TraceRecord, EvidenceBundle } from './types';

/** Supported export formats. */
export type ExportFormat = 'json' | 'jsonl' | 'csv';

/** Options for audit export. */
export interface AuditExportOptions {
  /** Export format */
  format: ExportFormat;
  /** Whether to include raw events in the export */
  includeEvents?: boolean;
  /** Whether to include content hashes */
  includeHashes?: boolean;
  /** Custom fields to include in CSV headers */
  csvFields?: string[];
}

/** Result of an audit export. */
export interface AuditExportResult {
  /** The exported data as a string */
  data: string;
  /** Format of the exported data */
  format: ExportFormat;
  /** Number of records exported */
  recordCount: number;
  /** Generation timestamp */
  generatedAt: number;
}

/**
 * Compute a SHA-256 hex hash, with FNV-1a fallback.
 */
async function computeHash(data: string): Promise<string> {
  if (typeof globalThis.crypto?.subtle !== 'undefined') {
    const encoded = new TextEncoder().encode(data);
    const buffer = await globalThis.crypto.subtle.digest('SHA-256', encoded);
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  let hash = 0x811c9dc5;
  for (let i = 0; i < data.length; i++) {
    hash ^= data.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

/**
 * Export trace records in the specified format.
 */
export function exportTraces(
  records: TraceRecord[],
  options: AuditExportOptions,
): AuditExportResult {
  const { format, includeEvents = false } = options;

  const sanitized = records.map((r) => {
    const base: Record<string, unknown> = {
      id: r.id,
      runId: r.runId,
      agentId: r.agentId,
      tenantId: r.tenantId,
      startedAt: r.startedAt,
      completedAt: r.completedAt,
      state: r.state,
      turnCount: r.turnCount,
      totalTokens: r.totalTokens,
      totalCostUSD: r.totalCostUSD,
      contentHash: r.contentHash,
    };
    if (includeEvents) {
      base.events = r.events;
    }
    return base;
  });

  let data: string;

  switch (format) {
    case 'json':
      data = JSON.stringify(sanitized, null, 2);
      break;

    case 'jsonl':
      data = sanitized.map((r) => JSON.stringify(r)).join('\n');
      break;

    case 'csv': {
      const fields = options.csvFields ?? [
        'id', 'runId', 'agentId', 'tenantId', 'startedAt',
        'completedAt', 'state', 'turnCount', 'totalTokens', 'totalCostUSD',
      ];
      const header = fields.join(',');
      const rows = sanitized.map((r) =>
        fields.map((f) => {
          const val = r[f];
          if (val === undefined || val === null) return '';
          const str = String(val);
          return str.includes(',') || str.includes('"')
            ? `"${str.replace(/"/g, '""')}"`
            : str;
        }).join(','),
      );
      data = [header, ...rows].join('\n');
      break;
    }

    default:
      throw new Error(`Unsupported export format: ${format}`);
  }

  return {
    data,
    format,
    recordCount: records.length,
    generatedAt: Date.now(),
  };
}

/**
 * Generate an evidence bundle from a trace record and governance data.
 */
export async function generateEvidenceBundle(
  trace: TraceRecord,
  policyDecisions: unknown[],
  approvalDecisions: unknown[],
): Promise<EvidenceBundle> {
  const traceHash = await computeHash(JSON.stringify(trace.events));
  const policyHash = await computeHash(JSON.stringify(policyDecisions));
  const approvalHash = await computeHash(JSON.stringify(approvalDecisions));
  const contentHash = await computeHash(
    `${traceHash}:${policyHash}:${approvalHash}`,
  );

  return {
    id: `evidence_${trace.runId}`,
    runId: trace.runId,
    version: '1.0.0',
    traceHash,
    policyHash,
    approvalHash,
    contentHash,
    generatedAt: Date.now(),
    traceId: trace.id,
    policyDecisions,
    approvalDecisions,
  };
}

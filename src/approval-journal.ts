/**
 * @module ApprovalJournal
 * @description
 * Append-only write-ahead log (WAL) for approval workflow events.
 *
 * The full control-plane JSON snapshot is rewritten on every mutation, which
 * is atomic via tmp-file + rename. However, if a process crashes _between_
 * the in-memory mutation and the atomic rename, the in-memory change is lost.
 *
 * For approval workflows — which carry real compliance weight (multi-party
 * authorization, escalation chains, audit trails) — we additionally record
 * every approval event to an append-only NDJSON journal that is `fsync`'d
 * before the mutation returns to the caller. On startup, the journal is
 * replayed over the loaded snapshot so any events that made it to the
 * journal but not to the snapshot are recovered.
 *
 * Compaction: after a successful snapshot persist, the journal can be
 * truncated because the snapshot now covers all committed events.
 */

import { randomUUID } from 'node:crypto';
import { appendFile, mkdir, open, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type { ActiveApproval, ApprovalVote } from './approval-workflows';

export type ApprovalJournalEvent =
  | {
      type: 'start';
      at: number;
      approval: ActiveApproval;
    }
  | {
      type: 'vote';
      at: number;
      approvalId: string;
      vote: ApprovalVote;
      resolution?: ActiveApproval['resolution'];
    }
  | {
      type: 'timeout';
      at: number;
      approvalId: string;
      newStep?: number;
      newDeadline?: number;
      resolution?: ActiveApproval['resolution'];
    };

export interface ApprovalJournalBackend {
  append(event: ApprovalJournalEvent): Promise<void>;
  read(): Promise<ApprovalJournalEvent[]>;
  truncate(): Promise<void>;
}

/**
 * File-backed journal. Every append opens the file, writes an NDJSON line,
 * fsync's, and closes. This is slower than keeping the handle open, but
 * simpler and has the strongest crash-recovery guarantees.
 */
export class FileApprovalJournal implements ApprovalJournalBackend {
  private readonly filePath: string;
  private writeChain: Promise<void> = Promise.resolve();

  constructor(dataDir: string, fileName = 'approval-journal.ndjson') {
    this.filePath = path.join(dataDir, fileName);
  }

  private async ensureParent(): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
  }

  async append(event: ApprovalJournalEvent): Promise<void> {
    const line = JSON.stringify(event) + '\n';
    this.writeChain = this.writeChain.then(async () => {
      await this.ensureParent();
      const handle = await open(this.filePath, 'a');
      try {
        await handle.appendFile(line, 'utf8');
        await handle.sync();
      } finally {
        await handle.close();
      }
    });
    await this.writeChain;
  }

  async read(): Promise<ApprovalJournalEvent[]> {
    try {
      const raw = await readFile(this.filePath, 'utf8');
      const events: ApprovalJournalEvent[] = [];
      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        try {
          events.push(JSON.parse(line) as ApprovalJournalEvent);
        } catch {
          // Partially written last line on crash — stop replay here.
          break;
        }
      }
      return events;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }

  async truncate(): Promise<void> {
    this.writeChain = this.writeChain.then(async () => {
      await this.ensureParent();
      const tmp = `${this.filePath}.${randomUUID()}.tmp`;
      await writeFile(tmp, '', 'utf8');
      await rename(tmp, this.filePath);
    });
    await this.writeChain;
  }
}

/** In-memory journal for tests. */
export class InMemoryApprovalJournal implements ApprovalJournalBackend {
  private events: ApprovalJournalEvent[] = [];

  async append(event: ApprovalJournalEvent): Promise<void> {
    this.events.push(event);
  }

  async read(): Promise<ApprovalJournalEvent[]> {
    return [...this.events];
  }

  async truncate(): Promise<void> {
    this.events = [];
  }
}

/**
 * Apply a list of journal events on top of the current state of the given
 * approval engine. Used on startup to recover events that were written to
 * the journal but not yet reflected in the main snapshot.
 */
export function replayApprovalJournal(
  events: ApprovalJournalEvent[],
  engine: {
    getApproval(id: string): ActiveApproval | undefined;
    loadApprovals(approvals: ActiveApproval[]): void;
    snapshotApprovals(): ActiveApproval[];
  },
): number {
  if (events.length === 0) return 0;

  // Build a mutable index from the current engine state so we can layer
  // journal events on top without re-implementing workflow semantics.
  const approvals = new Map<string, ActiveApproval>();
  for (const approval of engine.snapshotApprovals()) {
    approvals.set(approval.id, approval);
  }

  let applied = 0;

  for (const event of events) {
    if (event.type === 'start') {
      // Only re-insert if the snapshot did not already have it; in-snapshot
      // state is considered authoritative when present.
      if (!approvals.has(event.approval.id)) {
        approvals.set(event.approval.id, {
          ...event.approval,
          approvals: event.approval.approvals.map((v) => ({ ...v })),
        });
        applied++;
      }
      continue;
    }

    if (event.type === 'vote') {
      const existing = approvals.get(event.approvalId);
      if (!existing) continue;
      const hasVote = existing.approvals.some(
        (v) => v.approver === event.vote.approver && v.votedAt === event.vote.votedAt,
      );
      if (!hasVote) {
        existing.approvals = [...existing.approvals, { ...event.vote }];
        applied++;
      }
      if (event.resolution && !existing.resolution) {
        existing.resolution = event.resolution;
        applied++;
      }
      continue;
    }

    if (event.type === 'timeout') {
      const existing = approvals.get(event.approvalId);
      if (!existing) continue;
      if (typeof event.newStep === 'number' && existing.currentStep < event.newStep) {
        existing.currentStep = event.newStep;
        existing.approvals = [];
        applied++;
      }
      if (typeof event.newDeadline === 'number') {
        existing.currentStepDeadline = event.newDeadline;
      }
      if (event.resolution && !existing.resolution) {
        existing.resolution = event.resolution;
        applied++;
      }
    }
  }

  engine.loadApprovals([...approvals.values()]);
  return applied;
}

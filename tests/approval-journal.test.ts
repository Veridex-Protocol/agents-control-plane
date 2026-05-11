import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  ControlPlaneService,
  FileApprovalJournal,
  InMemoryApprovalJournal,
  replayApprovalJournal,
  ApprovalWorkflowEngine,
  type ActiveApproval,
  type ApprovalJournalEvent,
} from '../src';

async function makeTempDir(): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), 'veridex-approval-journal-'));
}

describe('ApprovalJournal — durability', () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop();
      if (dir) {
        await rm(dir, { recursive: true, force: true });
      }
    }
  });

  it('persists appended events across instances and supports truncation', async () => {
    const dataDir = await makeTempDir();
    tempDirs.push(dataDir);

    const j1 = new FileApprovalJournal(dataDir);
    const event: ApprovalJournalEvent = {
      type: 'start',
      at: 123,
      approval: {
        id: 'a_1',
        workflowId: 'wf',
        currentStep: 0,
        runId: 'r',
        agentId: 'ag',
        proposal: 'p',
        riskScore: 0.5,
        approvals: [],
        createdAt: 123,
        currentStepDeadline: 456,
      },
    };
    await j1.append(event);

    const j2 = new FileApprovalJournal(dataDir);
    const read = await j2.read();
    expect(read).toHaveLength(1);
    expect(read[0]).toEqual(event);

    await j2.truncate();
    expect(await j2.read()).toEqual([]);
  });

  it('tolerates a truncated last line (crash mid-write)', async () => {
    const dataDir = await makeTempDir();
    tempDirs.push(dataDir);

    const filePath = path.join(dataDir, 'approval-journal.ndjson');
    const valid = JSON.stringify({
      type: 'start',
      at: 1,
      approval: {
        id: 'a_ok',
        workflowId: 'wf',
        currentStep: 0,
        runId: 'r',
        agentId: 'ag',
        proposal: 'p',
        riskScore: 0,
        approvals: [],
        createdAt: 1,
        currentStepDeadline: 2,
      },
    });
    // simulate torn write: valid line + partial JSON
    await writeFile(filePath, `${valid}\n{"type":"vote","at":2,"approv`, 'utf8');

    const j = new FileApprovalJournal(dataDir);
    const events = await j.read();
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('start');
  });

  it('replayApprovalJournal re-applies events missing from the snapshot', () => {
    const engine = new ApprovalWorkflowEngine();
    const events: ApprovalJournalEvent[] = [
      {
        type: 'start',
        at: 1,
        approval: {
          id: 'a_1',
          workflowId: 'wf',
          currentStep: 0,
          runId: 'r',
          agentId: 'ag',
          proposal: 'p',
          riskScore: 0,
          approvals: [],
          createdAt: 1,
          currentStepDeadline: 10,
        },
      },
      {
        type: 'vote',
        at: 2,
        approvalId: 'a_1',
        vote: { approver: 'ops', approved: true, votedAt: 2 },
        resolution: 'approved',
      },
    ];

    const applied = replayApprovalJournal(events, engine);
    expect(applied).toBeGreaterThan(0);

    const approval = engine.getApproval('a_1') as ActiveApproval;
    expect(approval).toBeDefined();
    expect(approval.approvals).toHaveLength(1);
    expect(approval.resolution).toBe('approved');
  });

  it('recovers approvals from the journal when the snapshot was not written', async () => {
    const dataDir = await makeTempDir();
    tempDirs.push(dataDir);

    // Seed the journal with an approval event that never made it to the snapshot.
    const journal = new FileApprovalJournal(dataDir);
    await journal.append({
      type: 'start',
      at: Date.now(),
      approval: {
        id: 'a_orphan',
        workflowId: 'wf_main',
        currentStep: 0,
        runId: 'run_x',
        agentId: 'agent_x',
        proposal: 'ship it',
        riskScore: 0.9,
        approvals: [],
        createdAt: Date.now(),
        currentStepDeadline: Date.now() + 60_000,
      },
    });

    // Write a snapshot that declares the workflow but has NO active approvals.
    const snapshot = {
      version: 1,
      revision: 0,
      updatedAt: Date.now(),
      authTokens: [],
      tenants: [],
      workspaces: [],
      policyPacks: [],
      approvalWorkflows: [
        {
          id: 'wf_main',
          name: 'Main',
          description: '',
          escalationChain: [{ name: 'Ops', approvers: ['ops'], timeoutSeconds: 60, minApprovals: 1 }],
          defaultMode: 'block',
        },
      ],
      activeApprovals: [],
      agentManifests: [],
      workspaceResources: [],
      tasks: [],
      deploymentRevisions: [],
      incidents: [],
      evalSuites: [],
      evalRuns: [],
      policyBindings: [],
      assignments: [],
      maintenanceJobs: [],
      resourceMutationProposals: [],
    };
    await writeFile(path.join(dataDir, 'control-plane.json'), JSON.stringify(snapshot), 'utf8');

    const service = new ControlPlaneService({ dataDir });
    const recovered = await service.getApproval('a_orphan');
    expect(recovered).toBeDefined();
    expect(recovered?.proposal).toBe('ship it');

    // Recovery should have compacted the journal.
    const journal2 = new FileApprovalJournal(dataDir);
    expect(await journal2.read()).toEqual([]);
  });

  it('truncates journal after a normal persist cycle', async () => {
    const dataDir = await makeTempDir();
    tempDirs.push(dataDir);

    const service = new ControlPlaneService({ dataDir });
    await service.registerWorkflow({
      id: 'wf_main',
      name: 'Main',
      description: '',
      escalationChain: [{ name: 'Ops', approvers: ['ops'], timeoutSeconds: 60, minApprovals: 1 }],
      defaultMode: 'block',
    });
    await service.startApproval({
      workflowId: 'wf_main',
      runId: 'run_1',
      agentId: 'agent_1',
      proposal: 'go',
      riskScore: 0.3,
    });

    const journal = new FileApprovalJournal(dataDir);
    expect(await journal.read()).toEqual([]);
  });

  it('accepts custom in-memory journal via persistence injection', async () => {
    const dataDir = await makeTempDir();
    tempDirs.push(dataDir);

    const journal = new InMemoryApprovalJournal();
    const service = new ControlPlaneService({ dataDir }, { approvalJournal: journal });
    await service.registerWorkflow({
      id: 'wf_main',
      name: 'Main',
      description: '',
      escalationChain: [{ name: 'Ops', approvers: ['ops'], timeoutSeconds: 60, minApprovals: 1 }],
      defaultMode: 'block',
    });
    await service.startApproval({
      workflowId: 'wf_main',
      runId: 'run_1',
      agentId: 'agent_1',
      proposal: 'go',
      riskScore: 0.3,
    });
    // After a successful mutation, the service compacts the journal.
    expect(await journal.read()).toEqual([]);
  });
});

/**
 * @module ApprovalWorkflowEngine
 * @description
 * Enterprise approval workflow engine for the control plane.
 *
 * Supports multi-step escalation chains, group approvals,
 * timeout-based escalation, and auto-approve policies.
 */

import type { ApprovalWorkflow, } from './types';

/** The state of an active approval request within a workflow. */
export interface ActiveApproval {
  /** Unique approval ID */
  id: string;
  /** Workflow being executed */
  workflowId: string;
  /** Current escalation step index */
  currentStep: number;
  /** Run ID this approval belongs to */
  runId: string;
  /** Agent ID */
  agentId: string;
  /** What is being approved */
  proposal: string;
  /** Risk score from policy evaluation */
  riskScore: number;
  /** Approvals received at current step */
  approvals: ApprovalVote[];
  /** When this request was created */
  createdAt: number;
  /** When the current step times out */
  currentStepDeadline: number;
  /** Final resolution */
  resolution?: 'approved' | 'denied' | 'auto-approved' | 'escalated' | 'timed-out';
}

/** An individual approval vote. */
export interface ApprovalVote {
  /** Approver identifier */
  approver: string;
  /** Vote */
  approved: boolean;
  /** Reason for the vote */
  reason?: string;
  /** Timestamp */
  votedAt: number;
}

/**
 * Manages approval workflows with escalation chains.
 */
export class ApprovalWorkflowEngine {
  private workflows = new Map<string, ApprovalWorkflow>();
  private activeApprovals = new Map<string, ActiveApproval>();

  /** Register a workflow definition. */
  registerWorkflow(workflow: ApprovalWorkflow): void {
    this.workflows.set(workflow.id, workflow);
  }

  /** Get a registered workflow by ID. */
  getWorkflow(id: string): ApprovalWorkflow | undefined {
    return this.workflows.get(id);
  }

  /** List all registered workflows. */
  listWorkflows(): ApprovalWorkflow[] {
    return Array.from(this.workflows.values());
  }

  /**
   * Start an approval request using a specific workflow.
   * Returns the active approval tracking object.
   */
  startApproval(
    workflowId: string,
    runId: string,
    agentId: string,
    proposal: string,
    riskScore: number,
  ): ActiveApproval {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Workflow "${workflowId}" not found`);
    }

    if (workflow.escalationChain.length === 0) {
      throw new Error(`Workflow "${workflowId}" has no escalation steps`);
    }

    const now = Date.now();
    const firstStep = workflow.escalationChain[0];
    const id = `approval_${now}_${Math.random().toString(36).slice(2, 8)}`;

    const active: ActiveApproval = {
      id,
      workflowId,
      currentStep: 0,
      runId,
      agentId,
      proposal,
      riskScore,
      approvals: [],
      createdAt: now,
      currentStepDeadline: now + firstStep.timeoutSeconds * 1000,
    };

    this.activeApprovals.set(id, active);
    return active;
  }

  /**
   * Submit a vote on an active approval.
   * Returns the updated active approval with possible resolution.
   */
  vote(
    approvalId: string,
    approver: string,
    approved: boolean,
    reason?: string,
  ): ActiveApproval {
    const active = this.activeApprovals.get(approvalId);
    if (!active) {
      throw new Error(`Active approval "${approvalId}" not found`);
    }
    if (active.resolution) {
      throw new Error(`Approval "${approvalId}" is already resolved: ${active.resolution}`);
    }

    const workflow = this.workflows.get(active.workflowId);
    if (!workflow) {
      throw new Error(`Workflow "${active.workflowId}" no longer registered`);
    }

    const currentStep = workflow.escalationChain[active.currentStep];

    // Verify the voter is an authorized approver for this step
    if (!currentStep.approvers.includes(approver)) {
      throw new Error(
        `"${approver}" is not an authorized approver for step "${currentStep.name}"`,
      );
    }

    // Record the vote
    active.approvals.push({
      approver,
      approved,
      reason,
      votedAt: Date.now(),
    });

    // Check if enough approvals have been received
    const approvingVotes = active.approvals.filter((v) => v.approved);
    const denyingVotes = active.approvals.filter((v) => !v.approved);

    if (approvingVotes.length >= currentStep.minApprovals) {
      active.resolution = 'approved';
    } else if (denyingVotes.length > currentStep.approvers.length - currentStep.minApprovals) {
      // Enough denials that approval is impossible at this step
      active.resolution = 'denied';
    }

    return active;
  }

  /**
   * Check for timed-out approvals and escalate them.
   * Returns the list of approvals that were escalated or timed out.
   */
  processTimeouts(): ActiveApproval[] {
    const now = Date.now();
    const processed: ActiveApproval[] = [];

    for (const active of this.activeApprovals.values()) {
      if (active.resolution) continue;
      if (now < active.currentStepDeadline) continue;

      const workflow = this.workflows.get(active.workflowId);
      if (!workflow) continue;

      const nextStepIndex = active.currentStep + 1;

      if (nextStepIndex < workflow.escalationChain.length) {
        // Escalate to next step
        const nextStep = workflow.escalationChain[nextStepIndex];
        active.currentStep = nextStepIndex;
        active.currentStepDeadline = now + nextStep.timeoutSeconds * 1000;
        active.approvals = []; // Reset votes for new step
        active.resolution = undefined;
        processed.push(active);
      } else if (workflow.autoApproveAfterSeconds) {
        // Check if total time exceeds auto-approve threshold
        const totalElapsed = (now - active.createdAt) / 1000;
        if (totalElapsed >= workflow.autoApproveAfterSeconds) {
          active.resolution = 'auto-approved';
          processed.push(active);
        } else {
          active.resolution = 'timed-out';
          processed.push(active);
        }
      } else {
        // No more steps, no auto-approve — apply default mode
        if (workflow.defaultMode === 'auto-approve') {
          active.resolution = 'auto-approved';
        } else {
          active.resolution = 'timed-out';
        }
        processed.push(active);
      }
    }

    return processed;
  }

  /** Get an active approval by ID. */
  getApproval(id: string): ActiveApproval | undefined {
    return this.activeApprovals.get(id);
  }

  /** List all active (unresolved) approvals. */
  listPending(): ActiveApproval[] {
    return Array.from(this.activeApprovals.values()).filter(
      (a) => !a.resolution,
    );
  }

  /** List all resolved approvals. */
  listResolved(): ActiveApproval[] {
    return Array.from(this.activeApprovals.values()).filter(
      (a) => !!a.resolution,
    );
  }

  /** Clear resolved approvals from memory. */
  clearResolved(): number {
    let cleared = 0;
    for (const [id, active] of this.activeApprovals) {
      if (active.resolution) {
        this.activeApprovals.delete(id);
        cleared++;
      }
    }
    return cleared;
  }

  /** Replace workflows from a persisted snapshot. */
  loadWorkflows(workflows: ApprovalWorkflow[]): void {
    this.workflows.clear();
    for (const workflow of workflows) {
      this.workflows.set(workflow.id, {
        ...workflow,
        escalationChain: workflow.escalationChain.map((step) => ({ ...step })),
      });
    }
  }

  /** Replace active approvals from a persisted snapshot. */
  loadApprovals(approvals: ActiveApproval[]): void {
    this.activeApprovals.clear();
    for (const approval of approvals) {
      this.activeApprovals.set(approval.id, {
        ...approval,
        approvals: approval.approvals.map((vote) => ({ ...vote })),
      });
    }
  }

  /** Snapshot workflows for durable persistence. */
  snapshotWorkflows(): ApprovalWorkflow[] {
    return Array.from(this.workflows.values()).map((workflow) => ({
      ...workflow,
      escalationChain: workflow.escalationChain.map((step) => ({ ...step })),
    }));
  }

  /** Snapshot active approvals for durable persistence. */
  snapshotApprovals(): ActiveApproval[] {
    return Array.from(this.activeApprovals.values()).map((approval) => ({
      ...approval,
      approvals: approval.approvals.map((vote) => ({ ...vote })),
    }));
  }
}

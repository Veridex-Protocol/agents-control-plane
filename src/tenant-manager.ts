/**
 * @module TenantManager
 * @description
 * Multi-tenant governance for the control plane.
 *
 * Manages tenant lifecycle, configuration, and resource limits.
 */

import type { Tenant, TenantConfig } from './types';

/** Options for creating a tenant. */
export interface CreateTenantOptions {
  name: string;
  config?: Partial<TenantConfig>;
  metadata?: Record<string, unknown>;
}

/**
 * Manages multi-tenant governance — CRUD for tenants,
 * configuration enforcement, and status management.
 */
export class TenantManager {
  private tenants = new Map<string, Tenant>();

  /** Create a new tenant. */
  create(options: CreateTenantOptions): Tenant {
    const id = `tenant_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    const tenant: Tenant = {
      id,
      name: options.name,
      status: 'active',
      config: {
        maxConcurrentRuns: 10,
        auditEnabled: true,
        traceRetentionDays: 90,
        deploymentMode: 'local',
        ...options.config,
      },
      metadata: options.metadata,
      createdAt: Date.now(),
    };

    this.tenants.set(id, tenant);
    return tenant;
  }

  /** Get a tenant by ID. */
  get(id: string): Tenant | undefined {
    return this.tenants.get(id);
  }

  /** List all tenants, optionally filtered by status. */
  list(status?: Tenant['status']): Tenant[] {
    const all = Array.from(this.tenants.values());
    if (!status) return all;
    return all.filter((t) => t.status === status);
  }

  /** Update a tenant's configuration. */
  updateConfig(id: string, config: Partial<TenantConfig>): Tenant | undefined {
    const tenant = this.tenants.get(id);
    if (!tenant) return undefined;

    const updated: Tenant = {
      ...tenant,
      config: { ...tenant.config, ...config },
    };

    this.tenants.set(id, updated);
    return updated;
  }

  /** Suspend a tenant. */
  suspend(id: string): Tenant | undefined {
    const tenant = this.tenants.get(id);
    if (!tenant) return undefined;

    const suspended: Tenant = { ...tenant, status: 'suspended' };
    this.tenants.set(id, suspended);
    return suspended;
  }

  /** Reactivate a suspended tenant. */
  activate(id: string): Tenant | undefined {
    const tenant = this.tenants.get(id);
    if (!tenant) return undefined;

    const activated: Tenant = { ...tenant, status: 'active' };
    this.tenants.set(id, activated);
    return activated;
  }

  /** Delete a tenant. */
  delete(id: string): boolean {
    return this.tenants.delete(id);
  }

  /** Get the count of tenants. */
  count(): number {
    return this.tenants.size;
  }

  /** Replace all loaded tenants from a persisted snapshot. */
  load(tenants: Tenant[]): void {
    this.tenants.clear();
    for (const tenant of tenants) {
      this.tenants.set(tenant.id, { ...tenant });
    }
  }

  /** Snapshot tenants for durable persistence. */
  snapshot(): Tenant[] {
    return Array.from(this.tenants.values()).map((tenant) => ({
      ...tenant,
      config: { ...tenant.config },
      metadata: tenant.metadata ? { ...tenant.metadata } : undefined,
    }));
  }
}

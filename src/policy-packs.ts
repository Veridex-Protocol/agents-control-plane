/**
 * @module PolicyPackManager
 * @description
 * CRUD operations for policy packs — named sets of policy rules
 * that can be applied to tenants and agents.
 *
 * Policy packs are the enterprise mechanism for standardizing
 * and distributing policy configurations.
 */

import type { PolicyPack, PolicyRuleDefinition } from './types';

/** Options for creating a policy pack. */
export interface CreatePolicyPackOptions {
  name: string;
  description: string;
  version: string;
  rules: PolicyRuleDefinition[];
  tags?: string[];
}

/**
 * Manages policy pack lifecycle — create, list, get, update, delete.
 * Uses an in-memory store by default; can be backed by a persistent store.
 */
export class PolicyPackManager {
  private packs = new Map<string, PolicyPack>();

  /** Create a new policy pack. */
  create(options: CreatePolicyPackOptions): PolicyPack {
    const id = `pp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const now = Date.now();

    const pack: PolicyPack = {
      id,
      name: options.name,
      description: options.description,
      version: options.version,
      rules: options.rules,
      tags: options.tags,
      immutable: false,
      createdAt: now,
      updatedAt: now,
    };

    this.packs.set(id, pack);
    return pack;
  }

  /** Get a policy pack by ID. */
  get(id: string): PolicyPack | undefined {
    return this.packs.get(id);
  }

  /** List all policy packs, optionally filtered by tags. */
  list(tags?: string[]): PolicyPack[] {
    const all = Array.from(this.packs.values());
    if (!tags || tags.length === 0) return all;

    return all.filter((pack) =>
      tags.some((tag) => pack.tags?.includes(tag)),
    );
  }

  /** Update a policy pack's rules or metadata. */
  update(
    id: string,
    updates: Partial<Pick<PolicyPack, 'name' | 'description' | 'version' | 'rules' | 'tags'>>,
  ): PolicyPack | undefined {
    const existing = this.packs.get(id);
    if (!existing) return undefined;
    if (existing.immutable) {
      throw new Error(`Policy pack "${id}" is immutable and cannot be updated`);
    }

    const updated: PolicyPack = {
      ...existing,
      ...updates,
      updatedAt: Date.now(),
    };

    this.packs.set(id, updated);
    return updated;
  }

  /** Delete a policy pack. */
  delete(id: string): boolean {
    const existing = this.packs.get(id);
    if (!existing) return false;
    if (existing.immutable) {
      throw new Error(`Policy pack "${id}" is immutable and cannot be deleted`);
    }
    return this.packs.delete(id);
  }

  /** Register a system-defined immutable policy pack. */
  registerSystemPack(options: CreatePolicyPackOptions): PolicyPack {
    const pack = this.create(options);
    const immutable = { ...pack, immutable: true };
    this.packs.set(pack.id, immutable);
    return immutable;
  }

  /** Get the count of registered packs. */
  count(): number {
    return this.packs.size;
  }

  /** Clear all non-immutable packs. */
  clear(): void {
    for (const [id, pack] of this.packs) {
      if (!pack.immutable) {
        this.packs.delete(id);
      }
    }
  }

  /** Replace all loaded policy packs, preserving immutability flags from the snapshot. */
  load(packs: PolicyPack[]): void {
    this.packs.clear();
    for (const pack of packs) {
      this.packs.set(pack.id, { ...pack });
    }
  }

  /** Snapshot the current policy pack state for persistence. */
  snapshot(): PolicyPack[] {
    return Array.from(this.packs.values()).map((pack) => ({ ...pack }));
  }
}

/** Agent endpoints (/api/v1/agents/*). */
import { request } from './client.js';
import type { LiveAgents } from './types.js';

export function live(opts: { limit?: number; includeDeactivated?: boolean } = {}): Promise<LiveAgents> {
  return request('GET', '/agents/live', {
    query: { limit: opts.limit, include_deactivated: opts.includeDeactivated ? 1 : undefined },
  });
}

/** Deep detail for a single agent by agent_id. Loosely typed (rich payload). */
export function get(id: string, scan = false): Promise<Record<string, unknown>> {
  return request('GET', `/agents/${encodeURIComponent(id)}`, { query: scan ? { scan: 1 } : undefined });
}

export function anomalies(id: string, limit?: number): Promise<{ anomalies: Array<Record<string, unknown>> }> {
  return request('GET', `/agents/${encodeURIComponent(id)}/anomalies`, {
    query: limit !== undefined ? { limit } : undefined,
  });
}

/** Audit-log endpoints (/api/v1/audit-logs/*). */
import { request } from './client.js';
import type { AuditList } from './types.js';

export interface AuditQuery {
  filter?: 'ALLOW' | 'DENY' | 'DENIED';
  tool?: string;
  limit?: number;
  offset?: number;
  from?: number;
  to?: number;
  agent_name?: string;
  session_id?: string;
  search?: string;
  signal?: 'dlp' | 'ratelimit';
}

export function list(query: AuditQuery = {}): Promise<AuditList> {
  return request('GET', '/audit-logs', { query: query as Record<string, string | number | undefined> });
}

/*
 * There is no remove() and no removeAll(). Both used to call
 * `DELETE /audit-logs`; the endpoint is gone, because an audit log the audited
 * party can clear is not a record of anything. Nothing in this CLI called them.
 */

export function whitelist(
  id: string,
  scope: 'exact' | 'tool' = 'exact',
): Promise<{ ok: true; deduped: boolean; scope: string; policy_id: string; policy_version?: number; message?: string }> {
  return request('POST', `/audit-logs/${encodeURIComponent(id)}/whitelist`, { body: { scope } });
}

export function block(
  id: string,
  scope: 'exact' | 'tool' = 'exact',
): Promise<{ ok: true; deduped: boolean; scope: string; policy_id: string; policy_version?: number; message?: string }> {
  return request('POST', `/audit-logs/${encodeURIComponent(id)}/block`, { body: { scope } });
}

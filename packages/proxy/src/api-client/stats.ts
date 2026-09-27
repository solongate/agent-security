/** Stats endpoints (/api/v1/stats/*). */
import { request } from './client.js';
import type { Drift, Stats, Timeseries } from './types.js';

export function get(): Promise<Stats> {
  return request('GET', '/stats');
}

export function timeseries(
  opts: { period?: '24h' | '7d' | '30d' | 'all'; granularity?: '1h' | '1d' } = {},
): Promise<Timeseries> {
  return request('GET', '/stats/timeseries', { query: opts });
}

export function drift(days?: number): Promise<Drift> {
  return request('GET', '/stats/drift', { query: days !== undefined ? { days } : undefined });
}

/** Rich insights payload — kept loosely typed; consumers pick fields they need. */
export function securityInsights(days?: number): Promise<Record<string, unknown>> {
  return request('GET', '/stats/security-insights', { query: days !== undefined ? { days } : undefined });
}

/** Settings endpoints: security layers (rate limit + DLP), rate-limit history. */
import { request } from './client.js';
import type { RateLimitChange, SecurityLayers } from './types.js';

export function getSecurityLayers(): Promise<{ layers: SecurityLayers; availablePatterns: string[] }> {
  return request('GET', '/settings/security-layers');
}

export function setSecurityLayers(layers: SecurityLayers): Promise<{ layers: SecurityLayers }> {
  return request('PUT', '/settings/security-layers', { body: { layers } });
}

export function getRateLimitHistory(): Promise<{ history: RateLimitChange[] }> {
  return request('GET', '/settings/rate-limit-history');
}

export function clearRateLimitHistory(): Promise<{ history: RateLimitChange[] }> {
  return request('DELETE', '/settings/rate-limit-history', { query: { all: 1 } });
}

export interface GuardStatus {
  latest: number;
  installed: number | null;
  up_to_date: boolean;
  device_count: number;
  outdated_count: number;
}

export function getGuardStatus(): Promise<GuardStatus> {
  return request('GET', '/settings/guard-status');
}

export function getSelfProtection(): Promise<{ enabled: boolean }> {
  return request('GET', '/settings/self-protection');
}

export function setSelfProtection(enabled: boolean): Promise<{ enabled: boolean }> {
  return request('PUT', '/settings/self-protection', { body: { enabled } });
}

// ── Local log storage (hooks mirror the audit trail to a file on the agent) ─

export interface LocalLogsConfig {
  enabled: boolean;
  path: string;
}

export function getLocalLogs(): Promise<LocalLogsConfig> {
  return request('GET', '/settings/local-logs');
}

/** The API forces `enabled:false` when `path` is empty — set a path first. */
export function setLocalLogs(cfg: LocalLogsConfig): Promise<LocalLogsConfig> {
  return request('PUT', '/settings/local-logs', { body: cfg });
}


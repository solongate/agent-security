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

// ── Denial alerts (Telegram / email on a signal spike) ─────────────────────

export interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  threshold: number;
  windowSeconds: number;
  signal: 'any' | 'deny' | 'dlp' | 'ratelimit';
  slackUrls?: string[];
  emails?: string[];
  telegram?: string[];
  createdAt: string;
}

export function getAlerts(): Promise<{ rules: AlertRule[] }> {
  return request('GET', '/settings/denial-alerts');
}

export function createAlert(body: Partial<AlertRule> & { emails?: string[]; telegram?: string[]; slackUrl?: string }): Promise<{ rule: AlertRule }> {
  return request('POST', '/settings/denial-alerts', { body });
}

export function deleteAlert(id: string): Promise<{ ok: true }> {
  return request('DELETE', '/settings/denial-alerts', { query: { id } });
}

export function setAlertEnabled(id: string, enabled: boolean): Promise<{ ok: true }> {
  return request('PATCH', '/settings/denial-alerts', { query: { id }, body: { enabled } });
}

export function updateAlert(
  id: string,
  patch: { signal?: AlertRule['signal']; threshold?: number; windowSeconds?: number; emails?: string[]; telegram?: string[]; enabled?: boolean },
): Promise<{ rule: AlertRule }> {
  return request('PATCH', '/settings/denial-alerts', { query: { id }, body: patch });
}

// NOTE: no send-test for alerts. Delivering a real message to an arbitrary
// email/telegram on demand is an abuse/rate-limit vector — only webhooks (POST
// to the user's own url) are testable.

// ── Denial webhooks (stream every event to a URL) ──────────────────────────

export interface DenialWebhook {
  id: string;
  url: string;
  enabled: boolean;
  events: 'denials' | 'allowed' | 'all';
  headers?: Record<string, string>;
  createdAt: string;
}

export function getWebhooks(): Promise<{ webhooks: DenialWebhook[] }> {
  return request('GET', '/settings/denial-webhook');
}

export function createWebhook(body: { url: string; events?: 'denials' | 'allowed' | 'all'; headers?: Record<string, string> }): Promise<{ webhook: DenialWebhook }> {
  return request('POST', '/settings/denial-webhook', { body });
}

export function deleteWebhook(id: string): Promise<{ ok: true }> {
  return request('DELETE', '/settings/denial-webhook', { query: { id } });
}

export function sendTestWebhook(id: string): Promise<{ delivered: boolean }> {
  return request('POST', '/settings/denial-webhook/send-test', { body: { id } });
}

export function updateWebhook(id: string, patch: { enabled?: boolean; events?: DenialWebhook['events'] }): Promise<{ ok: true }> {
  return request('PATCH', '/settings/denial-webhook', { body: { id, ...patch } });
}

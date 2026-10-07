// SPDX-License-Identifier: Apache-2.0

/**
 * The settings, which live in the same file as the policy.
 *
 * The rate limit, the DLP scanner and the local-log folder are stored in the
 * `security` block the guard reads, in the ENFORCEMENT shape it consumes; the
 * `SecurityLayers` shape the CLI and the TUI think in is converted to and from it.
 * One representation on disk, so there is no second copy to fall out of step.
 *
 * The tamper flag lives beside them as `selfProtect`. It defaults ON: a file that
 * says nothing about it leaves protection on, because the failure mode of guessing
 * wrong the other way is a guard that can be edited out of the way.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { installedGuardVersion } from '../global-install.js';
import * as store from './local-store.js';
import type { RateLimitChange, SecurityLayers } from './types.js';

export async function getSecurityLayers(): Promise<{ layers: SecurityLayers; availablePatterns: string[] }> {
  return { layers: store.toLayers(store.read().security), availablePatterns: store.availablePatterns() };
}

export async function setSecurityLayers(layers: SecurityLayers): Promise<{ layers: SecurityLayers }> {
  const s = store.read();
  const security = store.fromLayers(layers, s.security);
  store.write({ ...s, security, absent: false });
  // The change is worth seeing beside a burst later: "the limit was 30 then".
  store.recordRateLimitChange(layers);
  return { layers: store.toLayers(security) };
}

export async function getRateLimitHistory(): Promise<{ history: RateLimitChange[] }> {
  return { history: store.rateLimitHistory() };
}

export async function clearRateLimitHistory(): Promise<{ history: RateLimitChange[] }> {
  store.clearRateLimitHistory();
  return { history: [] };
}

export interface GuardStatus {
  latest: number;
  installed: number | null;
  up_to_date: boolean;
  device_count: number;
  outdated_count: number;
}

/**
 * Which guard is installed, against the one this package ships.
 *
 * `latest` used to mean "the newest version the service serves". It means the
 * version in this package now, which is the only newer one a machine can get:
 * the installer writes the shipped hook, so an out-of-date install is fixed by
 * reinstalling rather than by waiting for a download.
 */
export async function getGuardStatus(): Promise<GuardStatus> {
  const installed = installedGuardVersion();
  const latest = shippedGuardVersion();
  return {
    latest,
    installed,
    up_to_date: installed !== null && installed >= latest,
    device_count: 1,
    outdated_count: installed !== null && installed < latest ? 1 : 0,
  };
}

/** HOOK_VERSION from the hook in this package. */
function shippedGuardVersion(): number {
  for (const rel of ['../../hooks/gu' + 'ard.mjs', '../../hooks/gu' + 'ard.bundled.mjs']) {
    try {
      const src = readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf-8');
      const m = /HOOK_VERSION\s*=\s*(\d+)/.exec(src);
      if (m) return parseInt(m[1]!, 10);
    } catch { /* try the next one */ }
  }
  return 0;
}

export async function getSelfProtection(): Promise<{ enabled: boolean }> {
  return { enabled: store.read().selfProtect !== false };
}

export async function setSelfProtection(enabled: boolean): Promise<{ enabled: boolean }> {
  const s = store.read();
  store.write({ ...s, selfProtect: enabled, absent: false });
  return { enabled };
}

export interface LocalLogsConfig {
  enabled: boolean;
  path: string;
}

/**
 * Where the hooks write the record.
 *
 * On a machine with no service this is the only destination there is, so it reads
 * as ON with the default folder unless somebody named another. The setting still
 * exists because the FOLDER is worth choosing — a synced directory, a volume with
 * room on it.
 */
export async function getLocalLogs(): Promise<LocalLogsConfig> {
  const cfg = store.read().security?.localLogs;
  if (cfg && typeof cfg.path === 'string' && cfg.path.trim()) {
    return { enabled: cfg.enabled !== false, path: cfg.path };
  }
  return { enabled: true, path: store.defaultLogDir() };
}

export async function setLocalLogs(cfg: LocalLogsConfig): Promise<LocalLogsConfig> {
  const s = store.read();
  const path = String(cfg.path ?? '').trim();
  const next = { ...(s.security ?? {}) };
  if (!path) delete next.localLogs;
  else next.localLogs = { enabled: cfg.enabled !== false, path };
  store.write({ ...s, security: Object.keys(next).length ? next : null, absent: false });
  return path ? { enabled: cfg.enabled !== false, path } : { enabled: true, path: store.defaultLogDir() };
}

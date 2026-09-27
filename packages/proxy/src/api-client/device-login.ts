/**
 * Device-pairing flow, usable from the CLI `login` command AND the dataroom's
 * Accounts panel. Split from login.ts so the TUI can render the verify URL and
 * drive the poll loop itself (no console output here).
 */
import { spawn } from 'node:child_process';
import { DEFAULT_API_URL } from './client.js';

export interface DeviceStart {
  deviceCode: string;
  verifyUrl: string;
  intervalMs: number;
  expiresAt: number;
}

export interface DevicePoll {
  status: 'pending' | 'approved' | 'expired' | 'not_found';
  apiKey?: string;
  project?: string;
  user?: string;
  email?: string;
}

/** Best-effort browser open. No-op on failure (headless / missing opener). */
export function openBrowser(url: string): void {
  try {
    const cmd = process.platform === 'win32' ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
    const args = process.platform === 'win32' ? ['/c', 'start', '""', url] : [url];
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', () => {});
    child.unref();
  } catch {
    /* user opens the printed URL manually */
  }
}

export async function startDeviceLogin(apiUrl: string = DEFAULT_API_URL): Promise<DeviceStart> {
  const res = await fetch(`${apiUrl}/api/v1/auth/device/start`, { method: 'POST' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const j = (await res.json()) as {
    device_code: string;
    verification_uri_complete?: string;
    verification_uri?: string;
    interval?: number;
    expires_in?: number;
  };
  return {
    deviceCode: j.device_code,
    verifyUrl: j.verification_uri_complete || j.verification_uri || '',
    intervalMs: Math.max(2, Number(j.interval) || 3) * 1000,
    expiresAt: Date.now() + (Number(j.expires_in) || 600) * 1000,
  };
}

export async function pollDeviceLogin(apiUrl: string, deviceCode: string): Promise<DevicePoll> {
  try {
    const res = await fetch(`${apiUrl}/api/v1/auth/device/poll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_code: deviceCode }),
    });
    const j = (await res.json().catch(() => ({}))) as {
      status?: string;
      api_key?: string;
      project?: { name?: string };
      user?: { name?: string; email?: string };
    };
    if (j.status === 'approved' && j.api_key) {
      return { status: 'approved', apiKey: j.api_key, project: j.project?.name, user: j.user?.name || j.user?.email, email: j.user?.email };
    }
    if (j.status === 'expired' || j.status === 'not_found') return { status: j.status };
    return { status: 'pending' };
  } catch {
    return { status: 'pending' }; // transient — keep polling
  }
}

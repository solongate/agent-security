/**
 * Lifecycle manager for the logs-server as a BACKGROUND service.
 *
 * The desired state lives in ~/.solongate/.logs-server.json and is the source
 * of truth: once enabled (from the dataroom Settings or by running
 * `solongate logs-server`), the server must keep existing until the user
 * DISABLES it — closing the dataroom, the terminal, or Ctrl+C only kills the
 * process, and the next human CLI invocation resurrects it (ensure…). Only an
 * explicit stop (Settings row → enter) flips desired to 'off'.
 *
 * The daemon is a plain detached `node dist/index.js logs-server` with output
 * appended to ~/.solongate/logs-server.log — no OS service files involved.
 */
import { spawn } from 'node:child_process';
import { mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = join(homedir(), '.solongate');
const STATE_FILE = join(DIR, '.logs-server.json');
const LOG_FILE = join(DIR, 'logs-server.log');
export const LOGS_SERVER_PORT = 8788;

interface DaemonFile {
  desired?: 'on' | 'off';
  pid?: number;
  port?: number;
  startedAt?: number;
}

function readState(): DaemonFile {
  try {
    const s = JSON.parse(readFileSync(STATE_FILE, 'utf-8')) as DaemonFile;
    return s && typeof s === 'object' ? s : {};
  } catch {
    return {};
  }
}

function writeState(s: DaemonFile): void {
  try {
    mkdirSync(DIR, { recursive: true });
    writeFileSync(STATE_FILE, JSON.stringify(s));
  } catch {
    /* best-effort */
  }
}

function pidAlive(pid?: number): boolean {
  if (!pid || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM'; // exists, not ours
  }
}

export interface LogsServerStatus {
  desired: 'on' | 'off';
  running: boolean;
  pid?: number;
  port: number;
}

export function logsServerStatus(): LogsServerStatus {
  const s = readState();
  const running = pidAlive(s.pid);
  return { desired: s.desired === 'on' ? 'on' : 'off', running, pid: running ? s.pid : undefined, port: s.port || LOGS_SERVER_PORT };
}

/** Called from runLogsServer when a (foreground or daemon) server starts. */
export function recordLogsServerStarted(port: number): void {
  writeState({ desired: 'on', pid: process.pid, port, startedAt: Date.now() });
}

/** Spawn the detached daemon (idempotent — no-op when already running). */
export function startLogsServerDaemon(): LogsServerStatus {
  const cur = logsServerStatus();
  if (cur.running) {
    writeState({ ...readState(), desired: 'on' });
    return { ...cur, desired: 'on' };
  }
  try {
    mkdirSync(DIR, { recursive: true });
    const log = openSync(LOG_FILE, 'a');
    // dist/index.js sits next to this module in the published bundle.
    const cli = join(dirname(fileURLToPath(import.meta.url)), 'index.js');
    const p = spawn(process.execPath, [cli, 'logs-server'], {
      detached: true,
      stdio: ['ignore', log, log],
      windowsHide: true,
      // Spawned by US, not by an agent: exempt from the human-only TTY gate
      // (a detached daemon has no terminal by definition).
      env: { ...process.env, SOLONGATE_INTERNAL: '1' },
    });
    p.on('error', () => {});
    p.unref();
    writeState({ desired: 'on', pid: p.pid, port: LOGS_SERVER_PORT, startedAt: Date.now() });
    return { desired: 'on', running: true, pid: p.pid, port: LOGS_SERVER_PORT };
  } catch {
    return { ...cur, desired: 'on', running: false };
  }
}

/** Explicit disable — the ONLY thing that flips desired to 'off'. */
export function stopLogsServerDaemon(): LogsServerStatus {
  const s = readState();
  if (pidAlive(s.pid)) {
    try {
      process.kill(s.pid!);
    } catch {
      /* already gone */
    }
  }
  writeState({ desired: 'off', port: s.port });
  return { desired: 'off', running: false, port: s.port || LOGS_SERVER_PORT };
}

/**
 * Resurrect the daemon when it SHOULD be running but isn't (machine reboot,
 * Ctrl+C on a foreground run, crash). Called from every human CLI startup.
 */
export function ensureLogsServerDaemon(): void {
  try {
    const s = logsServerStatus();
    if (s.desired === 'on' && !s.running) startLogsServerDaemon();
  } catch {
    /* never disturb the CLI */
  }
}

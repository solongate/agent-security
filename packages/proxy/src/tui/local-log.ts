/** Shared access to the machine-local audit log written by the hooks. */
import { closeSync, existsSync, openSync, readdirSync, readFileSync, readSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';
import { isAbsolute, join } from 'node:path';

/** Where the hooks write when local logging is on but NO custom folder is set
 *  (also the fallback they use for a path that isn't absolute on this device). */
export const DEFAULT_LOCAL_LOG = join(homedir(), '.solongate', 'local-logs', 'solongate-audit.jsonl');

/**
 * The local log file THIS device is actually writing to.
 *
 * Local logging takes a FOLDER from the dashboard, and the hooks append
 * `solongate-audit.jsonl` inside it — so a user who set, say, `/home/me/` gets
 * `/home/me/solongate-audit.jsonl`. Every viewer here used to read the DEFAULT
 * folder unconditionally, so with a custom folder configured the dataroom,
 * `watch` and `doctor` all showed an empty (or stale) log while entries were
 * landing correctly somewhere else — "local logs stopped working".
 *
 * The folder lives in the policy cache the hooks themselves read
 * (~/.solongate/.policy-cache-<agent>.json → security.localLogs), so we resolve
 * it the same way they do, preferring the most recently refreshed cache. Falls
 * back to the default path when nothing is configured or readable.
 */
/** What local logging is set to on this device, and where it can actually go. */
export interface LocalLogSetting {
  /** The project setting, as the hooks read it. */
  enabled: boolean;
  /** The folder the project asked for, verbatim (null when nothing is set). */
  configuredPath: string | null;
  /** False when that folder cannot be used HERE — e.g. a Windows path on Linux. */
  usableHere: boolean;
  /** The file entries actually land in, after any fallback. */
  file: string;
}

/**
 * Read the local-logging SETTING, not its output.
 *
 * Live used to decide on/off by whether the log file had any lines in it, so an
 * enabled log that happened to be empty — a fresh install, a folder just
 * changed, an account just switched — reported "local logs off" and told the
 * user to go and enable something that was already on. The setting and the
 * evidence of the setting are different questions; this answers the first.
 */
export function localLogsSetting(): LocalLogSetting {
  const off: LocalLogSetting = { enabled: false, configuredPath: null, usableHere: true, file: DEFAULT_LOCAL_LOG };
  try {
    for (const cache of policyCachesNewestFirst()) {
      try {
        const c = JSON.parse(readFileSync(cache, 'utf-8')) as { security?: { localLogs?: { enabled?: boolean; path?: string } } };
        const l = c?.security?.localLogs;
        if (!l || typeof l.enabled !== 'boolean') continue; // no answer in this cache — try the next
        if (!l.enabled) return { ...off, configuredPath: typeof l.path === 'string' ? l.path.trim() || null : null };
        const raw = typeof l.path === 'string' ? l.path.trim() : '';
        const dir = raw.replace(/[\\/]+$/, '');
        if (!dir) return { enabled: true, configuredPath: null, usableHere: true, file: DEFAULT_LOCAL_LOG };
        // Not absolute HERE means the hooks cannot use it and fall back — the
        // usual cause is a folder set from another OS (a "C:/..." on Linux).
        if (!isAbsolute(dir)) return { enabled: true, configuredPath: raw, usableHere: false, file: DEFAULT_LOCAL_LOG };
        const file = join(dir, 'solongate-audit.jsonl');
        const usable = existsSync(file) || existsSync(dir);
        return { enabled: true, configuredPath: raw, usableHere: usable, file: usable ? file : DEFAULT_LOCAL_LOG };
      } catch { /* try the next cache */ }
    }
  } catch { /* no ~/.solongate */ }
  return off;
}

/** Policy caches on this device, most recently refreshed first. */
function policyCachesNewestFirst(): string[] {
  const sgDir = join(homedir(), '.solongate');
  return readdirSync(sgDir)
    .filter((f) => f.startsWith('.policy-cache-') && f.endsWith('.json'))
    .map((f) => {
      const p = join(sgDir, f);
      let mtime = 0;
      try { mtime = statSync(p).mtimeMs; } catch { /* skip */ }
      return { p, mtime };
    })
    .sort((a, b) => b.mtime - a.mtime)
    .map((x) => x.p);
}

export function localLogFile(): string {
  try {
    const sgDir = join(homedir(), '.solongate');
    const caches = readdirSync(sgDir)
      .filter((f) => f.startsWith('.policy-cache-') && f.endsWith('.json'))
      .map((f) => {
        const p = join(sgDir, f);
        let mtime = 0;
        try { mtime = statSync(p).mtimeMs; } catch { /* skip */ }
        return { p, mtime };
      })
      .sort((a, b) => b.mtime - a.mtime);
    for (const { p } of caches) {
      try {
        const c = JSON.parse(readFileSync(p, 'utf-8')) as { security?: { localLogs?: { enabled?: boolean; path?: string } } };
        const l = c?.security?.localLogs;
        if (!l || !l.enabled || typeof l.path !== 'string' || !l.path.trim()) continue;
        // Mirrors resolveLocalLogDir() in audit.mjs: strip trailing separators,
        // and treat a non-absolute path (e.g. a Windows path read on Linux) as
        // "use the default folder" — which is exactly where the hooks put it.
        const dir = l.path.trim().replace(/[\\/]+$/, '');
        if (!dir) continue;
        if (!isAbsolute(dir)) return DEFAULT_LOCAL_LOG;
        // The folder is a PROJECT setting, so it can name a path that only
        // exists on another device (a Linux "/home/me" on a Mac). The hooks then
        // fall back to the default folder and drop a marker — follow them, or
        // this device would read an empty file that is never written.
        const file = join(dir, 'solongate-audit.jsonl');
        if (existsSync(file)) return file;
        return existsSync(dir) ? file : DEFAULT_LOCAL_LOG;
      } catch { /* try the next cache */ }
    }
  } catch { /* no ~/.solongate — fall through */ }
  return DEFAULT_LOCAL_LOG;
}

/** Resolved once per process for callers that want a plain path (the folder can
 *  only change via a dashboard edit, which needs a new session anyway). Prefer
 *  localLogFile() in long-lived views so a mid-session change is picked up. */
export const LOCAL_LOG = localLogFile();

/** True when the resolved file exists — viewers use it to say "no entries yet"
 *  instead of pointing at a path that was never written. */
/**
 * Make sure the local log belongs to the account now in use.
 *
 * The file is one per machine and no entry records which account produced it,
 * so after pairing a different account the previous one's calls were still
 * sitting in Live. Clearing on an in-app account switch was not enough: the
 * account can change by pairing a new device, by signing out, or from the
 * dashboard. A marker beside the log records whose it is (a hash, never the
 * key itself); when that stops matching, the file is not ours and is started
 * over. Returns true when it cleared.
 */
export function ensureLocalLogOwner(activeApiKey: string | null | undefined): boolean {
  try {
    const marker = join(homedir(), '.solongate', 'local-logs', '.owner');
    const want = activeApiKey ? createHash('sha256').update(activeApiKey).digest('hex').slice(0, 16) : '';
    let have = '';
    try { have = readFileSync(marker, 'utf-8').trim(); } catch { /* first run */ }
    if (have === want) return false;
    // Nothing is deleted any more. Entries carry the account that wrote them
    // and readers keep only their own, so a change of account separates the
    // history instead of destroying it. The marker is kept purely as a record.
    try { writeFileSync(marker, want); } catch { /* not writable; retried next run */ }
    return false;
  } catch {
    return false;
  }
}

export function localLogExists(): boolean {
  return existsSync(localLogFile());
}

/** Read the last `maxBytes` of a file as complete lines (first partial dropped). */
export function tailLines(file: string, maxBytes = 131_072): string[] {
  try {
    const size = statSync(file).size;
    const start = Math.max(0, size - maxBytes);
    const fd = openSync(file, 'r');
    const buf = Buffer.alloc(size - start);
    readSync(fd, buf, 0, buf.length, start);
    closeSync(fd);
    const lines = buf.toString('utf-8').split('\n').filter(Boolean);
    if (start > 0) lines.shift();
    return lines;
  } catch {
    return [];
  }
}

/** One parsed line of the local audit JSONL (fields are best-effort). */
export interface LocalLogLine {
  ts?: string;
  tool?: string;
  decision?: string;
  reason?: string;
  arguments?: unknown;
  dlp?: unknown;
  permission?: string;
  trust_level?: string;
  session_id?: string;
  /** Hash prefix of the account that wrote this line. */
  acct?: string;
  agent_name?: string;
  evaluation_time_ms?: number;
  matched_rule_id?: string;
  rate_limit_burst?: boolean;
}

/*
 * There is no deleteLocalEntry any more. It backed the Audit panel's x key,
 * which is gone with the rest of the delete surface: the cloud log has no
 * delete endpoint, and a TUI that could still take one line out of the local
 * mirror would be the one place left that edits history.
 *
 * clearLocalLog stays, and is a different thing. It empties the file when the
 * ACCOUNT changes, because the file is per machine rather than per account and
 * the alternative is showing one account's calls under another's name.
 */

/**
 * Empty the local log file. Returns how many lines were removed.
 *
 * The file is one per machine, not one per account, and nothing in an entry
 * says which account produced it — so when the account changes, the honest move
 * is to start it over rather than keep showing another account's calls in Live.
 */
export function clearLocalLog(): number {
  try {
    const file = localLogFile();
    const n = readFileSync(file, 'utf-8').split('\n').filter(Boolean).length;
    writeFileSync(file, '');
    return n;
  } catch {
    return 0;
  }
}

// The guard writes a DENY reason like "Security layer (DLP): blocked -
// arguments contain a Anthropic key" / "Security layer (rate limit): exceeded
// N calls/…" to BOTH cloud and local at block time, and it is never redacted —
// so it is the reliable signal source when the dlp/burst fields aren't stored
// and an arguments re-scan misses the (redacted/blocked) value.
const DLP_REASON = /security layer \(dlp\)/i;
const RL_REASON = /security layer \(rate limit\)|rate[- ]?limit(?:ed)?\b.*exceed|exceeded \d+ calls/i;

/** DLP pattern name + rate-limit-burst flag derived from a decision's reason. */
export function reasonSignals(reason: string | null | undefined): { dlp: string[]; burst: boolean } {
  const r = reason || '';
  const dlp: string[] = [];
  if (DLP_REASON.test(r)) {
    const m = r.match(/contain(?:s)? (?:a |an )?(.+?)(?:\.|$)/i);
    dlp.push(m ? m[1]!.trim() : 'DLP');
  }
  return { dlp, burst: RL_REASON.test(r) };
}

/**
 * The mark the hooks stamp on lines written by the account this device
 * enforces with. Readers keep only their own, so changing account separates the
 * history rather than destroying it.
 */
function ownMark(): string {
  try {
    const p = join(homedir(), '.solongate', 'cloud' + '-guard.json');
    const c = JSON.parse(readFileSync(p, 'utf-8')) as { apiKey?: string };
    return c?.apiKey ? createHash('sha256').update(c.apiKey).digest('hex').slice(0, 16) : '';
  } catch {
    return '';
  }
}

export function parseLocalLines(lines: string[]): Array<LocalLogLine & { at: number }> {
  const out: Array<LocalLogLine & { at: number }> = [];
  const mine = ownMark();
  for (const line of lines) {
    try {
      const j = JSON.parse(line) as LocalLogLine;
      // Written by a different account. Unstamped lines predate the mark and
      // cannot be attributed, so they stay out rather than pass as ours.
      if (mine && j.acct !== mine) continue;
      const at = Date.parse(j.ts ?? '');
      if (Number.isFinite(at)) out.push({ ...j, at });
    } catch {
      /* partial line */
    }
  }
  return out;
}

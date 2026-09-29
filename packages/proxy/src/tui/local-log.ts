/** Shared access to the machine-local audit log written by the hooks. */
import { closeSync, existsSync, openSync, readFileSync, readSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
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
 * WHERE this machine's audit trail is, resolved the way the HOOKS resolve it.
 *
 * Local logging takes a FOLDER and the hooks append solongate-audit.jsonl inside it,
 * so a policy naming /home/me gets /home/me/solongate-audit.jsonl. Every viewer used
 * to read the DEFAULT folder unconditionally, so with a custom folder configured the
 * dataroom, `watch` and `doctor` all showed an empty log while entries were landing
 * somewhere else.
 *
 * IT READS THE POLICY FILE. Both of these functions used to read the policy CACHES,
 * newest first — a service's answer, kept per agent — and nothing has written one since
 * the refresh was removed. So localLogsSetting returned `off` on every machine, and off
 * is not cosmetic: the Live panel SKIPS READING THE LOG when it is told off. The guard
 * wrote entries and no viewer showed them.
 *
 * `enabled` is reported TRUE always, and that is the honest answer rather than a
 * simplification. While there was a service the choice was real — entries went there OR
 * to a file, never both — so `false` meant "do not write locally". With nowhere to send
 * them, both writers ignore the flag and record unconditionally; the setting chooses
 * only the folder. A viewer honouring a `false` would refuse to read a file that is
 * being written. internal/config/locallogs.go says the same in Go.
 */
export function localLogsSetting(): LocalLogSetting {
  const def: LocalLogSetting = {
    enabled: true, configuredPath: null, usableHere: true, file: DEFAULT_LOCAL_LOG,
  };
  try {
    const p = join(homedir(), '.solongate', 'pol' + 'icy.json');
    if (!existsSync(p)) return def;
    const obj = JSON.parse(readFileSync(p, 'utf-8')) as {
      security?: { localLogs?: { enabled?: boolean; path?: string } };
      policy?: { security?: { localLogs?: { enabled?: boolean; path?: string } } };
    };
    // Both spellings: the envelope, and a policy document carrying `security` inside
    // it. Every other reader on this machine accepts both, and one that did not would
    // look in a different folder than the hooks write to.
    const l = obj?.security?.localLogs ?? obj?.policy?.security?.localLogs;
    if (!l) return def;

    const raw = typeof l.path === 'string' ? l.path.trim() : '';
    const dir = raw.replace(/[\\/]+$/, '');
    if (!dir) return def;
    // Not absolute HERE means the hooks cannot use it and fall back — the usual cause
    // is a folder set from another OS (a "C:/..." on Linux, which Node would treat as
    // relative and create inside whatever repository the agent happened to run in).
    if (!isAbsolute(dir)) return { enabled: true, configuredPath: raw, usableHere: false, file: DEFAULT_LOCAL_LOG };
    const file = join(dir, 'solongate-audit.jsonl');
    const usable = existsSync(file) || existsSync(dir);
    return { enabled: true, configuredPath: raw, usableHere: usable, file: usable ? file : DEFAULT_LOCAL_LOG };
  } catch {
    return def;
  }
}

/**
 * The file this machine is actually writing to.
 *
 * Long-lived views should call this rather than caching the answer: the folder can
 * change under them when somebody edits the policy mid-session.
 *
 * It used to walk the caches itself, with a copy of the resolution above that had
 * drifted from it in one respect — it returned the default when the folder did not
 * exist, where the setting reported `usableHere: false` and the default. One
 * resolution, one answer.
 */
export function localLogFile(): string {
  return localLogsSetting().file;
}

/** Resolved once per process for callers that want a plain path (the folder can
 *  only change via a dashboard edit, which needs a new session anyway). Prefer
 *  localLogFile() in long-lived views so a mid-session change is picked up. */
export const LOCAL_LOG = localLogFile();

/** True when the resolved file exists — viewers use it to say "no entries yet"
 *  instead of pointing at a path that was never written. */
// ensureLocalLogOwner stood here. It wrote a `.owner` marker beside the log holding a
// hash of the account in use, so a change of account could be noticed — one file per
// machine, and no entry recorded who produced it, so after pairing a different account
// the previous one's calls were still sitting in Live. By the end it deleted nothing and
// only kept the marker up to date.
//
// Nothing calls it, there are no accounts, and the `acct` stamp it paired with is gone
// from both guards. internal/tui/app.go dropped its Go twin at the same time.

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
// ownMark lived here: a 16-character hash of the credential, which the hooks stamped
// on every line they wrote as `acct`. parseLocalLines kept only the lines carrying it,
// because one machine's log could hold two accounts' calls and after pairing a
// different account the previous one's kept showing up.
//
// Nothing stamps it. Keeping the filter would have been destructive rather than dead: a
// credential file left behind by an older install makes the mark non-empty, and then
// every line written since would be dropped as somebody else's — Live would go blank on
// exactly the machines that had been upgraded. internal/tui/locallog.go had the same
// filter and lost it at the same time.

export function parseLocalLines(lines: string[]): Array<LocalLogLine & { at: number }> {
  const out: Array<LocalLogLine & { at: number }> = [];
  for (const line of lines) {
    try {
      const j = JSON.parse(line) as LocalLogLine;
      const at = Date.parse(j.ts ?? '');
      if (Number.isFinite(at)) out.push({ ...j, at });
    } catch {
      /* partial line */
    }
  }
  return out;
}

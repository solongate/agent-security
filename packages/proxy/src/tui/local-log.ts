/** Shared access to the machine-local audit log written by the hooks. */
import { closeSync, existsSync, openSync, readFileSync, readSync, statSync, writeFileSync } from 'node:fs';
import { DEFAULT_LOG_FILE, localLogFile, policyPath } from '../api-client/local-store.js';

/**
 * WHERE THIS MACHINE'S AUDIT TRAIL IS — one resolution, in the store.
 *
 * It used to be resolved here, twice: once in localLogsSetting and once in a copy inside
 * localLogFile that had drifted from it. Both read the policy CACHES, newest first,
 * because that is where a service's answer was kept — and nothing has written one since
 * the refresh was removed, so both returned "off, default folder" on every machine. That
 * is not cosmetic: the Live panel SKIPS READING THE LOG when it is told off, so the guard
 * wrote entries and no viewer showed them.
 *
 * The answer now comes from the api-client store, which is the lower layer and the same
 * one `solongate audit` and `solongate stats` read through — so a custom folder cannot be
 * honoured by one surface and ignored by another. internal/config/locallogs.go is the Go
 * side of the same question.
 */
export const DEFAULT_LOCAL_LOG = DEFAULT_LOG_FILE();

/** What local logging is set to on this device, and where it can actually go. */
export interface LocalLogSetting {
  /**
   * ALWAYS TRUE, and the field stays because the panels read it.
   *
   * It used to mean what it says. While there was a service the choice was real —
   * entries went there OR to a file, never both — so `false` meant "do not write
   * locally". With nowhere to send them, both writers ignore the flag and record
   * unconditionally; the setting chooses only the folder. A viewer honouring a `false`
   * would refuse to read a file that is being written.
   */
  enabled: boolean;
  /** The folder the policy asked for, verbatim (null when it names none). */
  configuredPath: string | null;
  /** False when that folder cannot be used HERE — e.g. a Windows path on Linux. */
  usableHere: boolean;
  /** The file entries actually land in, after any fallback. */
  file: string;
}

/**
 * The setting, for the surfaces that show the user what is configured and whether it
 * can be honoured here. The FILE comes from the store; this adds only the two things a
 * display needs that a reader does not: what was asked for, and whether it worked.
 */
export function localLogsSetting(): LocalLogSetting {
  const file = localLogFile();
  let configuredPath: string | null = null;
  try {
    const obj = JSON.parse(readFileSync(policyPath(), 'utf-8')) as {
      security?: { localLogs?: { path?: string } };
      policy?: { security?: { localLogs?: { path?: string } } };
    };
    const raw = (obj?.security?.localLogs ?? obj?.policy?.security?.localLogs)?.path;
    if (typeof raw === 'string' && raw.trim()) configuredPath = raw;
  } catch { /* no policy, or half a policy: nothing was asked for */ }

  // Usable HERE means the hooks could use it: the store falls back to the default file
  // for a folder that is not a location on this machine (a "C:/logs" on Linux, or one
  // that does not exist), so a configured path that did not survive is the signal.
  const usableHere = configuredPath === null || file !== DEFAULT_LOG_FILE();
  return { enabled: true, configuredPath, usableHere, file };
}

export { localLogFile };

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

/**
 * The store behind every command and every panel: two files on this machine.
 *
 *   ~/.solongate/policy.json                      the policy, and the layers
 *   ~/.solongate/local-logs/solongate-audit.jsonl what the hooks recorded
 *
 * There is no service. This module is what `api.policies`, `api.settings`,
 * `api.audit` and `api.stats` are made of — they kept their names and their
 * types, because the CLI and the TUI are written against those and both work
 * unchanged when the transport underneath is a file.
 *
 * THE POLICY FILE IS SHARED WITH THE GUARD, which is the constraint that shapes
 * everything here. The guard reads it on every tool call, in two spellings:
 *
 *   {"policy": {…}, "security": {…}, "selfProtect": true}   the envelope
 *   {"mode": "denylist", "rules": [ … ], "security": {…}}   the policy alone
 *
 * Both are read, and WHICHEVER ONE A PERSON WROTE IS WHAT GETS WRITTEN BACK. A
 * hand-written bare policy stays bare after `solongate policy deny …` — quietly
 * reshaping somebody's file into an envelope would be a surprise, and the guard
 * reads either.
 *
 * `security` is stored in the ENFORCEMENT shape, the one the guard consumes, and
 * converted to and from the `SecurityLayers` shape the CLI thinks in. One
 * representation on disk, no second copy to fall out of step: the conversion is
 * exactly invertible, and asserted to be.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { DLP_PATTERN_NAMES } from '../dlp-patterns.js';
import type {
  AuditEntry,
  AuditList,
  LayerMode,
  PolicyRule,
  PolicySet,
  RateLimitChange,
  SecurityLayers,
} from './types.js';

/** Owner-only, the same numbers the hooks and sgshared use. */
const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

export const sgDir = (): string => resolve(homedir(), '.solongate');
export const policyPath = (): string => join(sgDir(), 'poli' + 'cy.json');
const historyPath = (): string => join(sgDir(), 'rate-limit-history.json');
const localLogPath = (): string => join(sgDir(), 'local-logs', 'solongate-audit.jsonl');

/** The folder the hooks write to when nobody named another. */
export const defaultLogDir = (): string => join(sgDir(), 'local-logs');

/** Raised for the cases a service used to answer with a 404 or a 409. */
export class LocalStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LocalStoreError';
  }
}

// ── The guard's `security` shape ─────────────────────────────────────────────
//
// Pointers-as-optionals, exactly as the guard reads them: an ABSENT key and a
// key set to null are the same answer here ("this layer is off"), which is why
// the conversion below can be lossless in both directions.

interface DlpRules {
  patterns: string[];
  custom: { name: string; re: string }[];
}

interface RateLimitNumbers {
  perMinute: number;
  perHour: number;
  perDay: number;
}

export interface GuardSecurity {
  rateLimit?: RateLimitNumbers | null;
  rateLimitObserve?: RateLimitNumbers | null;
  dlpBlock?: DlpRules | null;
  dlpRedact?: DlpRules | null;
  localLogs?: { enabled: boolean; path: string } | null;
}

interface Stored {
  /** The policy, or null when the file holds only layers. */
  policy: PolicySet | null;
  security: GuardSecurity | null;
  selfProtect: boolean | null;
  /** Whether the file was written as an envelope. Preserved on write. */
  envelope: boolean;
  /** True when there is no file at all. */
  absent: boolean;
}

const EMPTY: Stored = { policy: null, security: null, selfProtect: null, envelope: true, absent: true };

/** Read the file, in either spelling. An unreadable file is not an empty one. */
export function read(): Stored {
  const p = policyPath();
  if (!existsSync(p)) return { ...EMPTY };
  let raw: string;
  try {
    raw = readFileSync(p, 'utf-8');
  } catch (e) {
    throw new LocalStoreError(`cannot read ${p}: ${(e as Error).message}`);
  }
  let obj: unknown;
  try {
    obj = JSON.parse(raw);
  } catch (e) {
    // Reported rather than swallowed. Returning "no policy" for a file with a
    // stray comma would tell somebody their rules are gone when they are not —
    // and the guard, which fails the same way, would be enforcing nothing.
    throw new LocalStoreError(`${p} is not valid JSON: ${(e as Error).message}`);
  }
  if (!obj || typeof obj !== 'object') throw new LocalStoreError(`${p} does not hold a JSON object`);
  const o = obj as Record<string, unknown>;

  // The PRESENCE of a `policy` key makes it the envelope, even when its value is
  // null. A file carrying layers and NO RULES is a real configuration — DLP on,
  // nothing forbidden — and treating it as a bare policy read the whole envelope AS
  // the policy, which gave a nameless empty one instead of none.
  //
  // The guard's loader and the Go store draw the same line. Three readers of one
  // file disagreeing about it is the shape of bug this repository keeps finding.
  if ('policy' in o) {
    const inner = (o['policy'] ?? {}) as Record<string, unknown>;
    return {
      policy: o['policy'] ? (inner as unknown as PolicySet) : null,
      security: (o['security'] ?? inner['security'] ?? null) as GuardSecurity | null,
      selfProtect: typeof o['selfProtect'] === 'boolean' ? o['selfProtect'] : null,
      envelope: true,
      absent: false,
    };
  }
  // A bare policy. `security` inside it is how a service stores one, so it is the
  // shape a policy exported from a service arrives in.
  return {
    policy: o as unknown as PolicySet,
    security: (o['security'] ?? null) as GuardSecurity | null,
    selfProtect: typeof o['selfProtect'] === 'boolean' ? o['selfProtect'] : null,
    envelope: false,
    absent: false,
  };
}

/** Write the file back in the shape it was in. */
export function write(s: Stored): void {
  const doc: Record<string, unknown> = {};
  if (s.envelope) {
    doc['policy'] = s.policy ?? null;
    if (s.security) doc['security'] = s.security;
    if (s.selfProtect !== null) doc['selfProtect'] = s.selfProtect;
  } else {
    Object.assign(doc, s.policy ?? {});
    if (s.security) doc['security'] = s.security;
    else delete doc['security'];
    if (s.selfProtect !== null) doc['selfProtect'] = s.selfProtect;
  }
  const p = policyPath();
  mkdirSync(sgDir(), { recursive: true, mode: DIR_MODE });
  // Written through a temporary file and renamed. The guard reads this on EVERY
  // tool call, and a half-written file there is not a stale policy, it is an
  // unparseable one — which the guard reports as no policy at all.
  const tmp = p + '.tmp-' + process.pid;
  writeFileSync(tmp, JSON.stringify(doc, null, 2) + '\n', { mode: FILE_MODE });
  renameSync(tmp, p);
}

// ── SecurityLayers <-> the guard's shape ─────────────────────────────────────
//
// The same mapping the service applied (store.GuardEnforcementConfig): a rate
// limit in block mode is `rateLimit`, in detect mode `rateLimitObserve`, and
// never both. DLP in block mode sets `dlpBlock` AND `dlpRedact`, because blocking
// is the extra step over redacting; detect mode sets only `dlpRedact`.
//
// Which makes it invertible, and that is why there is one copy on disk: dlpBlock
// present means block, dlpRedact alone means detect, neither means off.

const ZERO_LIMITS: RateLimitNumbers = { perMinute: 0, perHour: 0, perDay: 0 };

export const DEFAULT_LAYERS: SecurityLayers = {
  rateLimit: { mode: 'off', perMinute: 0, perHour: 0, perDay: 0 },
  dlp: { mode: 'off', patterns: [], custom: [] },
};

export function toLayers(sec: GuardSecurity | null): SecurityLayers {
  const nums = sec?.rateLimit ?? sec?.rateLimitObserve ?? ZERO_LIMITS;
  const rlMode: LayerMode = sec?.rateLimit ? 'block' : sec?.rateLimitObserve ? 'detect' : 'off';
  const dlp = sec?.dlpBlock ?? sec?.dlpRedact ?? null;
  const dlpMode: LayerMode = sec?.dlpBlock ? 'block' : sec?.dlpRedact ? 'detect' : 'off';
  return {
    rateLimit: {
      mode: rlMode,
      perMinute: Number(nums.perMinute) || 0,
      perHour: Number(nums.perHour) || 0,
      perDay: Number(nums.perDay) || 0,
    },
    dlp: {
      mode: dlpMode,
      patterns: Array.isArray(dlp?.patterns) ? dlp!.patterns.slice() : [],
      custom: Array.isArray(dlp?.custom) ? dlp!.custom.slice() : [],
    },
  };
}

export function fromLayers(layers: SecurityLayers, keep: GuardSecurity | null): GuardSecurity {
  const out: GuardSecurity = {};
  // localLogs is not a layer the CLI edits here; it has its own setting, so it
  // survives a rate-limit or DLP change untouched.
  if (keep?.localLogs) out.localLogs = keep.localLogs;

  const nums: RateLimitNumbers = {
    perMinute: Number(layers.rateLimit.perMinute) || 0,
    perHour: Number(layers.rateLimit.perHour) || 0,
    perDay: Number(layers.rateLimit.perDay) || 0,
  };
  if (layers.rateLimit.mode === 'block') out.rateLimit = nums;
  else if (layers.rateLimit.mode === 'detect') out.rateLimitObserve = nums;

  const rules: DlpRules = {
    patterns: layers.dlp.patterns.slice(),
    custom: layers.dlp.custom.slice(),
  };
  if (layers.dlp.mode === 'block') {
    out.dlpBlock = rules;
    out.dlpRedact = rules;
  } else if (layers.dlp.mode === 'detect') {
    out.dlpRedact = rules;
  }
  return out;
}

export const availablePatterns = (): string[] => DLP_PATTERN_NAMES.slice();

// ── The policy ───────────────────────────────────────────────────────────────

/** The one policy this machine has, or null. */
export function policy(): PolicySet | null {
  return read().policy;
}

export function savePolicy(p: PolicySet): void {
  const s = read();
  write({ ...s, policy: p, absent: false });
}

/**
 * The id a machine's policy answers to.
 *
 * Every command takes one, because a service had many policies. A machine has
 * one file, so the id in the file is the only id there is — and `local` is
 * accepted as a name for it so nobody has to look the id up to edit their own
 * policy.
 */
export function resolveId(id: string | undefined, p: PolicySet | null): void {
  if (!p) throw new LocalStoreError('this machine has no policy. `solongate policy create <name>` writes one.');
  if (!id || id === p.id || id === 'local' || id === p.name) return;
  throw new LocalStoreError(
    `this machine's policy is ${p.id} (${p.name}); there is no ${id}. One file, one policy.`,
  );
}

export function nextRuleId(rules: PolicyRule[]): string {
  // Stable and readable, and it must not collide with a rule somebody wrote by
  // hand: keep counting past the highest `rule-N` already present.
  let max = 0;
  for (const r of rules) {
    const m = /^rule-(\d+)$/.exec(r.id || '');
    if (m) max = Math.max(max, parseInt(m[1]!, 10));
  }
  return `rule-${max + 1}`;
}

// ── The audit log ────────────────────────────────────────────────────────────

/** One line as the hooks write it. Everything is optional: they are versioned. */
interface LogLine {
  ts?: string;
  tool?: string;
  arguments?: unknown;
  decision?: string;
  reason?: string | null;
  permission?: string;
  session_id?: string | null;
  agent_id?: string | null;
  agent_name?: string | null;
  evaluation_time_ms?: number | null;
  dlp?: string[];
  rate_limit_burst?: boolean;
}

/**
 * Read the local log, newest first.
 *
 * The whole file is read and that is a deliberate bound rather than an oversight:
 * it is append-only with no rotation, so this caps what one call will hold in
 * memory at the same sixteen megabytes the other readers of this file use, taken
 * from the END because that is where the recent entries are.
 */
const MAX_LOG_BYTES = 16 * 1024 * 1024;

export function logLines(): Array<LogLine & { id: string; at: number }> {
  const f = localLogPath();
  if (!existsSync(f)) return [];
  let text: string;
  try {
    text = readFileSync(f, 'utf-8');
  } catch {
    return [];
  }
  if (text.length > MAX_LOG_BYTES) {
    const cut = text.length - MAX_LOG_BYTES;
    text = text.slice(text.indexOf('\n', cut) + 1);
  }
  const out: Array<LogLine & { id: string; at: number }> = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (!line.trim()) continue;
    let o: LogLine;
    try {
      o = JSON.parse(line) as LogLine;
    } catch {
      continue;
    }
    const at = o.ts ? Date.parse(o.ts) : NaN;
    out.push({ ...o, at: Number.isFinite(at) ? at : 0, id: String(i + 1) });
  }
  // Newest first, and the ORIGINAL line number is the id — so an id a person saw
  // still names the same entry after more lines are appended.
  return out.reverse();
}

export function toAuditEntry(l: LogLine & { id: string; at: number }): AuditEntry {
  const args = l.arguments && typeof l.arguments === 'object'
    ? (l.arguments as Record<string, unknown>)
    : l.arguments === undefined ? null : { value: l.arguments };
  return {
    id: l.id,
    request_id: l.id,
    session_id: l.session_id ?? null,
    tool_name: l.tool ?? '',
    server_name: 'local',
    permission: l.permission ?? 'READ',
    trust_level: 'UNTRUSTED',
    decision: l.decision ?? 'ALLOW',
    matched_rule_id: null,
    reason: l.reason ?? null,
    evaluation_time_ms: l.evaluation_time_ms ?? null,
    arguments_summary: args,
    dlp_matches: Array.isArray(l.dlp) ? l.dlp : [],
    rate_limit_burst: l.rate_limit_burst === true,
    agent_id: l.agent_id ?? null,
    agent_name: l.agent_name ?? null,
    created_at: l.ts ?? new Date(l.at || 0).toISOString(),
  };
}

export function auditList(query: {
  limit?: number;
  offset?: number;
  decision?: string;
  tool?: string;
  search?: string;
  signal?: string;
  agentName?: string;
} = {}): AuditList {
  const limit = Math.max(1, Math.min(query.limit ?? 50, 1000));
  const offset = Math.max(0, query.offset ?? 0);
  let rows = logLines().map(toAuditEntry);

  if (query.decision) rows = rows.filter((r) => r.decision === query.decision);
  if (query.tool) {
    const needle = query.tool.toLowerCase();
    rows = rows.filter((r) => r.tool_name.toLowerCase().includes(needle));
  }
  if (query.agentName) {
    const needle = query.agentName.toLowerCase();
    rows = rows.filter((r) => (r.agent_name ?? '').toLowerCase().includes(needle));
  }
  if (query.signal === 'dlp') rows = rows.filter((r) => r.dlp_matches.length > 0 || /DLP/i.test(r.reason ?? ''));
  if (query.signal === 'ratelimit') rows = rows.filter((r) => r.rate_limit_burst || /rate limit/i.test(r.reason ?? ''));
  if (query.search) {
    const needle = query.search.toLowerCase();
    rows = rows.filter((r) =>
      r.tool_name.toLowerCase().includes(needle)
      || (r.reason ?? '').toLowerCase().includes(needle)
      || JSON.stringify(r.arguments_summary ?? {}).toLowerCase().includes(needle));
  }

  const layers = toLayers(read().security);
  return {
    entries: rows.slice(offset, offset + limit),
    total: rows.length,
    limit,
    offset,
    rate_limit_per_minute: layers.rateLimit.perMinute,
  };
}

// ── The rate-limit history ───────────────────────────────────────────────────
//
// Kept because the change is worth seeing beside a burst: "the limit was 30 when
// that happened". A service recorded it; nothing else does, so writing it is part
// of changing the limit.

export function rateLimitHistory(): RateLimitChange[] {
  try {
    const raw = JSON.parse(readFileSync(historyPath(), 'utf-8'));
    if (!Array.isArray(raw)) return [];
    return raw.filter((r) => r && typeof r.ts === 'number').slice(0, 200);
  } catch {
    return [];
  }
}

export function recordRateLimitChange(l: SecurityLayers): void {
  const entry: RateLimitChange = {
    ts: Date.now(),
    minute: l.rateLimit.perMinute,
    hour: l.rateLimit.perHour,
    day: l.rateLimit.perDay,
  };
  const prev = rateLimitHistory();
  // An unchanged limit is not a change. Saving one on every settings write would
  // fill the list with rows that say nothing.
  const last = prev[0];
  if (last && last.minute === entry.minute && last.hour === entry.hour && last.day === entry.day) return;
  try {
    mkdirSync(sgDir(), { recursive: true, mode: DIR_MODE });
    writeFileSync(historyPath(), JSON.stringify([entry, ...prev].slice(0, 200), null, 2), { mode: FILE_MODE });
  } catch { /* the limit still changed; only the note about it is at risk */ }
}

export function clearRateLimitHistory(): void {
  try {
    writeFileSync(historyPath(), '[]', { mode: FILE_MODE });
  } catch { /* nothing to clear */ }
}

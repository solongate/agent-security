#!/usr/bin/env node
/**
 * SolonGate Audit Hook for Claude Code (PostToolUse)
 * Logs tool execution results to SolonGate Cloud.
 * Auto-installed by: npx @solongate/proxy login
 */
import { readFileSync, existsSync, writeFileSync, mkdirSync, appendFileSync } from 'node:fs';
import { resolve, join, isAbsolute } from 'node:path';
import { homedir } from 'node:os';

// ── Per-project scratch, kept OUT of the project ─────────────────────────────
// The guard and the audit hook pass a few small flags to each other (the eval
// ring, the last-eval measurement, the deny flag, the tool-call marker). These
// used to be written to `./.solongate/` — relative to whatever directory the
// agent happened to run in — which scattered a dot-folder through every folder
// an agent ever touched, config directories included, and put it inside repos
// that had no ignore rule for it. It also read as "local logging is on" to
// anyone who found one, which is a different setting entirely.
//
// They now live under the user's own ~/.solongate, in a directory named by a
// hash of the project path, so the per-project separation the dataroom relies
// on survives while nothing is written where the user works. The hash is
// duplicated in guard.mjs, audit.mjs and the dataroom: all three must agree for
// a call's flags to be found, so keep them identical if any one is touched.
function projectKey(dir) {
  let h = 0x811c9dc5;
  const s = String(dir || '');
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16);
}

function projectFlagDir() {
  return join(resolve(homedir(), '.solongate'), 'projects', projectKey(resolve(process.cwd())));
}


// Bump on every audit hook change. The cloud serves the newest version; the guard
// hook installs it on its next run (no re-login needed). See guard.mjs
// fetchAndInstallHook / maybeSelfUpdate.
// 29 collapses a run of `*` in a custom DLP glob before compiling it. That is a
// HANG fix, so an installed hook must pick it up: see dlpGlobToRe.
const HOOK_VERSION = 29;

function loadEnvKey(dir) {
  try {
    const envPath = resolve(dir, '.env');
    if (!existsSync(envPath)) return {};
    const lines = readFileSync(envPath, 'utf-8').split('\n');
    const env = {};
    for (const line of lines) {
      const m = line.match(/^([A-Z_]+)=(.*)$/);
      if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, '').trim();
    }
    return env;
  } catch { return {}; }
}

// Global cloud config written by `init --global` (~/.solongate/cloud-guard.json).
// A system-wide PostToolUse hook runs from any cwd, so a project .env can't be
// relied on for the key — read the absolute global config too.
function loadGlobalCloudConfig() {
  try {
    const p = resolve(homedir(), '.solongate', 'cloud-guard.json');
    if (!existsSync(p)) return {};
    const cfg = JSON.parse(readFileSync(p, 'utf-8'));
    return (cfg && typeof cfg === 'object') ? cfg : {};
  } catch { return {}; }
}

// The guard (PreToolUse) measures the policy-eval time and drops it in a flag
// file; this hook logs the ALLOW path but can't time the guard itself, so it
// reads that value back. The flag carries the tool (and session) it was measured
// for, so a long-running tool (a 10-minute Bash build) still gets ITS eval time
// instead of a stale-TTL zero. Returns null when no matching measurement exists —
// an unknown eval time must be stored as null, not a fake 0 that drags averages.
function readLastEvalMs(toolName, sessionId) {
  // Prefer the ring: average the recent same-session eval records. When several
  // tool calls run in PARALLEL they all land here within a moment, so each one
  // reports the burst's arithmetic-mean eval time instead of a blank (the single
  // .last-eval flag would be overwritten / half-read under that concurrency). A
  // lone sequential call has only itself in the window → it reports its own time.
  try {
    const ring = join(projectFlagDir(), '.eval-ring.jsonl');
    if (existsSync(ring)) {
      const now = Date.now();
      const recent = [];
      for (const line of readFileSync(ring, 'utf-8').split('\n')) {
        if (!line) continue;
        let r; try { r = JSON.parse(line); } catch { continue; }
        if (!r || typeof r.ms !== 'number' || typeof r.ts !== 'number') continue;
        if (now - r.ts > 2500) continue; // recent burst only
        if (r.session && sessionId && r.session !== sessionId) continue;
        recent.push(r.ms);
      }
      if (recent.length) return Math.max(0, Math.round(recent.reduce((a, b) => a + b, 0) / recent.length));
    }
  } catch {}
  // Fallback: the single-value flag (original behavior).
  try {
    const p = join(projectFlagDir(), '.last-eval');
    if (!existsSync(p)) return null;
    const c = JSON.parse(readFileSync(p, 'utf-8'));
    if (!c || typeof c.ms !== 'number' || typeof c.ts !== 'number') return null;
    if (typeof c.tool === 'string') {
      if (c.tool !== toolName) return null;
      if (c.session && sessionId && c.session !== sessionId) return null;
      if (Date.now() - c.ts > 2 * 3600 * 1000) return null;
      return Math.max(0, Math.round(c.ms));
    }
    if (Date.now() - c.ts < 30000) return Math.max(0, Math.round(c.ms));
    return null;
  } catch { return null; }
}

// ── DLP output redaction (PostToolUse) ──
// Masks secret VALUES inside the tool OUTPUT the model sees (file reads, stdout,
// fetched pages). Active whenever DLP is on (detect OR block) — the server
// delivers the enabled pattern set as `security.dlpRedact` in the policy cache.
// Patterns mirror guard.mjs / apps/api/src/lib/security-layers.ts (global flag
// so every occurrence is replaced). Scanning RAW output text (not JSON) means
// the quote handling is exact — no escaping artifacts.
const DLP_PATTERNS = [
  { name: 'AWS access key', re: /AKIA[0-9A-Z]{16}/g },
  { name: 'Private key block', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { name: 'Anthropic key', re: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'OpenAI key', re: /sk-(proj-)?[A-Za-z0-9_-]{20,}/g },
  { name: 'GitHub token', re: /gh[pousr]_[A-Za-z0-9]{20,}/g },
  { name: 'GitHub fine-grained PAT', re: /github_pat_[A-Za-z0-9_]{20,}/g },
  { name: 'GitLab token', re: /glpat-[A-Za-z0-9_-]{20,}/g },
  { name: 'Slack token', re: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'Stripe key', re: /[sr]k_(live|test)_[A-Za-z0-9]{20,}/g },
  { name: 'SendGrid key', re: /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g },
  { name: 'Twilio key', re: /SK[0-9a-fA-F]{32}/g },
  { name: 'npm token', re: /npm_[A-Za-z0-9]{36}/g },
  { name: 'JWT', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { name: 'Bearer token', re: /bearer\s+[A-Za-z0-9._-]{20,}/gi },
];

// Read the redaction config the guard cached on the matching PreToolUse call.
function loadDlpRedact() {
  try {
    const sel = (process.env.SOLONGATE_AGENT_ID || process.argv[2] || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
    const f = resolve(homedir(), '.solongate', '.policy-cache-' + sel + '.json');
    if (!existsSync(f)) return null;
    const c = JSON.parse(readFileSync(f, 'utf-8'));
    const d = c && c.security && c.security.dlpRedact;
    return d && Array.isArray(d.patterns) ? d : null;
  } catch { return null; }
}

// ── DETECT-mode observation ──
// In DETECT mode the guard doesn't block (and doesn't log) — the call is ALLOWED
// and reaches THIS PostToolUse hook. To make "detect" mean observe-AND-record
// (not silent), we scan the ARGUMENTS for DLP hits and flag rate-limit bursts
// here, on the ALLOW entry. Block-mode hits are DENIED upstream and carry their
// own reason, so this only fires for detect-mode ALLOWs. Everything is wrapped
// fail-safe: any error just omits the field.

// Which DLP patterns match the stringified tool arguments (uses the enabled set
// the guard cached; block+detect both populate dlpRedact). Names only.
function dlpScanArgs(argsSummary, dlpCfg) {
  try {
    if (!dlpCfg || !Array.isArray(dlpCfg.patterns) || !dlpCfg.patterns.length) return [];
    const text = typeof argsSummary === 'string' ? argsSummary : JSON.stringify(argsSummary || {});
    if (!text) return [];
    const enabled = new Set(dlpCfg.patterns);
    const hits = [];
    for (const p of DLP_PATTERNS) {
      if (!enabled.has(p.name)) continue;
      try { p.re.lastIndex = 0; if (p.re.test(text)) hits.push(p.name); } catch { /* skip */ }
      if (hits.length >= 5) break;
    }
    for (const c of (dlpCfg.custom || [])) {
      try { if (c && c.re && dlpGlobToRe(c.re, 'gi').test(text)) hits.push(c.name || 'custom'); } catch { /* skip */ }
      if (hits.length >= 5) break;
    }
    return hits;
  } catch { return []; }
}

// Detect-mode rate-limit config (delivered only when mode === 'detect').
function loadRateLimitObserve() {
  try {
    const sel = (process.env.SOLONGATE_AGENT_ID || process.argv[2] || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
    const f = resolve(homedir(), '.solongate', '.policy-cache-' + sel + '.json');
    if (!existsSync(f)) return null;
    const c = JSON.parse(readFileSync(f, 'utf-8'));
    const r = c && c.security && c.security.rateLimitObserve;
    return r && typeof r === 'object' ? r : null;
  } catch { return null; }
}

// Sliding-window burst check for DETECT mode. Uses a SEPARATE stamps file from
// the guard's enforcement file so observation never interferes with blocking.
// Returns true when this call is at/over an enabled window's limit.
function rateLimitObserveBurst(agentKey, limits) {
  try {
    if (!limits) return false;
    const key = String(agentKey || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
    const file = resolve(homedir(), '.solongate', '.ratelimit-observe-' + key + '.json');
    const now = Date.now();
    let stamps = [];
    if (existsSync(file)) { try { stamps = JSON.parse(readFileSync(file, 'utf-8')); } catch { stamps = []; } }
    if (!Array.isArray(stamps)) stamps = [];
    stamps = stamps.filter((t) => typeof t === 'number' && now - t < 86400000);
    if (stamps.length > 50000) stamps = stamps.slice(-50000);
    const windows = [
      { key: 'perDay', ms: 86400000 },
      { key: 'perHour', ms: 3600000 },
      { key: 'perMinute', ms: 60000 },
    ];
    let burst = false;
    for (const w of windows) {
      const limit = limits[w.key];
      if (limit > 0) {
        const count = stamps.reduce((n, t) => (now - t < w.ms ? n + 1 : n), 0);
        if (count >= limit) { burst = true; break; }
      }
    }
    stamps.push(now);
    try { writeFileSync(file, JSON.stringify(stamps)); } catch { /* best-effort */ }
    return burst;
  } catch { return false; }
}

// Local log storage: the user can opt to keep a full copy of every audit entry
// in a file of their choosing (set from the dashboard survey / Settings, then
// delivered to us via the same policy cache the guard writes). We append one
// JSON object per line (JSONL) to that path. Fully local, best-effort, and
// never blocks the tool call or the cloud audit POST.
function loadLocalLogs() {
  try {
    const sel = (process.env.SOLONGATE_AGENT_ID || process.argv[2] || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
    const f = resolve(homedir(), '.solongate', '.policy-cache-' + sel + '.json');
    if (existsSync(f)) {
      const c = JSON.parse(readFileSync(f, 'utf-8'));
      const l = c && c.security && c.security.localLogs;
      if (l && l.enabled && typeof l.path === 'string' && l.path.trim()) return { path: l.path.trim() };
      // A cache that carries the key at all has an ANSWER, and the answer is
      // "not local" — including when it is null, which is what the refresh
      // writes for a project with no security config. Requiring it to be
      // truthy sent that case to the device-wide marker instead, so a stale
      // marker kept ALLOW rows on disk after local logging was switched off.
      if (c && 'security' in c) return null;
    }
  } catch { /* unreadable cache — fall through to the marker */ }
  // No usable config (cold cache, or a refresh that failed while the key was
  // being rotated): honour the persisted local-only marker instead of defaulting
  // to the cloud, which would ship an entry the project wants kept on-device.
  // The guard writes this marker on every policy refresh (writeLocalMarker).
  try {
    const m = JSON.parse(readFileSync(resolve(homedir(), '.solongate', '.local-logs-mode.json'), 'utf-8'));
    if (m && m.localOnly) return { path: resolve(homedir(), '.solongate', 'local-logs') };
  } catch { /* no marker → cloud */ }
  return null;
}

// Resolve the FOLDER local logs may be written into. It MUST be absolute on
// THIS machine. A relative path — e.g. a Windows "C:/Users/…" path evaluated on
// Linux, where Node treats it as relative — would be created under the agent's
// current working directory and pollute whatever project it happens to run in.
// When the configured path isn't absolute here, fall back to a fixed home folder
// so entries are never lost and never leak into a project, and record the bad
// path so the dashboard/user can be told their path isn't valid on this device.
function resolveLocalLogDir(rawPath) {
  const dir = String(rawPath || '').trim().replace(/[\\/]+$/, '');
  if (!dir) return null;
  if (isAbsolute(dir)) return dir;
  const fallback = resolve(homedir(), '.solongate', 'local-logs');
  try {
    // Owner-only: this directory holds the credential and the policy cache, and
    // every program that creates it has to agree on the mode — mkdirSync applies
    // one only when it CREATES, so the first one to run decides for all of them.
    // Same number as SG_DIR_MODE in the guard and sgshared.DirMode in Go.
    mkdirSync(resolve(homedir(), '.solongate'), { recursive: true, mode: 0o700 });
    writeFileSync(resolve(homedir(), '.solongate', '.local-logs-invalid-path'),
      JSON.stringify({ configured: dir, fallback, ts: Date.now() }));
  } catch { /* ignore */ }
  return fallback;
}

// The path is a FOLDER; we write solongate-audit.jsonl inside it (creating the
// folder if missing), then append one JSON line.
function appendLocalLog(cfg, entry) {
  try {
    const dir = resolveLocalLogDir(cfg.path);
    if (!dir) return;
    const line = JSON.stringify(entry) + '\n';
    try {
      mkdirSync(dir, { recursive: true });
      appendFileSync(join(dir, 'solongate-audit.jsonl'), line);
    } catch {
      // The folder is a PROJECT setting shared by every device, so a path that
      // is valid on one machine can be unwritable on another (a Linux "/home/me"
      // does not exist on macOS). Silently dropping the entry loses it for good,
      // since local-only mode also skips the cloud POST — fall back to the
      // per-device default folder and record the offending path.
      const fb = resolve(homedir(), '.solongate', 'local-logs');
      try { mkdirSync(fb, { recursive: true }); } catch { /* ignore */ }
      try { appendFileSync(join(fb, 'solongate-audit.jsonl'), line); } catch { /* ignore */ }
      try {
        writeFileSync(resolve(homedir(), '.solongate', '.local-logs-invalid-path'),
          JSON.stringify({ configured: dir, fallback: fb, ts: Date.now() }));
      } catch { /* ignore */ }
    }
  } catch { /* best-effort: never disturb the tool call */ }
}

// Replace every secret match with a labelled placeholder. cfg = { patterns:
// string[] (enabled built-in names), custom: {name,re}[] }.
// Custom patterns are GLOBs: `*` = any run of non-whitespace (so a fragment
// matches a whole token), same wildcard mechanic as the policy layer.
//
// A RUN of `*` collapses to one, and that is a fix rather than a tidy-up. `*`
// becomes `[^\s]*`, so `**` became two unbounded quantifiers over the same
// character class back to back — the textbook catastrophic-backtracking shape.
// Measured on this converter against sixty characters of tool output: six stars
// 0.9s, eight 28s, ten four minutes, twenty-four never finished. The pattern is
// one somebody types, and this scan runs over every tool result. Collapsing
// changes nothing about what a glob accepts, because `[^\s]*[^\s]*` matches
// exactly the strings `[^\s]*` matches. Kept identical in the guard and the
// shield, which carry the same converter.
function dlpGlobToRe(glob, flags) {
  let re = '';
  for (const ch of String(glob || '').replace(/\*{2,}/g, '*')) {
    if (ch === '*') re += '[^\\s]*';
    else if ('.+?^${}()|[]\\'.indexOf(ch) !== -1) re += '\\' + ch;
    else re += ch;
  }
  return new RegExp(re, flags);
}
function dlpRedactText(text, cfg) {
  if (!cfg || typeof text !== "string" || !text) return text;
  const allow = new Set(Array.isArray(cfg.patterns) ? cfg.patterns : []);
  const NUL = String.fromCharCode(0);
  const labels = [];
  const stash = (label) => NUL + (labels.push(label) - 1) + NUL;
  let out = text;
  for (const p of DLP_PATTERNS) {
    if (allow.has(p.name)) out = out.replace(p.re, () => stash("[REDACTED:" + p.name + "]"));
  }
  for (const c of Array.isArray(cfg.custom) ? cfg.custom : []) {
    try { out = out.replace(dlpGlobToRe(c.re, "gi"), () => stash("[REDACTED:" + (c.name || "custom") + "]")); } catch {}
  }
  return out.replace(new RegExp(NUL + "(\\d+)" + NUL, "g"), (_, i) => labels[+i] || "");
}

// Best-effort extraction of the model-visible text from a tool_response. Shapes
// are undocumented, so probe the known fields (Bash stdout, Read file.content,
// string/array content) and fall back to a raw string output.
function extractOutputText(toolResponse, toolOutput) {
  const r = toolResponse;
  if (typeof r === 'string') return r;
  if (r && typeof r === 'object') {
    if (typeof r.stdout === 'string' && r.stdout) return r.stdout;
    if (typeof r.content === 'string' && r.content) return r.content;
    if (r.file && typeof r.file.content === 'string') return r.file.content;
    if (Array.isArray(r.content)) {
      const t = r.content.filter((x) => x && x.type === 'text' && typeof x.text === 'string').map((x) => x.text).join('\n');
      if (t) return t;
    }
    // Native Glob delivers its hits as a `filenames` string[] with NO stdout/
    // content field, so getText() returned null and the DLP redaction silently
    // skipped it — a secret-looking path then survived in the Glob listing the
    // model saw. Join to one-path-per-line so dlpRedactText can act on it; the
    // PostToolUse updatedToolOutput then replaces the model-visible list.
    if (Array.isArray(r.filenames)) {
      const t = r.filenames.filter((x) => typeof x === 'string').join('\n');
      if (t) return t;
    }
  }
  if (typeof toolOutput === 'string' && toolOutput) return toolOutput;
  return null;
}

// Small stable string hash (FNV-1a, hex). Duplicated verbatim in guard.mjs —
// the two MUST produce the same value for the same tool_input (that is how a
// PostToolUse call is matched to the guard's deny flag), so keep them in sync.
function callFingerprint(s) {
  let h = 0x811c9dc5;
  const str = String(s || '');
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16);
}

function guessPermission(toolName) {
  const name = (toolName || '').toLowerCase();
  // Codex routes every file edit through `apply_patch` — no substring below
  // matches it, so it would otherwise be logged as a READ. Mirrors guard.mjs.
  if (name === 'apply_patch' || name === 'applypatch') return 'WRITE';
  if (name.includes('exec') || name.includes('shell') || name.includes('run') || name.includes('eval') || name === 'bash') return 'EXECUTE';
  if (name.includes('fetch') || name.includes('http') || name.includes('request') || name.includes('curl') || name.includes('network') || name.includes('download') || name.includes('upload') || name === 'websearch') return 'NETWORK';
  if (name.includes('write') || name.includes('create') || name.includes('delete') || name.includes('update') || name.includes('set') || name.includes('edit') || name.includes('remove') || name.includes('insert')) return 'WRITE';
  return 'READ';
}

const dotenv = loadEnvKey(process.cwd());
const globalCfg = loadGlobalCloudConfig();
// The LOGIN outranks a project-local env file (mirrors guard.mjs): a stale key
// left in the folder an agent starts in must never shadow the paired credential
// and silence this hook's audit POST. The env file still applies when there is
// no login at all.
const API_KEY = process.env.SOLONGATE_API_KEY || globalCfg.apiKey || dotenv.SOLONGATE_API_KEY || '';
const API_URL = process.env.SOLONGATE_API_URL || globalCfg.apiUrl || dotenv.SOLONGATE_API_URL || 'https://api.solongate.com';

// Agent identity from CLI args: node audit.mjs <agent_id> <agent_name>
const AGENT_ID = process.argv[2] || 'claude-code';
const AGENT_NAME = process.argv[3] || 'Claude Code';

// Accept both live and test keys (test keys are used for trials / sandboxes).
if (!API_KEY || !(API_KEY.startsWith('sg_live_') || API_KEY.startsWith('sg_test_'))) process.exit(0);

let input = '';
// Read stdin SYNCHRONOUSLY (fd 0). Calling process.exit() from inside the
// process.stdin stream 'end' callback aborts on Windows + Node 24 with
// `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c`
// (libuv double-closes the stdin pipe handle during teardown). Reading fd 0 to
// EOF avoids creating that handle, so the exits below tear down cleanly.
try { input += readFileSync(0, 'utf-8'); } catch {}
;(async () => {
  // Safety backstop ONLY: the normal path exits by natural drain. Force-exit if the
  // loop fails to drain — 8s > the 5s fetch timeout, so the threadpool is idle and
  // exit() can't hit the Windows UV_HANDLE_CLOSING abort.
  try { setTimeout(() => { try { process.exit(process.exitCode || 0); } catch {} }, 8000).unref(); } catch {}
  try {
    const data = JSON.parse(input);
    let EMITTED_PAYLOAD = null;

    // Debug: append raw stdin to file for agent detection troubleshooting.
    // Opt-in (SOLONGATE_DEBUG) so a global hook doesn't litter every cwd.
    if (process.env.SOLONGATE_DEBUG) {
      try {
        const debugLine = JSON.stringify({ ts: new Date().toISOString(), argv: process.argv.slice(2), tool_name: data.tool_name || data.toolName, agent_id: AGENT_ID }) + '\n';
        const { appendFileSync: afs, mkdirSync: mds } = await import('node:fs');
        mds(resolve('.solongate'), { recursive: true });
        afs(resolve('.solongate', '.debug-audit-log'), debugLine);
      } catch {}
    }

    let toolName = data.tool_name || data.toolName || '';
    let toolInput = data.tool_input || data.toolInput || data.params || {};
    if (!toolName) toolName = 'unknown';

    if (toolName === 'Bash' && JSON.stringify(toolInput).includes('audit-logs')) {
      process.exit(0);
    }

    // Did the guard already log a DENY for THIS EXACT call? If so this
    // PostToolUse is a duplicate and must not be logged as a second entry.
    //
    // The match is per-CALL, not per-tool. Matching the tool name alone
    // mislabels the NEXT call whenever it shares the name and lands inside the
    // 10s window — on Codex every shell call is "Bash", so an allowed
    // `echo merhaba` right after a blocked `cat …` was recorded as DENY
    // "blocked by policy guard" while it had actually run. The guard now writes
    // the call's tool_use_id and an argument fingerprint into the flag; we
    // require one of them to match and only fall back to the old name+time rule
    // for a flag written by an older guard (no id, no fp).
    let guardDenied = false;
    try {
      const denyFlagPath = join(projectFlagDir(), '.last-deny');
      if (existsSync(denyFlagPath)) {
        const flag = JSON.parse(readFileSync(denyFlagPath, 'utf-8'));
        const fresh = flag.ts && Date.now() - flag.ts < 10000 && flag.tool === toolName;
        if (fresh) {
          const id = String(data.tool_use_id || data.toolUseId || data.tool_call_id || '');
          let fp = '';
          try { fp = callFingerprint(JSON.stringify(data.tool_input || data.toolInput || data.params || {})); } catch { fp = ''; }
          if (flag.id && id) guardDenied = flag.id === id;
          else if (flag.fp && fp) guardDenied = flag.fp === fp;
          else guardDenied = !flag.id && !flag.fp; // legacy flag — old behavior
        }
      }
    } catch {}

    const toolResponse = data.tool_response || data.toolResponse || {};
    const toolOutput = data.tool_output || data.toolOutput || '';
    const resultJson = data.result_json ? (typeof data.result_json === 'string' ? data.result_json : JSON.stringify(data.result_json)) : '';

    // DLP: rewrite the output the model sees so secret values are masked. Emit
    // the updated output BEFORE the (fire-and-forget) audit log. Fail-open: any
    // error leaves the original output untouched.
    try {
      const dlpCfg = loadDlpRedact();
      const redactName = (s) => (dlpCfg && typeof s === 'string') ? dlpRedactText(s, dlpCfg) : s;

      // Glob (and Grep in files mode) deliver a STRUCTURED result:
      //   { filenames: string[], numFiles, truncated, totalMatches, ... }
      // Claude Code REJECTS a plain-string updatedToolOutput for such a tool —
      // it prints "PostToolUse:Glob hook warning" and keeps the ORIGINAL result,
      // so the unredacted listing is what the model sees. The fix is to return
      // the SAME shape: the filenames array with secret-looking names masked,
      // preserving every other field.
      if (toolResponse && typeof toolResponse === 'object' && Array.isArray(toolResponse.filenames)) {
        const orig = toolResponse.filenames.map((f) => String(f));
        const masked = orig.map(redactName);
        if (masked.some((f, i) => f !== orig[i])) {
          const updated = { ...toolResponse, filenames: masked, numFiles: masked.length };
          if (typeof toolResponse.totalMatches === 'number') updated.totalMatches = masked.length;
          EMITTED_PAYLOAD = JSON.stringify({
            hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: updated },
          });
        }
      } else {
        // String-output tools (Bash, Read, text Grep, MCP listers): redact
        // secrets in the TEXT, return a STRING.
        let out = null;
        if (dlpCfg) {
          const base = extractOutputText(toolResponse, toolOutput);
          if (typeof base === 'string') {
            const redacted = dlpRedactText(base, dlpCfg);
            if (redacted !== base) out = redacted;
          }
        }
        if (typeof out === 'string') {
          // Never emit EMPTY content. When DLP stripping removes every line
          // (e.g. a grep/cat that hit only hidden or secret lines) and the tool
          // ALSO errored, the resulting tool_result is is_error:true with empty
          // content — which the API rejects ("content cannot be empty if is_error
          // is true") and hard-crashes the whole agent conversation. Fall back to
          // a bare newline: still looks like empty output, but is non-empty.
          if (out === '') out = '\n';
          // Preserve the tool's result SHAPE. Bash and other tools deliver a
          // STRUCTURED result ({ stdout, stderr, ... } or { content }); Claude
          // Code rejects a bare-string replacement for those (hook warning) and
          // keeps the original. Clone the object and swap its text field; only a
          // genuinely string-typed result is replaced with a string.
          const tr = toolResponse;
          let updated;
          if (tr && typeof tr === 'object' && typeof tr.stdout === 'string') updated = { ...tr, stdout: out };
          else if (tr && typeof tr === 'object' && typeof tr.content === 'string') updated = { ...tr, content: out };
          else if (tr && typeof tr === 'object' && Array.isArray(tr.content)) updated = { ...tr, content: [{ type: 'text', text: out }] };
          // Read / NotebookRead nest the file body at file.content. It's a STRUCTURED
          // result, so a bare-string replacement is rejected ("PostToolUse:Read hook
          // warning") and the raw secret leaks through — preserve the shape instead.
          else if (tr && typeof tr === 'object' && tr.file && typeof tr.file.content === 'string') updated = { ...tr, file: { ...tr.file, content: out } };
          else updated = out;
          EMITTED_PAYLOAD = JSON.stringify({
            hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: updated },
          });
        }
      }
    } catch {}

    const hasError = guardDenied ||
      toolResponse.error ||
      toolResponse.exitCode > 0 ||
      toolResponse.isError ||
      (toolOutput && typeof toolOutput === 'string' && toolOutput.includes('"error"')) ||
      (resultJson && resultJson.includes('"error"'));

    // Keep the full command/args for audit review (the dashboard shows them in
    // the detail view). Only cap pathologically large values.
    const argsSummary = {};
    for (const [k, v] of Object.entries(toolInput)) {
      argsSummary[k] = typeof v === 'string' && v.length > 8000
        ? v.slice(0, 8000) + '…'
        : v;
    }

    // Codex CANNOT rewrite tool output from PostToolUse: its output struct is
    // deny_unknown_fields and the only rewrite field it defines
    // (updatedMCPToolOutput) is explicitly rejected as unsupported — so emitting
    // our `updatedToolOutput` there wouldn't redact anything, it would just make
    // Codex report a failed hook on every single tool call. Drop the payload and
    // keep the audit log. The DLP protection Codex DOES get runs earlier, in the
    // PreToolUse guard (secret reads redirected to a redacted copy) — see
    // guard.mjs dlpRedactReadPlan.
    if (AGENT_ID === 'codex' && typeof EMITTED_PAYLOAD === 'string') EMITTED_PAYLOAD = null;

    // Flush the model-visible replacement to stdout, THEN exit. On Windows a
    // bare process.exit() can truncate an un-drained pipe write, so Claude Code
    // receives malformed hook JSON, prints "PostToolUse hook warning", and
    // DISCARDS the replacement — leaving the unredacted output visible. Gate the exit
    // on the write's flush callback (and on the fire-and-forget audit POST).
    let flushed = (typeof EMITTED_PAYLOAD !== 'string');
    let fetchDone = false;
    // Set the exit code and let the event loop drain naturally — do NOT call
    // process.exit(). On Windows + Node 24, process.exit() in the same tick the
    // audit-log fetch settled aborts with `Assertion failed: !(handle->flags &
    // UV_HANDLE_CLOSING), file src\win\async.c` (a threadpool DNS worker is still
    // mid-uv_async_send when exit() force-closes the loop's async handle). undici
    // unrefs idle sockets, so Node exits on its own ~1ms after the fetch settles.
    const maybeExit = () => { if (flushed && fetchDone) { process.exitCode = 0; } };
    if (typeof EMITTED_PAYLOAD === 'string') {
      try { process.stdout.write(EMITTED_PAYLOAD, () => { flushed = true; maybeExit(); }); }
      catch { flushed = true; }
    }

    const sessionId = data.session_id || data.sessionId || data.conversation_id || '';
    const decision = hasError ? 'DENY' : 'ALLOW';
    const reason = guardDenied ? 'blocked by policy guard' : hasError ? 'tool returned error' : 'allowed';
    const permission = guessPermission(toolName);
    const evaluationTimeMs = readLastEvalMs(toolName, sessionId);

    // DETECT-mode observation: record DLP matches / rate-limit bursts on this
    // ALLOW entry so "detect" means observe-AND-log (not silent). Fail-safe —
    // any error leaves the fields off. Only meaningful on ALLOW (block-mode hits
    // are DENIED upstream with their own reason).
    let dlpMatches = [];
    let rateLimitBurst = false;
    if (decision === 'ALLOW') {
      try { dlpMatches = dlpScanArgs(argsSummary, loadDlpRedact()); } catch { dlpMatches = []; }
      try { rateLimitBurst = rateLimitObserveBurst(AGENT_ID, loadRateLimitObserve()); } catch { rateLimitBurst = false; }
    }

    // Local log storage (opt-in): when ON, logs are kept LOCAL ONLY — we append
    // this entry to the user's chosen file and do NOT send it to the cloud.
    const localLogs = loadLocalLogs();
    if (localLogs) {
      appendLocalLog(localLogs, {
        ts: new Date().toISOString(),
        tool: toolName, arguments: argsSummary, decision, reason, permission,
        evaluation_time_ms: evaluationTimeMs, agent_id: AGENT_ID, agent_name: AGENT_NAME, session_id: sessionId,
        ...(dlpMatches.length ? { dlp: dlpMatches } : {}),
        ...(rateLimitBurst ? { rate_limit_burst: true } : {}),
      });
      fetchDone = true;
      maybeExit();
    } else {
      // Fire-and-forget: don't block tool execution waiting for API response
      fetch(`${API_URL}/api/v1/audit-logs`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tool: toolName,
          arguments: argsSummary,
          decision,
          reason,
          permission,
          source: `${AGENT_ID}-hook`,
          evaluationTimeMs,
          agent_id: AGENT_ID,
          agent_name: AGENT_NAME,
          session_id: sessionId,
          ...(dlpMatches.length ? { dlp: dlpMatches } : {}),
          ...(rateLimitBurst ? { rate_limit_burst: true } : {}),
        }),
        signal: AbortSignal.timeout(5000),
      }).catch(() => {}).finally(() => { fetchDone = true; maybeExit(); });
    }
    // Safety backstop ONLY (unref'd, 8s > the 5s fetch timeout): the normal path
    // exits by natural drain ~1ms after the fetch settles. This fires only if the
    // loop somehow fails to drain — by 8s the threadpool is idle, so exit() is safe.
    try { setTimeout(() => { try { process.exit(process.exitCode || 0); } catch {} }, 8000).unref(); } catch {}
  } catch {
    process.exitCode = 0;
  }
})();

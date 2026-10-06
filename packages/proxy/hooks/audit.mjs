#!/usr/bin/env node
/**
 * SolonGate Audit Hook for Claude Code (PostToolUse)
 * Logs tool execution results to SolonGate Cloud.
 * Auto-installed by: npx @solongate/proxy login
 */
import { readFileSync, existsSync, writeFileSync, mkdirSync, appendFileSync, chmodSync } from 'node:fs';
import { resolve, join, isAbsolute } from 'node:path';
import { homedir } from 'node:os';

import { DLP_PATTERN_NAMES, dlpGlobToRe, dlpPatterns } from './dlp.mjs';
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


// Bump on every audit hook change. Nothing serves it — the version is how the
// installed copy on a machine can be compared with the one in a checkout.
// 29 collapses a run of `*` in a custom DLP glob before compiling it. That is a
// HANG fix, so an installed hook must pick it up: see dlpGlobToRe.
// 33: the DLP pattern list moved to ./dlp.mjs, shared with the guard and the shield.
// This hook now IMPORTS a sibling, so an install that does not copy that file leaves this
// one unable to start -- which is why internal/install/installed_hooks_test.go runs every
// installed hook from the directory it was installed into.
const HOOK_VERSION = 33;

// loadEnvKey and loadGlobalCloudConfig lived here, and between them they resolved an
// API key from a project .env and from ~/.solongate/cloud-guard.json. Both are gone: the
// key authenticated an audit POST, that POST is gone, and a hook that runs after every
// tool call should not stat and read two files to learn something it will not use.
//
// The guard hook dropped the identical pair (hooks/guard.mjs), and so did the Go twin.

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

// THE PATTERN LIST LIVES IN ./dlp.mjs, one copy for the three hooks that scan.
//
// Each of them carried its own, and they had drifted: the guard had 70 and each hook had
// 14 — so on a machine without the Go binary, which is the default, a policy asking for
// most of the list was enforcing nothing. Compiled here with the flags THIS hook needs:
// `g`, because this REPLACES every occurrence — without it only the first
// secret in a file is masked and the rest reach the model.
const DLP_PATTERNS = dlpPatterns('g');

// Read the redaction config the guard cached on the matching PreToolUse call.
// Owner-only, and the same numbers the guard and sgshared use: several programs
// create this ONE directory, and a mode applies only on CREATE, so whichever runs
// first on a machine decides it for all of them. The local audit log is the
// sharpest case — it records every command, path and URL a call carried.
const SG_DIR_MODE = 0o700;
const SG_FILE_MODE = 0o600;

// ── Where the security block comes from ──────────────────────────────────────
//
// THIS MACHINE'S OWN FILE, and nothing else. It used to be a cache a service filled,
// with the file as a second look — and without that second look this hook read an
// empty cache and concluded there was no DLP configuration at all, which is not a
// small miss: on a client that can rewrite a tool's result (Claude Code, Codex) the
// GUARD deliberately leaves read-DLP to this hook and allows the call, so no
// configuration here meant no masking anywhere, and nothing said so.
//
// The file is read in the two spellings the guard accepts: the envelope a
// service answers with, and a policy document carrying `security` inside it.
function localSecurity() {
  try {
    const p = resolve(homedir(), '.solongate', 'policy.json');
    if (!existsSync(p)) return null;
    const obj = JSON.parse(readFileSync(p, 'utf-8'));
    if (!obj || typeof obj !== 'object') return null;
    if (obj.security && typeof obj.security === 'object') return obj.security;
    if (obj.policy && obj.policy.security && typeof obj.policy.security === 'object') return obj.policy.security;
    return null;
  } catch { return null; }
}

// THE FILE IS THE ONLY ANSWER, and a stale cache may not override it.
//
// This used to read the per-agent policy cache first, and a cache carrying the
// `security` key AT ALL won — `null` included, because a service answering null meant
// "this project has no layers configured" and that outranked a local file. Nothing
// writes that cache now, which made what remained a hazard rather than dead weight:
// a cache left behind by an older install still outranked the file, so a machine that
// upgraded could have the DLP its policy configures SWITCHED OFF by a stale reply —
// silently, since the file would look correct to whoever wrote it.
//
// The guard stopped consulting it for the same reason. Two readers of one machine's
// configuration have to agree about where that configuration is.
function loadSecurity() {
  return localSecurity();
}

function loadDlpRedact() {
  try {
    const sec = loadSecurity();
    // dlpBlock is honoured as redaction too, and that is not a convenience.
    // A service sends BOTH when DLP is on — blocking is the extra step over
    // redacting, so `dlpRedact` is always there. A file written by hand usually
    // carries only `dlpBlock`, which is the spelling that reads as "refuse
    // secrets": taking `dlpRedact` alone gave that file argument blocking and NO
    // output masking, which on a client that redacts in this hook is the whole
    // protection for a file read.
    //
    // dlpObserve is NOT here, and its absence is the detect mode. See
    // loadDlpScan: detect scans the same patterns and records the same hit, and
    // changes nothing the model sees.
    const d = (sec && sec.dlpRedact) || (sec && sec.dlpBlock);
    return d && Array.isArray(d.patterns) ? d : null;
  } catch { return null; }
}

// The patterns to SCAN with, whichever mode is on.
//
// Every mode scans; they differ only in what happens next. Reading the config
// through one function keeps a mode from silently losing its scan because the
// key it writes was not in somebody's `||` chain — which is how detect came to
// record nothing while redacting everything.
function loadDlpScan() {
  try {
    const sec = loadSecurity();
    const d = (sec && sec.dlpRedact) || (sec && sec.dlpBlock) || (sec && sec.dlpObserve);
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
    const sec = loadSecurity();
    const r = sec && sec.rateLimitObserve;
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

// Local log storage: a full copy of every audit entry, in a folder of the user's
// choosing — `security.localLogs.path` in the policy file. One JSON object per line
// (JSONL). Best-effort, and it never blocks the tool call.
function loadLocalLogs() {
  // WHERE, never WHETHER. This used to answer null for "send it to the service
  // instead", and there is no service: a null here now would lose the entry.
  // A configured folder wins; otherwise the per-device default.
  try {
    const sec = loadSecurity();
    const l = sec && sec.localLogs;
    if (l && typeof l.path === 'string' && l.path.trim()) return { path: l.path.trim() };
  } catch { /* fall through to the default */ }
  return { path: resolve(homedir(), '.solongate', 'local-logs') };
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
    // Owner-only: this directory holds the policy and the audit trail, and every
    // program that creates it has to agree on the mode — mkdirSync applies
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
    const narrow = (f) => { try { chmodSync(f, SG_FILE_MODE); } catch { /* ignore */ } };
    try {
      mkdirSync(dir, { recursive: true, mode: SG_DIR_MODE });
      const file = join(dir, 'solongate-audit.jsonl');
      appendFileSync(file, line, { mode: SG_FILE_MODE });
      // The mode on append applies only when it CREATES, so a log an older
      // version wrote 0644 would keep it. The guard narrows it the same way.
      narrow(file);
    } catch {
      // The folder is a PROJECT setting shared by every device, so a path that
      // is valid on one machine can be unwritable on another (a Linux "/home/me"
      // does not exist on macOS). Silently dropping the entry loses it for good,
      // since local-only mode also skips the cloud POST — fall back to the
      // per-device default folder and record the offending path.
      const fb = resolve(homedir(), '.solongate', 'local-logs');
      try { mkdirSync(fb, { recursive: true, mode: SG_DIR_MODE }); } catch { /* ignore */ }
      try {
        const file = join(fb, 'solongate-audit.jsonl');
        appendFileSync(file, line, { mode: SG_FILE_MODE });
        narrow(file);
      } catch { /* ignore */ }
      try {
        writeFileSync(resolve(homedir(), '.solongate', '.local-logs-invalid-path'),
          JSON.stringify({ configured: dir, fallback: fb, ts: Date.now() }));
      } catch { /* ignore */ }
    }
  } catch { /* best-effort: never disturb the tool call */ }
}

// WHAT THE OUTPUT SCAN CAUGHT, so the row can carry it.
//
// The audit row's `dlp` field used to come from dlpScanArgs alone, which reads
// the ARGUMENTS. For `Read secrets.txt` the arguments are a file path and
// nothing else, so the scan correctly found nothing and the row said dlp:no —
// while the redactor below masked an AWS key out of the file's contents on its
// way to the model. The one place a secret was actually caught was the one
// place nothing was written down, and the layers panel reported "no dlp hits in
// last 7 days" over three reads it had just redacted.
//
// A security product's record is half the product. A hit nobody can see later
// did not happen, as far as anyone reviewing the log is concerned.
const OUTPUT_DLP_HITS = new Set();

// dlpGlobToRe is in ./dlp.mjs too: three copies of one converter, and the reason it
// collapses a run of stars is a HANG on a pattern somebody types.
function dlpRedactText(text, cfg, found) {
  if (!cfg || typeof text !== "string" || !text) return text;
  const allow = new Set(Array.isArray(cfg.patterns) ? cfg.patterns : []);
  const NUL = String.fromCharCode(0);
  const labels = [];
  const stash = (label) => NUL + (labels.push(label) - 1) + NUL;
  // `found` collects the pattern NAMES this call masked, so the audit row can
  // say which secret was caught. Optional: callers that only want the text pass
  // nothing and nothing changes for them.
  const hit = (name) => { if (found) found.add(name); };
  let out = text;
  for (const p of DLP_PATTERNS) {
    if (allow.has(p.name)) out = out.replace(p.re, () => { hit(p.name); return stash("[REDACTED:" + p.name + "]"); });
  }
  for (const c of Array.isArray(cfg.custom) ? cfg.custom : []) {
    try {
      const nm = c.name || "custom";
      out = out.replace(dlpGlobToRe(c.re, "gi"), () => { hit(nm); return stash("[REDACTED:" + nm + "]"); });
    } catch {}
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

// Agent identity from CLI args: node audit.mjs <agent_id> <agent_name>
const AGENT_ID = process.argv[2] || 'claude-code';
const AGENT_NAME = process.argv[3] || 'Claude Code';

// THERE IS NO CREDENTIAL GATE HERE, and its absence is the point.
//
// A key was resolved above this line, and the line after it used to end
// `|| process.exit(0)`: on a machine with no service this hook did nothing
// whatsoever. Two things were lost that way, and only one of them is bookkeeping:
//
//   Every ALLOW went unrecorded. The guard records denials and this records the
//   rest, so a local audit log held refusals and nothing else.
//
//   And DLP MASKING OF TOOL OUTPUT never ran. On a client that can rewrite a
//   result, the guard leaves read-DLP to this hook BY DESIGN and allows the call.
//   With the hook gone the secret reached the model — so a `dlpBlock` in a local
//   policy protected an argument while doing nothing at all for a file read.
//
// The key itself is gone now too, along with the malformed-key check that made an
// unusable one count as none.

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
      const redactName = (s) => (dlpCfg && typeof s === 'string') ? dlpRedactText(s, dlpCfg, OUTPUT_DLP_HITS) : s;

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
            const redacted = dlpRedactText(base, dlpCfg, OUTPUT_DLP_HITS);
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
    // DISCARDS the replacement — leaving the unredacted output visible. So the exit
    // is gated on the write's flush callback.
    //
    // It used to be gated on a second thing as well: `fetchDone`, the fire-and-forget
    // audit POST. That is gone, and with it the reason this could not simply call
    // process.exit() — on Windows + Node 24, exiting in the same tick a fetch settled
    // aborted with `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING)`, because a
    // threadpool DNS worker was still mid-uv_async_send. Nothing is in flight now, but
    // the drain is kept as it is: it is correct, it is what the Go twin does, and the
    // hook has nothing to gain from exiting a millisecond sooner.
    let flushed = (typeof EMITTED_PAYLOAD !== 'string');
    const maybeExit = () => { if (flushed) { process.exitCode = 0; } };
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
      try { dlpMatches = dlpScanArgs(argsSummary, loadDlpScan()); } catch { dlpMatches = []; }
      // Arguments and output are two places one call can carry a secret, and a
      // row that names only the first is why a redacted read looked clean.
      //
      // In DETECT mode nothing above masked anything, so there is nothing in
      // OUTPUT_DLP_HITS: the scan has to happen here instead. It reads the
      // output and throws the text away, which is exactly what detect means.
      try {
        if (!OUTPUT_DLP_HITS.size) {
          const scanCfg = loadDlpScan();
          const sec = loadSecurity();
          if (scanCfg && sec && sec.dlpObserve && !sec.dlpRedact && !sec.dlpBlock) {
            const base = extractOutputText(toolResponse, toolOutput);
            if (typeof base === 'string' && base) {
              for (const n of dlpScanArgs(base, scanCfg)) OUTPUT_DLP_HITS.add(n);
            }
          }
        }
        for (const name of OUTPUT_DLP_HITS) {
          if (!dlpMatches.includes(name)) dlpMatches.push(name);
        }
      } catch { /* the args hits still stand */ }
      try { rateLimitBurst = rateLimitObserveBurst(AGENT_ID, loadRateLimitObserve()); } catch { rateLimitBurst = false; }
    }

    // THE RECORD GOES TO THE FILE. There used to be a branch here that POSTed it
    // instead, to whatever API_URL was — and that branch carried the tool, its
    // arguments and the reason off the machine. It is gone with the service that
    // received them, and so is the question of whether to record: the only thing
    // left to choose is the folder.
    appendLocalLog(loadLocalLogs(), {
      ts: new Date().toISOString(),
      tool: toolName, arguments: argsSummary, decision, reason, permission,
      evaluation_time_ms: evaluationTimeMs, agent_id: AGENT_ID, agent_name: AGENT_NAME, session_id: sessionId,
      ...(dlpMatches.length ? { dlp: dlpMatches } : {}),
      ...(rateLimitBurst ? { rate_limit_burst: true } : {}),
    });
    maybeExit();
    // Safety backstop ONLY, unref'd: the normal path exits by natural drain. This
    // fires only if the loop somehow fails to drain.
    try { setTimeout(() => { try { process.exit(process.exitCode || 0); } catch {} }, 8000).unref(); } catch {}
  } catch {
    process.exitCode = 0;
  }
})();

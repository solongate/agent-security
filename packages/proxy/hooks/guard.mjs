#!/usr/bin/env node
/**
 * SolonGate Cloud Policy Guard Hook (PreToolUse) — GLOBAL system-wide enforcement.
 *
 * This is the cloud twin of the air-gapped guard hook. Identical decision engine
 * (OPA WASM, NIST SP 800-207 PDP, fail-closed), but the policy + compiled WASM
 * are fetched from SolonGate Cloud and authenticated with the project API key.
 * Installed globally (~/.claude/settings.json) it intercepts EVERY tool call from
 * EVERY Claude Code session on the machine — exactly like the air-gapped product,
 * just sourced from the cloud instead of a local docker API.
 *
 * Cloud differences vs. air-gap guard.mjs:
 *   - API_KEY (sg_live_…/sg_test_…) from env/.env, attached to every API call.
 *   - API_URL defaults to https://api.solongate.com.
 *   - Enforcement is gated on the API key (the key identifies the project +
 *     its active policy), NOT on SOLONGATE_AGENT_ID.
 *   - No AI Judge and NO gray route: cloud routing is binary, WHITE (allow) /
 *     BLACK (block). The OPA policy alone decides; nothing is escalated.
 *
 * Exit code 2 = BLOCK, exit code 0 = ALLOW.
 * Logs DENY decisions to SolonGate Cloud. ALLOWs are logged by audit.mjs.
 * Auto-installed by: npx @solongate/proxy init --global
 */
import { readFileSync, existsSync, statSync, readdirSync, writeFileSync, mkdirSync, chmodSync, renameSync, appendFileSync, rmSync, rmdirSync, openSync, readSync, closeSync, accessSync, constants } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { resolve, join, dirname, isAbsolute } from 'node:path';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';
import { gunzipSync } from 'node:zlib';

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

// Remove the dot-folder older versions left in this working directory. Only our
// own files go, and the directory only if that empties it — a folder someone
// else put there, or one with anything unexpected in it, is left alone.
let _legacySwept = false;
function sweepLegacyFlagDir() {
  if (_legacySwept) return;
  _legacySwept = true;
  try {
    const dir = resolve(process.cwd(), '.solongate');
    if (!existsSync(dir)) return;
    const ours = new Set(['.eval-ring.jsonl', '.last-eval', '.last-deny', '.last-tool-call', '.debug-guard-log']);
    const left = [];
    for (const f of readdirSync(dir)) {
      if (ours.has(f)) { try { rmSync(join(dir, f), { force: true }); } catch { left.push(f); } }
      else left.push(f);
    }
    if (left.length === 0) { try { rmdirSync(dir); } catch { /* not empty after all */ } }
  } catch { /* never let cleanup disturb a tool call */ }
}

import { createHash } from 'node:crypto';

// Bump on every guard.mjs change. The cloud serves the newest bundle + version;
// the installed hook self-updates when the cloud version is higher (see
// maybeSelfUpdate). This is what makes guard fixes propagate without a manual
// reinstall — the same trust model as the OPA WASM this hook already runs.
// 91 collapses a run of `*` in a glob before compiling it. That is a HANG fix,
// so an installed hook must pick it up: see dlpGlobToRe.
const HOOK_VERSION = 91;

// ── The Go guard, when there is one and it is the right one ──────────────────
//
// Everything below this block is the Node decision engine. It stays, it stays
// correct, and it stays the thing that runs whenever the fast path cannot be
// trusted. THE RULE: a missing, stale, unreadable or crashing binary must mean
// SLOW BUT GUARDED, never FAST BUT UNGUARDED. Every failure here falls through.
//
// Three things this gets right that a naive `exec the binary` would not:
//
// 1. STDIN IS READ HERE, ONCE, BEFORE THE BINARY RUNS. Handing the child fd 0
//    directly would be faster to write and impossible to recover from: a binary
//    that dies after consuming the payload leaves Node with nothing to fall back
//    WITH, so it would evaluate an empty call and allow it. The payload is a few
//    KB and the read is synchronous; the safety is worth more than the copy.
//
// 2. EXIT 2 IS AMBIGUOUS. It is this hook's block signal AND the code the Go
//    runtime uses for an unhandled panic. A block always writes a decision to
//    stdout first; a panic writes a stack trace to stderr and nothing to stdout.
//    So exit 2 is honoured only with output to show for it, and a panic falls
//    through to Node — which will reach its own verdict on the same payload.
//
// 3. THE VERSION MUST MATCH EXACTLY, not merely exist. This hook self-updates
//    from the cloud on its own schedule while the binary only moves when npm
//    moves it, so a machine can hold a hook from this week and a binary from
//    last month. HOOK_VERSION bumps on every change to this file, and the binary
//    prints the HOOK_VERSION it implements. Different numbers mean different
//    decisions, and a binary that is merely OLD is not a smaller problem than
//    one that is missing.
//
// SOLONGATE_NO_GO_GUARD=1 pins execution to Node. It exists so a failure can be
// bisected without uninstalling anything.

// The refresh invocation has no tool call on stdin — it is spawned detached and
// its stdin may be a pipe nobody ever closes, so reading it would hang the hook
// forever. It also has nothing for the binary to decide. Both paths skip it.
const SG_REFRESH_ARG = process.argv.includes('--sg-refresh-policy');

// The one read of fd 0 in this process. Everything downstream uses this string.
const SG_STDIN = SG_REFRESH_ARG ? '' : (() => {
  try { return readFileSync(0, 'utf-8'); } catch { return ''; }
})();

// When this process began, as epoch milliseconds — the instant every reported
// guard time is measured from.
//
// `performance.timeOrigin` is stamped before Node's bootstrap runs, so a
// duration taken from it includes the interpreter coming up and this file being
// parsed. That is not an accounting nicety: those two are the MAJORITY of what a
// tool call pays for enforcement. Starting the clock further down (which is what
// `Date.now()` at the top of the async body did) left them outside the window
// and made the audit log report ~1ms for a call that really cost tens of them —
// a number no process on a real machine can achieve, and one that quietly turned
// the latency column into fiction.
//
// What is still NOT in it: the client's own fork/exec of node, which happens
// before this process exists and which nothing running inside it can observe.
const SG_ORIGIN_MS = (() => {
  try { return Math.round(performance.timeOrigin); } catch { return Date.now(); }
})();

// Where a binary may legitimately live, in the order they are trusted.
//
// The env override is first so a build can be pointed at without reinstalling.
// The platform package is the normal path for a project-local install. The copy
// under ~/.solongate/bin is what a GLOBAL install has: the hook is written to
// ~/.solongate/hooks as a lone file and launched from arbitrary working
// directories, where resolving through node_modules finds nothing.
function sgGuardCandidates() {
  const out = [];
  if (process.env.SOLONGATE_GUARD_BIN) out.push(process.env.SOLONGATE_GUARD_BIN);
  const exe = process.platform === 'win32' ? 'solongate-guard.exe' : 'solongate-guard';
  const os_ = process.platform === 'win32' ? 'win32' : process.platform;
  const cpu = process.arch === 'x64' ? 'x64' : process.arch;
  try {
    // The manifest, not a main entry: these packages contain a binary and
    // nothing else, so there is no JavaScript in them to resolve.
    //
    // createRequire rather than import.meta.resolve: the latter is not a sync
    // function on every Node 18 this package supports, and a hook is not the
    // place to find that out. node:module is a builtin, so importing it cannot
    // fail the way a real dependency could.
    const req = createRequire(import.meta.url);
    out.push(join(dirname(req.resolve(`@solongate/guard-${os_}-${cpu}/package.json`)), exe));
  } catch {
    // Not installed for this platform, which is what optionalDependencies does
    // on a host with no published binary, and is not an error.
  }
  out.push(resolve(homedir(), '.solongate', 'bin', exe));
  return out;
}

// Hand the whole call to the binary. Returns only when Node must decide instead.
function sgTryGoGuard() {
  for (const bin of sgGuardCandidates()) {
    try {
      if (!existsSync(bin)) continue;
      if (process.platform !== 'win32') accessSync(bin, constants.X_OK);
    } catch { continue; }

    // Ask what it is. Bounded, because this runs before anything has decided the
    // binary can be trusted and it must not be able to hang what it speeds up.
    let version;
    try {
      const v = spawnSync(bin, ['--sg-version'], { encoding: 'utf-8', timeout: 2000 });
      if (v.error || v.status !== 0) continue;
      version = String(v.stdout || '').trim();
    } catch { continue; }
    if (version !== String(HOOK_VERSION)) continue;

    let r;
    try {
      r = spawnSync(bin, process.argv.slice(2), {
        input: SG_STDIN,
        encoding: 'utf-8',
        // The binary writes the eval record the audit hook reads back, so it is
        // the one reporting this call's guard time — and from inside a process
        // that was spawned partway through the work, it can only see its own
        // share of it. Node's boot, this file's parse, the fd 0 read and the
        // version probe above are all already spent by the time it starts.
        // Handing it the origin is what lets the number it reports be the whole
        // hook instead of the last two milliseconds of it.
        env: { ...process.env, SOLONGATE_HOOK_ORIGIN_MS: String(SG_ORIGIN_MS) },
        // Well past every network call the guard makes. A binary still running
        // at this point is not going to produce an answer worth waiting for.
        timeout: 10000,
      });
    } catch { return; }

    // Killed, timed out, or never started: Node decides.
    if (!r || r.error || r.signal) return;
    const status = r.status;
    const stdout = r.stdout || '';
    if (status !== 0 && status !== 2) return;
    // See (2) above: a block without a decision to show is a crash wearing a
    // block's exit code.
    if (status === 2 && stdout.trim() === '') return;

    try {
      if (stdout) process.stdout.write(stdout);
      if (r.stderr) process.stderr.write(r.stderr);
    } catch {
      // Writing the answer is the whole job. If it could not be delivered, Node
      // has not written anything either, so it can still do the work.
      return;
    }
    process.exit(status);
  }
}

if (!SG_REFRESH_ARG && process.env.SOLONGATE_NO_GO_GUARD !== '1') {
  // A throw anywhere in here is a bug in the fast path, and a bug in the fast
  // path must not become an unguarded tool call.
  try { sgTryGoGuard(); } catch {}
}

// True when local log storage is ON. In that mode logs are kept LOCAL ONLY and
// nothing is sent to the cloud audit log — local and cloud are one or the
// other, never both.
//
// `undefined` is the ONLY value that means "we do not know yet". `null` is an
// answer: it is what the refresh writes when the API returns no security block,
// i.e. this project has no local-log config, i.e. cloud. Treating null as
// unknown is what kept logs on the machine after local logging was switched
// off — the answer fell through to the device-wide marker, and that marker is
// shared by every agent on the box while the policy cache is per agent, so
// whichever one refreshed last decided where everybody's logs went.
function localLogsOnly(security) {
  if (security !== undefined) {
    const l = security && security.localLogs;
    return !!(l && l.enabled && typeof l.path === 'string' && l.path.trim());
  }
  // Genuinely unknown (cold start, unreadable cache): consult the persisted
  // marker so a DENY is NEVER leaked to the cloud when this device is in
  // local-only mode. Without this fallback the first call(s) before the policy
  // cache warms POST the denial to the cloud and fire webhooks/alerts even
  // though the user chose local-only.
  try {
    const m = JSON.parse(readFileSync(join(resolve(homedir(), '.solongate'), '.local-logs-mode.json'), 'utf-8'));
    return !!(m && m.localOnly);
  } catch { return false; }
}

// Persist whether this device is in local-only mode, INDEPENDENT of the policy
// cache, so localLogsOnly() answers correctly even on a cache-miss call. Written
// on every policy refresh; switching back to cloud sets localOnly:false so cloud
// POSTs resume.
function writeLocalMarker(security) {
  try {
    const l = security && security.localLogs;
    const localOnly = !!(l && l.enabled && typeof l.path === 'string' && l.path.trim());
    writeFileSync(join(resolve(homedir(), '.solongate'), '.local-logs-mode.json'), JSON.stringify({ localOnly, ts: Date.now() }));
  } catch {}
}

// Resolve the FOLDER local logs may be written into. It MUST be absolute on
// THIS machine. A relative path — e.g. a Windows "C:/Users/…" path evaluated on
// Linux, where Node treats it as relative — would be created under the agent's
// current working directory and pollute whatever project it happens to run in
// (that's how stray "…/C:/Users/HP/solongate-logs" folders appear inside repos).
// When the configured path isn't absolute here, fall back to a fixed home folder
// so entries are never lost and never leak into a project, and record the bad
// path so the dashboard/user can be told their path isn't valid on this device.
let _invalidPathNoted = false;
function resolveLocalLogDir(rawPath) {
  const dir = String(rawPath || '').trim().replace(/[\\/]+$/, '');
  if (!dir) return null;
  if (isAbsolute(dir)) return dir;
  const fallback = resolve(homedir(), '.solongate', 'local-logs');
  // Non-absolute path (e.g. a Windows path on Linux): fall back. The diagnostic
  // marker is written at most ONCE per process, NOT on every denial — a per-call
  // writeFileSync here widened the window where a concurrent guard process dies
  // before its audit append lands (dropped denials under a simultaneous burst).
  if (!_invalidPathNoted) {
    _invalidPathNoted = true;
    try {
      mkdirSync(resolve(homedir(), '.solongate'), { recursive: true });
      writeFileSync(resolve(homedir(), '.solongate', '.local-logs-invalid-path'),
        JSON.stringify({ configured: dir, fallback, ts: Date.now() }));
    } catch { /* ignore */ }
  }
  return fallback;
}

// Local log storage (opt-in): write solongate-audit.jsonl inside the user's
// chosen FOLDER. The audit hook does the ALLOW path; the guard does DENY (a
// blocked call never reaches PostToolUse). `security` is the resolved config.
/**
 * Short, non-reversible mark of the account an entry belongs to.
 *
 * The machine-local log is one file, and nothing in a line said which account
 * produced it, so after pairing a different account the viewers presented the
 * previous one's calls as yours. Stamping each line lets a reader keep only its
 * own without deleting anybody's history. It is a hash prefix, never the key.
 */
function accountMark() {
  try {
    return API_KEY ? createHash('sha256').update(API_KEY).digest('hex').slice(0, 16) : '';
  } catch {
    return '';
  }
}

/**
 * Record a denial in the cloud WITHOUT making the agent wait for it.
 *
 * The verdict is the product; the audit line is bookkeeping. Awaiting the POST
 * put a full network round trip between "blocked" and the agent hearing it —
 * measured at 1643ms per denial, against 78ms with the API unreachable. Handing
 * it to a detached child keeps the record and gives the time back.
 */
function postAuditDetached(entry) {
  try {
    const payload = Buffer.from(JSON.stringify({
      url: API_URL + '/api/v1/audit-logs',
      headers: AUTH_HEADERS,
      body: entry,
    }), 'utf-8').toString('base64');
    spawn(process.execPath, [process.argv[1], '--sg-audit-post', payload], { detached: true, stdio: 'ignore' }).unref();
  } catch { /* the denial still stands; only the record is at risk */ }
}

function writeLocalLog(security, entry) {
  try {
    const mark = accountMark();
    if (mark) entry = { ...entry, acct: mark };
    const l = security && security.localLogs;
    // No usable folder in the resolved config. The answer can still be "local is
    // on" from the persisted marker alone, i.e. WITHOUT a resolved config (empty
    // or cold policy cache, or a refresh that failed while the key was being
    // rotated) — in which case keep the copy in the per-device default folder
    // rather than dropping it.
    if (!l || !l.enabled || typeof l.path !== 'string' || !l.path.trim()) {
      if (!localLogsOnly(security)) return; // local logging is off — cloud only
      const fallbackDir = resolve(homedir(), '.solongate', 'local-logs');
      const fallbackLine = JSON.stringify(entry) + '\n';
      const fallbackPayload = Buffer.from(JSON.stringify({ dir: fallbackDir, line: fallbackLine }), 'utf-8').toString('base64');
      spawn(process.execPath, [process.argv[1], '--sg-log-write', fallbackPayload], { detached: true, stdio: 'ignore' }).unref();
      return;
    }
    // Resolve the dir with ZERO filesystem work (no mkdir, no marker write) so the
    // detached spawn below is the FIRST syscall. Traced root cause: the earliest
    // guard processes in a burst do extra startup work (policy refresh + WASM),
    // exceed Claude Code's hook timeout, and get SIGKILLed partway THROUGH
    // writeLocalLog — before any append. So we hand the write to a DETACHED child
    // (own process group, survives the kill) IMMEDIATELY, as the very first action,
    // and do it EVERY time (no inline append → no partial-write / duplicate risk).
    let dir = String(l.path).trim().replace(/[\\/]+$/, '');
    if (!dir) return;
    if (!isAbsolute(dir)) dir = resolve(homedir(), '.solongate', 'local-logs');
    const line = JSON.stringify(entry) + '\n';
    const payload = Buffer.from(JSON.stringify({ dir, line }), 'utf-8').toString('base64');
    spawn(process.execPath, [process.argv[1], '--sg-log-write', payload], { detached: true, stdio: 'ignore' }).unref();
  } catch { /* best-effort */ }
}

// Safe file read with size limit (1MB max) to prevent DoS via large files
const MAX_FILE_READ = 1024 * 1024; // 1MB
function safeReadFileSync(filePath, encoding = 'utf-8') {
  try {
    const stat = statSync(filePath);
    if (stat.size > MAX_FILE_READ) return '';
    return readFileSync(filePath, encoding);
  } catch { return ''; }
}

// ── Load .env file (Claude Code doesn't load .env into process.env) ──
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

// ── Global cloud config (~/.solongate/cloud-guard.json) ──
// A GLOBAL hook runs from an arbitrary cwd every session, so a project-local
// .env can't be relied on to carry the API key. The global installer writes the
// key + URL here once; this absolute path is read regardless of cwd. Shape:
//   { "apiKey": "sg_live_…", "apiUrl": "https://api.solongate.com" }
function loadGlobalCloudConfig() {
  try {
    const p = resolve(homedir(), '.solongate', 'cloud-guard.json');
    if (!existsSync(p)) return {};
    const cfg = JSON.parse(readFileSync(p, 'utf-8'));
    return (cfg && typeof cfg === 'object') ? cfg : {};
  } catch { return {}; }
}

// A real cloud key is `sg_live_`/`sg_test_` followed by hex (see generateApiKey:
// 24 random bytes → 48 hex chars). Template/placeholder values shipped in sample
// .env files (e.g. `sg_live_your_key_here`) pass a naive truthiness check but are
// bogus — and because resolution prefers a project .env over the global login
// credential, a stray placeholder .env would shadow a valid login and 401 every
// API call, making the guard fail closed on EVERYTHING. Filter to real keys so a
// placeholder is skipped and the next real candidate (usually the login cred in
// cloud-guard.json) is used instead.
function isRealKey(k) {
  if (typeof k !== 'string') return false;
  const v = k.trim();
  if (!/^sg_(live|test)_/.test(v)) return false;
  const body = v.replace(/^sg_(live|test)_/, '');
  if (/your_key_here|placeholder|example|^x+$/i.test(body)) return false;
  return /^[a-f0-9]{16,}$/i.test(body);
}

function guessPermission(toolName) {
  const name = (toolName || '').toLowerCase();
  // Codex writes every file edit through one tool named `apply_patch` — no
  // substring below matches it, so without this it would be classified READ and
  // a WRITE-scoped rule would never fire on a Codex edit.
  if (name === 'apply_patch' || name === 'applypatch') return 'WRITE';
  if (name.includes('exec') || name.includes('shell') || name.includes('run') || name.includes('eval') || name === 'bash') return 'EXECUTE';
  if (name.includes('fetch') || name.includes('http') || name.includes('request') || name.includes('curl') || name.includes('network') || name.includes('download') || name.includes('upload') || name === 'websearch') return 'NETWORK';
  // `replace`, `patch` and `modify` are here because Antigravity's edit tool is
  // `replace_file_content`, which matched none of the words above and fell
  // through to READ. A WRITE-scoped rule therefore missed the tool the agent
  // actually edits with: "deny writes under config/" left it free to rewrite
  // config/ all day. The list is words a tool NAME uses for changing something,
  // not an enumeration of known tools, and it errs wide because the name that
  // classifies wrong is silently unguarded rather than loudly broken.
  if (name.includes('write') || name.includes('create') || name.includes('delete') || name.includes('update') || name.includes('set') || name.includes('edit') || name.includes('remove') || name.includes('insert') ||
      name.includes('replace') || name.includes('patch') || name.includes('modify') || name.includes('append') || name.includes('overwrite') || name.includes('rename') || name.includes('move') || name.includes('mkdir') || name.includes('touch')) return 'WRITE';
  return 'READ';
}

const hookCwdEarly = process.cwd();
const dotenv = loadEnvKey(hookCwdEarly);
const globalCfg = loadGlobalCloudConfig();
// Resolution order: process env → the LOGIN (global ~/.solongate config) →
// project-local .env.
//
// The login deliberately outranks .env. It used to be the other way round, and a
// forgotten key in the folder an agent happened to start in (an old install left
// one in $HOME) then shadowed the paired credential: every cloud call 401'd, so
// nothing was logged from that directory while the very same agent logged fine
// one folder over — with no visible symptom, because enforcement needs no
// network. A .env is not a file the user is meant to maintain, and logging in
// must be enough to make logging work everywhere. .env still wins when there is
// no login at all, which is the case it exists for (air-gapped / CI checkouts).
const API_URL = process.env.SOLONGATE_API_URL || globalCfg.apiUrl || dotenv.SOLONGATE_API_URL || 'https://api.solongate.com';
// Cloud API key (sg_live_… / sg_test_…). The key identifies the project AND
// authenticates every API call (active policy, compiled WASM, audit logs). When
// absent, this hook does nothing — a machine with no key is intentionally
// unenforced (the cloud has no policy to apply). Each candidate is filtered
// through isRealKey() so a placeholder .env (sg_live_your_key_here) can't shadow
// the real login credential and force a fail-closed on every call.
const API_KEY = [process.env.SOLONGATE_API_KEY, globalCfg.apiKey, dotenv.SOLONGATE_API_KEY].find(isRealKey) || '';
// WHERE the key came from. A project .env silently outranks the login, so a stale
// key in the folder an agent happens to run from makes every cloud call 401:
// enforcement still works (it is local) but NOTHING is logged, anywhere, with no
// visible sign — the same session works fine one directory over. Recording the
// source lets the 401 handler name the culprit instead of failing mutely.
const API_KEY_SOURCE = process.env.SOLONGATE_API_KEY && isRealKey(process.env.SOLONGATE_API_KEY)
  ? 'environment variable SOLONGATE_API_KEY'
  : isRealKey(globalCfg.apiKey)
    ? 'login (~/.solongate)'
    : join(hookCwdEarly, '.' + 'env');
const API_URL_SOURCE = process.env.SOLONGATE_API_URL
  ? 'environment variable SOLONGATE_API_URL'
  : globalCfg.apiUrl
    ? 'login (~/.solongate)'
    : join(hookCwdEarly, '.' + 'env');

// Record/clear the "the cloud rejected this credential" marker. `solongate
// doctor` surfaces it, so a 401 stops being invisible.
function noteAuthResult(ok) {
  try {
    const p = join(resolve(homedir(), '.solongate'), '.key-rejected.json');
    if (ok) { if (existsSync(p)) rmSync(p, { force: true }); return; }
    writeFileSync(p, JSON.stringify({
      ts: Date.now(), cwd: hookCwdEarly,
      keySource: API_KEY_SOURCE, apiUrl: API_URL, apiUrlSource: API_URL_SOURCE,
    }));
  } catch { /* best-effort */ }
}
// Auth headers attached to every cloud API request. Cloud accepts either the
// Authorization: Bearer form or X-API-Key; we send both for robustness.
const AUTH_HEADERS = API_KEY ? { 'Authorization': 'Bearer ' + API_KEY, 'X-API-Key': API_KEY } : {};

// ── Self-update (best-effort, throttled, integrity-checked) ──
// Once per ~6h the hook asks the cloud for the latest guard bundle. If the cloud
// version is higher AND the sha256 verifies AND the payload looks like this guard
// hook, it atomically replaces its own file. Any failure is swallowed so a bad
// update can never break enforcement — the current code simply keeps running.
// Fetch one hook bundle from the cloud and atomically replace the installed file
// if the served version is newer AND the sha256 verifies AND it looks like the
// right hook. Any failure is swallowed.
async function fetchAndInstallHook(endpoint, fileName, currentVersion, marker, minLen) {
  try {
    const res = await fetch(API_URL + '/api/v1/hooks/' + endpoint, { headers: AUTH_HEADERS, signal: AbortSignal.timeout(5000) });
    if (!res.ok) return;
    const data = await res.json();
    if (!data || typeof data.version !== 'number' || data.version <= currentVersion) return;
    if (typeof data.content !== 'string' || typeof data.sha256 !== 'string') return;
    const buf = Buffer.from(data.content, 'base64');
    if (createHash('sha256').update(buf).digest('hex') !== data.sha256) return;
    const text = buf.toString('utf-8');
    if (!text.startsWith('#!/usr/bin/env node') || text.length < minLen || !text.includes(marker)) return;
    const hooksDir = join(resolve(homedir(), '.solongate'), 'hooks');
    const tmp = join(hooksDir, '.' + fileName + '.tmp');
    writeFileSync(tmp, text);
    try { chmodSync(join(hooksDir, fileName), 0o644); } catch { /* may be locked read-only */ }
    renameSync(tmp, join(hooksDir, fileName)); // atomic swap, takes effect next call
  } catch { /* never break enforcement on update failure */ }
}

// Read the HOOK_VERSION baked into an installed sibling hook (0 if absent/old).
function installedHookVersion(fileName) {
  try {
    const f = join(resolve(homedir(), '.solongate'), 'hooks', fileName);
    const m = (safeReadFileSync(f) || '').match(/HOOK_VERSION\s*=\s*(\d+)/);
    return m ? parseInt(m[1], 10) : 0;
  } catch { return 0; }
}

/**
 * Which clients the guard is REGISTERED for on this machine.
 *
 * The dashboard used to infer this from "whose guard has called in", which
 * answers a different question than `repair` and `doctor` do — a client that is
 * installed but has not been opened in days reads as unguarded, and the three
 * surfaces contradicted each other while using identical wording. The machine
 * is the only thing that can see its own files, so it reports them.
 *
 * Cheap on purpose: four existence/substring checks against files this hook
 * already treats as tamper targets, run on a poll that is throttled to 10s.
 */
function registeredClients() {
  const home = resolve(homedir());
  const has = (p, needle) => {
    try {
      const s = safeReadFileSync(p);
      if (!s) return false;
      return needle ? s.includes(needle) : true;
    } catch { return false; }
  };
  const out = [];
  if (has(join(home, '.claude', 'settings.json'), '.solongate')) out.push('claude-code');
  if (has(join(home, '.gemini', 'config', 'hooks.json'), '.solongate')) out.push('antigravity');
  if (has(join(process.env.CODEX_HOME ? resolve(process.env.CODEX_HOME) : join(home, '.codex'), 'hooks.json'), '.solongate')) out.push('codex');
  const xdg = process.env.XDG_CONFIG_HOME ? resolve(process.env.XDG_CONFIG_HOME) : join(home, '.config');
  if (has(join(xdg, 'opencode', 'plugins', 'solongate.js'), 'tool.execute.before')) out.push('opencode');
  return out;
}

// Latest hook versions the cloud reports on /policies/active (hook_versions).
// Captured during the policy fetch of THIS run (or its short-lived cache); lets
// maybeSelfUpdate() know it is behind and bypass the 6h stamp entirely.
let CLOUD_HOOK_VERSIONS = null;

function hooksBehindCloud() {
  const v = CLOUD_HOOK_VERSIONS;
  if (!v || typeof v !== 'object') return false;
  if (Number(v.guard) > HOOK_VERSION) return true;
  if (Number(v.audit) > installedHookVersion('audit.mjs')) return true;
  if (Number(v.shield) > installedHookVersion('shield.mjs')) return true;
  return false;
}

// Once per ~6h: update the guard itself AND its sibling hooks (audit, shield).
// The guard is the only hook that self-updates from the cloud, so it carries the
// others — that's why a new audit/shield reaches every device with NO re-login:
// the guard fetches and installs them on its next run.
//
// The 6h stamp only rate-limits the BLIND check. When the policy response says
// the cloud serves a NEWER hook (hook_versions), we update immediately — so a
// fresh release lands on the next executed command, and a stamp refreshed by an
// earlier run (e.g. before the release finished deploying) can't delay it.
async function maybeSelfUpdate() {
  if (!API_KEY) return;
  try {
    const sgDir = resolve(homedir(), '.solongate');
    const stamp = join(sgDir, '.hook-update-check');
    if (!hooksBehindCloud()) {
      const last = parseInt(safeReadFileSync(stamp) || '0', 10);
      if (Number.isFinite(last) && Date.now() - last < 6 * 3600 * 1000) return;
    }
    try { writeFileSync(stamp, String(Date.now())); } catch { /* ignore */ }
    // Guard compares to its OWN running version; siblings to their installed file.
    await fetchAndInstallHook('guard', 'guard.mjs', HOOK_VERSION, 'SolonGate Cloud Policy Guard', 50000);
    await fetchAndInstallHook('audit', 'audit.mjs', installedHookVersion('audit.mjs'), 'SolonGate Audit Hook', 1500);
    await fetchAndInstallHook('shield', 'shield.mjs', installedHookVersion('shield.mjs'), 'SolonGate Shield', 1500);
  } catch { /* never break enforcement on update failure */ }
}

// Two distinct identities, deliberately kept separate:
//
//   AGENT_TYPE — the real AI client running this hook (claude-code / codex /
//   antigravity / openclaw). Baked into the hook registration by the installer
//   as argv[2] (e.g. `node guard.mjs claude-code`). Decides the response
//   format AND whether a selected policy actually applies to this client.
//   claude-code and codex share ONE response contract (see blockTool); only
//   antigravity differs.
//
//   POLICY_SELECTOR — set per-terminal via SOLONGATE_AGENT_ID (a policy id
//   from the dashboard "Use in terminal" button, or an agent name). Decides
//   WHICH policy to load. When unset, no policy is enforced — a plain launch
//   is intentionally unrestricted.
const AGENT_TYPE = process.argv[2] || 'claude-code';
const POLICY_SELECTOR = process.env.SOLONGATE_AGENT_ID || '';
const AGENT_ID = POLICY_SELECTOR || AGENT_TYPE;
const AGENT_NAME = process.env.SOLONGATE_AGENT_NAME || process.argv[3] || AGENT_TYPE;

// ── Background policy refresh (stale-while-revalidate) ──
// The hot path NEVER blocks on the network: when the policy cache is stale it
// serves the cached (or local) policy INSTANTLY and spawns this detached mode to
// fetch a fresh policy and rewrite the cache for the NEXT call. Result: fast tool
// calls AND ~one-call propagation of policy changes — no long-TTL tradeoff.
// Survivable local-log writer. A denial's audit line is written by a DETACHED
// child (this same file, invoked with --sg-log-write <base64>) so the entry
// lands even if Claude Code kills the parent hook mid-write during a concurrent
// denial burst. Handled FIRST and exits immediately — the child never loads the
// heavy guard logic below.
// Survivable CLOUD writer, same idea. A denial used to `await` its audit POST
// before telling the agent it was blocked, so the agent sat waiting on a network
// round trip to be told "no": measured at 1643ms per denial against 78ms with
// the API unreachable. The record still has to land, so it is handed to a
// detached child rather than dropped — the verdict goes out at once and the POST
// finishes on its own.
{
  const _ai = process.argv.indexOf('--sg-audit-post');
  if (_ai !== -1) {
    try {
      const _raw = Buffer.from(process.argv[_ai + 1] || '', 'base64').toString('utf-8');
      const _p = JSON.parse(_raw);
      if (_p && _p.url && _p.body) {
        fetch(_p.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(_p.headers || {}) },
          body: JSON.stringify(_p.body),
          signal: AbortSignal.timeout(10000),
        }).catch(() => {}).finally(() => process.exit(0));
        setTimeout(() => process.exit(0), 11000).unref();
      } else process.exit(0);
    } catch { process.exit(0); }
  }
}

{
  const _wi = process.argv.indexOf('--sg-log-write');
  if (_wi !== -1) {
    try {
      const _pl = JSON.parse(Buffer.from(process.argv[_wi + 1] || '', 'base64').toString('utf-8'));
      if (_pl && _pl.dir && _pl.line) {
        // The folder is a PROJECT setting, so it reaches every device — and a
        // path that exists on one ("/home/me/") is unwritable on another (macOS
        // has no /home). When that happens the append used to fail silently, and
        // because local-only mode also skips the cloud POST, the entry was lost
        // entirely: "no logs on the Mac". Fall back to the per-device default
        // folder, which always exists, and leave a marker naming the bad path.
        let _dir = _pl.dir;
        try {
          mkdirSync(_dir, { recursive: true });
          appendFileSync(join(_dir, 'solongate-audit.jsonl'), _pl.line);
        } catch {
          const _fb = join(resolve(homedir(), '.solongate'), 'local-logs');
          try { mkdirSync(_fb, { recursive: true }); } catch {}
          try { appendFileSync(join(_fb, 'solongate-audit.jsonl'), _pl.line); } catch {}
          try {
            writeFileSync(join(resolve(homedir(), '.solongate'), '.local-logs-invalid-path'),
              JSON.stringify({ configured: _dir, fallback: _fb, ts: Date.now() }));
          } catch {}
        }
      }
    } catch {}
    process.exit(0);
  }
}
const REFRESH_MODE = process.argv.includes('--sg-refresh-policy');
async function refreshPolicyCache() {
  try {
    const agentKey = (AGENT_ID || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
    const cacheFile = join(resolve(homedir(), '.solongate'), '.policy-cache-' + agentKey + '.json');
    // Preserve existing fields so a failed fetch never erases the last-known-good.
    let selfProtect = true, security = null, hookVersions = null, policy = null;
    try {
      if (existsSync(cacheFile)) {
        const c = JSON.parse(readFileSync(cacheFile, 'utf-8'));
        if (c) { policy = c.policy ?? null; if (typeof c.selfProtect === 'boolean') selfProtect = c.selfProtect; if (c.security !== undefined) security = c.security; if (c.hookVersions) hookVersions = c.hookVersions; }
      }
    } catch {}
    try {
      const res = await fetch(
        API_URL + '/api/v1/policies/active?agent_id=' + encodeURIComponent(AGENT_ID || '')
          + '&hv=' + HOOK_VERSION
          + '&clients=' + encodeURIComponent(registeredClients().join(',')),
        { headers: AUTH_HEADERS, signal: AbortSignal.timeout(8000) },
      );
      if (res.ok) {
        const body = await res.json();
        if (typeof body?.self_protection_enabled === 'boolean') selfProtect = body.self_protection_enabled;
        // A successful answer REPLACES the security block rather than merging
        // into it. Only overwriting when the field was present meant a config
        // the API had stopped sending lived on in the cache forever — switch
        // local logging off in the dashboard and this device kept writing to
        // disk and kept skipping the cloud, with nothing to show why.
        security = body?.security !== undefined ? body.security : null;
        if (body?.hook_versions && typeof body.hook_versions === 'object') hookVersions = body.hook_versions;
        policy = (body && body.policy) ? body.policy : null;
        noteAuthResult(true);
      } else if (res.status === 401 || res.status === 403) {
        // The credential this hook resolved is not accepted. Enforcement keeps
        // working (it needs no network) but every audit write silently fails, so
        // leave a breadcrumb naming the key's SOURCE — usually a stale .env in
        // whatever folder the agent was started from.
        noteAuthResult(false);
      }
    } catch {}
    // Always advance _ts (success or failure) so the hot path backs off between refreshes.
    try { writeFileSync(cacheFile, JSON.stringify({ _ts: Date.now(), policy, selfProtect, security, hookVersions })); } catch {}
    writeLocalMarker(security);
  } catch {}
}
if (REFRESH_MODE) { try { setTimeout(() => { try { process.exit(process.exitCode || 0); } catch {} }, 8000).unref(); } catch {} refreshPolicyCache().finally(() => { process.exitCode = 0; }); }

// ── Per-tool block/allow output ──
// Response format depends on the agent:
// Claude Code:      exit 2 + stderr = BLOCK, exit 0 = ALLOW
// Codex CLI:        IDENTICAL to Claude Code — verified against the Codex source
//   (codex-rs/hooks): exit 2 with a non-empty stderr blocks the tool with that
//   text as the reason; exit 0 with EMPTY stdout allows; exit 0 with
//   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":
//   "deny","permissionDecisionReason":"…"}} also blocks. Two things are NOT
//   interchangeable with Claude and are load-bearing here: the output struct is
//   deny_unknown_fields (any extra key makes Codex discard the whole decision),
//   and permissionDecision "allow" is only legal TOGETHER WITH updatedInput —
//   a bare allow is rejected as unsupported. Hence allowTool() stays silent.
// Antigravity CLI:  its PreToolUse hook result is a protobuf message decoded from
//   stdout JSON — BLOCK = {"allow_tool": false, "deny_reason": "..."}, ALLOW =
//   {"allow_tool": true} (exit 0). NOTE: {"decision":"deny"} is Antigravity's
//   *Stop* hook schema, NOT the tool gate — agy silently runs the tool if we
//   send that, so the field names here are load-bearing (verified in the agy
//   1.1.5 binary: AllowTool bool / DenyReason string).

// Terminate the hook WITHOUT forcing process.exit(). On Windows + Node 24, calling
// process.exit() right after a fetch() (the cloud audit-log POST) aborts with
// `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c`:
// the fetch's DNS/socket teardown is still settling in libuv's threadpool and
// exit() double-closes the loop's async handle. The abort replaces exit code 2, so
// Claude Code sees a non-blocking hook failure and runs the tool anyway — the guard
// computes DENY but never blocks. Instead set process.exitCode and let the event
// loop drain and exit on its own. A latch preserves the FIRST code (so a later
// allowTool() reached on fall-through can't overwrite a block), SG_DONE unwinds the
// stack, and an unref'd backstop force-exits only if a handle is stuck — by then
// the threadpool has drained, so exit() is safe.
const SG_DONE = Symbol('sg-done');
let _sgDone = false;
// The decision JSON must be written to stdout AT MOST ONCE. The handler can reach
// a terminal allowTool() even after a block already emitted its deny (the SG_DONE
// unwind is swallowed on some paths), which for Claude Code was harmless
// (allowTool writes nothing there) but for Antigravity appended a second
// {"allow_tool":true} right after {"allow_tool":false} — agy then parsed the
// trailing allow (or failed on the double object) and ran the blocked tool. This
// latch guarantees the FIRST decision is the only one on stdout.
let _decisionEmitted = false;
// Terminate WITHOUT ever calling process.exit() on the hot path. On Windows + Node
// 24, process.exit() called in (or right after) the same tick a cloud fetch()
// settled aborts with `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING),
// file src\win\async.c`: a libuv threadpool worker (DNS) is still mid-uv_async_send
// when exit() force-closes the loop's async handle. The abort replaces exit code 2,
// so Claude Code sees a non-blocking hook failure and runs the tool anyway (guard
// logs DENY, never blocks). Instead we just set process.exitCode and let the event
// loop drain — undici unrefs idle sockets, so Node exits on its own within ~1ms of
// the work finishing, cleanly (no forced teardown → no abort). A latch preserves
// the FIRST code so a later allowTool() on fall-through can't overwrite a block; an
// unref'd backstop armed at the top of the handler is the only place exit() may run,
// and only long after every fetch has settled.
function sgFinish(code) {
  if (!_sgDone) { _sgDone = true; process.exitCode = code; }
  throw SG_DONE;
}

// ── Client adapters ────────────────────────────────────────────────────────
// The ONLY client-aware code in this hook. Everything between the two ends
// reasons over two VENDOR-NEUTRAL shapes that belong to SolonGate, not to any
// one client:
//
//   CALL     { client, tool, args, command, cwd, sessionId, response, raw }
//   DECISION { type: 'deny' | 'allow' | 'rewrite', reason, patch }
//
// Each adapter translates one client BOTH ways: `parse` maps that client's raw
// payload onto CALL, `emit` maps DECISION onto that client's wire format and
// returns the process exit code. No layer outside this block may branch on the
// client. Adding a client = adding one entry here.

// Two clients happen to share Anthropic's PreToolUse wire format (Claude Code
// and Codex CLI). That is a fact about those two clients, not a canonical
// format — the neutral CALL/DECISION shapes above are the canonical ones. These
// helpers exist so the shared dialect is written once.
// Argument keys are part of a client's dialect too, so translating only the
// ENVELOPE leaves vendor names sitting inside `args` and the middle still sees
// client-specific data. These aliases rename the known ones to the neutral key
// every layer already understands. Unrecognized keys pass through untouched:
// they may still hold a path or a secret, and the scanners must keep seeing them.
const ARG_ALIASES = {
  commandline: 'command',
  cmd: 'command',
  absolutepath: 'file_path',
  targetfile: 'file_path',
  filepath: 'file_path',
  target_file: 'file_path',
  notebook_path: 'file_path',
};
function neutralizeArgs(a, drop = []) {
  const out = {};
  for (const [k, v] of Object.entries(a && typeof a === 'object' ? a : {})) {
    const lk = k.toLowerCase();
    if (drop.includes(lk)) continue;
    const nk = ARG_ALIASES[lk] || k;
    if (out[nk] === undefined) out[nk] = v;
  }
  return out;
}

function parseFlatPayload(raw) {
  const args = neutralizeArgs(raw.tool_input || raw.toolInput || raw.params || {});
  return {
    tool: raw.tool_name || raw.toolName || '',
    args,
    command: typeof args?.command === 'string' ? args.command : null,
    cwd: raw.cwd || '',
    sessionId: raw.session_id || raw.sessionId || raw.conversation_id || '',
    response: raw.tool_response || raw.toolResponse || {},
  };
}
// Exit 2 is what actually enforces a block: JSON + exit 0 goes through the
// normal permission flow, which AUTO-ACCEPT overrides (observed: a DLP-blocked
// Write still landed on disk in auto mode). Exit 2 hard-blocks before the
// permission system, in every mode. The JSON stays as the Windows/PowerShell
// fallback, where a native exit code may not propagate reliably. Codex reads
// the stderr text at exit 2 and ignores stdout, so both halves serve it too.
function emitHookSpecific(d) {
  if (d.type === 'deny') {
    const msg = d.reason || '[SolonGate] Blocked by policy';
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: msg,
      },
    }));
    process.stderr.write(msg + '\n');
    return 2;
  }
  if (d.type === 'rewrite') {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow', updatedInput: d.patch },
    }));
    return 0;
  }
  return 0; // allow: silence is consent in this dialect
}

// `redactsOutput` is a CAPABILITY, not an identity: true means this client has a
// post-tool stage that can rewrite what the tool returned, so a secret inside a
// file the agent reads gets masked there. False means masking has to happen
// before the tool runs (redact into a temp copy, point the read at it) and any
// masking we cannot apply becomes a block. Layers ask about the capability, never
// about which client is running.
const CLIENTS = {
  'claude-code': {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    redactsOutput: true, // audit.mjs rewrites the tool result at PostToolUse
  },

  // Codex CLI: same decision dialect as Claude Code, different INPUT problem.
  // Every file edit arrives as one apply_patch call whose target paths live
  // inside the patch text, so parse lifts them onto the neutral `paths` field
  // (see liftFreeformPatchPaths, applied to every client for safety).
  codex: {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    redactsOutput: false, // has a post-tool stage, but it rejects output rewrites
  },

  // OpenCode: no subprocess hook contract at all — a plugin runs in-process and
  // refuses a call by throwing. The shim that does the throwing (see
  // hooks/opencode-plugin.mjs) spawns this guard with a flat Claude-shaped
  // payload and reads the Claude dialect back, so both halves are reused as-is
  // and only the identity differs.
  opencode: {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    // tool.execute.after does hand the plugin the tool's result, but whether
    // writing to it changes what the model sees is untested. Claiming the
    // capability we have not proven would let a secret through masked-in-name-
    // only; false makes any masking we cannot apply a block instead.
    redactsOutput: false,
  },

  // Antigravity CLI: nested payload, and a decision dialect of its own.
  antigravity: {
    redactsOutput: false, // no post-tool stage at all (its output is ignored)
    parse(raw) {
      const tc = (raw.toolCall && typeof raw.toolCall === 'object') ? raw.toolCall : {};
      const a = (tc.args && typeof tc.args === 'object') ? tc.args : {};
      // Cwd is dropped from args on purpose: it is the environment the call runs
      // in, not something the call acts on, and it is lifted to call.cwd below.
      // Leaving it in made the working directory look like an access target.
      const args = neutralizeArgs(a, ['cwd']);
      let cwd = raw.cwd || '';
      if (!cwd) {
        if (typeof a.Cwd === 'string' && a.Cwd) cwd = a.Cwd;
        else if (Array.isArray(raw.workspacePaths) && typeof raw.workspacePaths[0] === 'string') cwd = raw.workspacePaths[0];
      }
      return {
        tool: raw.tool_name || tc.name || '',
        args,
        command: typeof args.command === 'string' ? args.command : null,
        cwd,
        sessionId: raw.session_id || raw.conversationId || '',
        response: raw.tool_response || raw.toolResponse || {},
      };
    },
    emit(d) {
      if (d.type === 'deny') {
        // hooks.md contract is { decision, reason }; the older Go binary reads
        // { allow_tool, deny_reason }. Writing both makes the block land on
        // whichever build is running. Exit 0: agy reads the JSON, not the code.
        const msg = `[SolonGate] ${d.reason}`;
        process.stdout.write(JSON.stringify({ decision: 'deny', reason: msg, allow_tool: false, deny_reason: msg }));
        return 0;
      }
      if (d.type === 'rewrite') {
        // `overwrite` is shallow-merged into the tool args before it runs, so
        // the rewritten call is the one that executes. Shell text rides in
        // CommandLine, which is where this client keeps a command.
        const overwrite = {};
        if (d.patch && typeof d.patch.command === 'string') overwrite.CommandLine = d.patch.command;
        else Object.assign(overwrite, d.patch || {});
        process.stdout.write(JSON.stringify({ decision: 'allow', overwrite, allow_tool: true }));
        return 0;
      }
      process.stdout.write(JSON.stringify({ decision: 'allow', allow_tool: true }));
      return 0;
    },
  },

  // Unknown client: never silently adopt another client's rules. Parse by
  // payload SHAPE and deny with the most widely enforced signal available
  // (JSON + exit 2). A client that needs anything else gets its own entry.
  generic: {
    redactsOutput: false, // assume the weaker capability, so masking fails closed
    parse(raw) {
      return (raw.toolCall && typeof raw.toolCall === 'object')
        ? CLIENTS.antigravity.parse(raw)
        : parseFlatPayload(raw);
    },
    emit: emitHookSpecific,
  },
};

const CLIENT = CLIENTS[AGENT_TYPE] || CLIENTS.generic;

// Emit ONE decision through the active adapter, then finish. The latch keeps the
// FIRST decision: a later fall-through allow must never overwrite a block (that
// bug once made agy run a tool the guard had already denied).
function emitDecision(d) {
  if (!_decisionEmitted) {
    _decisionEmitted = true;
    const code = CLIENT.emit(d);
    sgFinish(code);
  }
  sgFinish(0);
}

function blockTool(reason) {
  emitDecision({ type: 'deny', reason });
}

function allowTool() {
  emitDecision({ type: 'allow' });
}

// Allow the tool but REPLACE its input, so hidden entries are filtered out of a
// listing before the agent ever sees them. The rewritten call is what runs, so
// no block is needed. Each adapter knows how its client carries the patch.
function rewriteTool(patch) {
  emitDecision({ type: 'rewrite', patch });
}

// Identity of the tool call being evaluated, captured from the RAW payload
// before any normalization, so the deny flag below names the exact call. Both
// halves are best-effort: a client that sends neither falls back to the legacy
// tool+time match in audit.mjs.
let CALL_ID = '';
let CALL_FP = '';
// Small stable string hash (FNV-1a, hex). Duplicated verbatim in audit.mjs —
// the two MUST produce the same value for the same tool_input, so keep them in
// sync if either is ever touched.
function callFingerprint(s) {
  let h = 0x811c9dc5;
  const str = String(s || '');
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16);
}

// Records WHICH call was denied, so the PostToolUse audit hook does not log a
// second, ALLOW-looking entry for a call the guard already blocked.
function writeDenyFlag(toolName) {
  try {
    const flagDir = projectFlagDir();
    mkdirSync(flagDir, { recursive: true });
    // Deny-specific flag: audit.mjs (PostToolUse) reads it to avoid logging a
    // second, ALLOW-looking entry for a call the guard already denied.
    //
    // It carries the CALL's identity, not just the tool name. Matching on the
    // name alone mislabels a DIFFERENT call that merely follows a denial within
    // the flag's 10s window — and on Codex every shell call is named "Bash", so
    // an allowed `echo hi` right after a blocked `cat secret` was logged as
    // DENY ("blocked by policy guard") even though it ran normally.
    writeFileSync(join(flagDir, '.last-deny'), JSON.stringify({
      tool: toolName, ts: Date.now(), id: CALL_ID, fp: CALL_FP,
    }));
  } catch {}
}

// ── Prompt Injection Detection (Stage 1: Rule-Based) ──
const PI_CATEGORIES = [
  {
    name: 'delimiter_injection', weight: 0.95,
    patterns: [
      /<\/system>/i, /<\|im_end\|>/i, /<\|im_start\|>/i, /<\|endoftext\|>/i,
      /\[INST\]/i, /\[\/INST\]/i, /<<SYS>>/i, /<<\/SYS>>/i,
      /###\s*(Human|Assistant|System)\s*:/i, /<\|user\|>/i, /<\|assistant\|>/i,
      /---\s*END\s*SYSTEM\s*PROMPT\s*---/i,
    ],
  },
  {
    name: 'instruction_override', weight: 0.9,
    patterns: [
      /\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directives?)\b/i,
      /\bdisregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?|guidelines?)\b/i,
      /\bforget\s+(all\s+|everything\s+)?(your|the|previous|prior|above|earlier)\b/i,
      /\boverride\s+(the\s+)?(system|previous|current)\s+(prompt|instructions?|rules?|settings?)\b/i,
      /\bdo\s+not\s+follow\s+(your|the|any)\s+(instructions?|rules?|guidelines?)\b/i,
      /\bcancel\s+(all\s+)?(prior|previous)\s+(directives?|instructions?)\b/i,
      /\bnew\s+instructions?\s+supersede\b/i,
      /\byour\s+(previous\s+)?instructions?\s+are\s+(now\s+)?void\b/i,
    ],
  },
  {
    name: 'role_hijacking', weight: 0.85,
    patterns: [
      /\b(pretend|act|behave)\s+(you\s+are|as\s+if\s+you|like\s+you|to\s+be)\b/i,
      /\byou\s+are\s+now\s+(a|an|the|my|DAN)\b/i,
      /\bsimulate\s+being\b/i, /\bassume\s+the\s+role\s+of\b/i,
      /\benter\s+(developer|admin|debug|god|sudo|unrestricted)\s+mode\b/i,
      /\bswitch\s+to\s+(unrestricted|unfiltered)\s+mode\b/i,
      /\byou\s+are\s+no\s+longer\s+bound\b/i,
      /\bno\s+(safety\s+)?restrictions?\s+(apply|anymore|now)\b/i,
    ],
  },
  {
    name: 'jailbreak_keywords', weight: 0.8,
    patterns: [
      /\bjailbreak\b/i, /\bDAN\s+mode\b/i,
      /\b(system\s+override|admin\s+mode|debug\s+mode|developer\s+mode|maintenance\s+mode)\b/i,
      /\bmaster\s+key\b/i, /\bbackdoor\s+access\b/i,
      /\bsudo\s+mode\b/i, /\bgod\s+mode\b/i,
      /\bsafety\s+filters?\s+(off|disabled?|removed?)\b/i,
    ],
  },
  {
    name: 'encoding_evasion', weight: 0.75,
    patterns: [
      /\b(decode|translate)\s+(this|the\s+following)\s+(base64|rot13|hex)\b/i,
      /\b(base64|rot13)\s*:\s*[A-Za-z0-9+/=]{10,}/i,
      /\bexecute\s+the\s+(reverse|decoded)\b/i,
      /\breverse\s+of\s*:\s*\w{10,}/i,
    ],
  },
  {
    name: 'separator_injection', weight: 0.7,
    patterns: [
      /[-=]{3,}\s*\n\s*(new\s+instructions?|system|instructions?)\s*:/i,
      /```\s*\n\s*<\/?system>/i,
      /\bEND\s+(SYSTEM\s+)?(PROMPT|INSTRUCTIONS?)\b.*\bNEW\s+(SYSTEM\s+)?(PROMPT|INSTRUCTIONS?)\b/is,
    ],
  },
  {
    name: 'multi_language', weight: 0.7,
    patterns: [
      /ignor(iere|a|e[zs]?)\s+(alle|todas?|toutes?|tüm|все)/iu,
      /игнорируйте/iu, /yoksay/iu,
      /vorherigen?\s+Anweisungen/iu, /instrucciones\s+anteriores/iu,
      /instructions?\s+pr[eé]c[eé]dentes?/iu, /önceki\s+talimatlar/iu,
    ],
  },
];

function detectPromptInjection(text, customCategories = [], threshold = 0.5) {
  const matched = [];
  let maxWeight = 0;
  const allCategories = [...PI_CATEGORIES, ...customCategories];
  for (const cat of allCategories) {
    for (const pat of cat.patterns) {
      if (pat.test(text)) {
        matched.push(cat.name);
        if (cat.weight > maxWeight) maxWeight = cat.weight;
        break;
      }
    }
  }
  if (matched.length === 0) return null;
  const score = Math.min(1.0, maxWeight + 0.05 * (matched.length - 1));
  const trustScore = 1.0 - score;
  const blocked = Math.round(trustScore * 1000) < Math.round(threshold * 1000);
  return { score, trustScore, categories: matched, blocked };
}

// ── Glob Matching ──
function matchGlob(str, pattern) {
  if (pattern === '*') return true;
  const s = str.toLowerCase();
  const p = pattern.toLowerCase();
  if (s === p) return true;
  const startsW = p.startsWith('*');
  const endsW = p.endsWith('*');
  if (startsW && endsW) { const infix = p.slice(1, -1); return infix.length > 0 && s.includes(infix); }
  if (startsW) return s.endsWith(p.slice(1));
  if (endsW) return s.startsWith(p.slice(0, -1));
  const idx = p.indexOf('*');
  if (idx !== -1) {
    const pre = p.slice(0, idx);
    const suf = p.slice(idx + 1);
    return s.startsWith(pre) && s.endsWith(suf) && s.length >= pre.length + suf.length;
  }
  return false;
}

// ── Path Glob (supports **) ──
function matchPathGlob(path, pattern) {
  const p = path.replace(/\\/g, '/').toLowerCase();
  const g = pattern.replace(/\\/g, '/').toLowerCase();
  if (p === g) return true;
  if (g.includes('**')) {
    const parts = g.split('**').filter(s => s.length > 0);
    if (parts.length === 0) return true;
    return parts.every(segment => p.includes(segment));
  }
  return matchGlob(p, g);
}

// ── Safe Webhook URL Validation (prevent SSRF) ──
function isSafeWebhookUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:') return false;
    const host = u.hostname.toLowerCase();
    // Block private/reserved IPs and metadata endpoints
    if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' || host === '::1') return false;
    if (host.startsWith('10.') || host.startsWith('192.168.') || host.startsWith('172.')) return false;
    if (host === '169.254.169.254' || host === 'metadata.google.internal') return false;
    if (host.endsWith('.internal') || host.endsWith('.local')) return false;
    return true;
  } catch { return false; }
}

// ── Safe Regex Validation (prevent ReDoS from cloud-supplied patterns) ──
function isSafeRegex(pattern) {
  if (typeof pattern !== 'string' || pattern.length > 512) return false;
  // Block nested quantifiers: (a+)+, (a*)+, (a{1,})+, etc.
  if (/(\+|\*|\{[^}]+\})\s*(\+|\*|\{[^}]+\})/.test(pattern)) return false;
  if (/\([^)]*(\+|\*|\{[^}]+\})[^)]*\)\s*(\+|\*|\{[^}]+\})/.test(pattern)) return false;
  // Block excessive alternation groups (>10 alternatives)
  if ((pattern.match(/\|/g) || []).length > 10) return false;
  try { new RegExp(pattern); return true; } catch { return false; }
}

// ── Extract Functions (deep scan all string values) ──
function scanStrings(obj) {
  const strings = [];
  function walk(v) {
    if (typeof v === 'string' && v.trim()) strings.push(v.trim());
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  }
  walk(obj);
  return strings;
}

function looksLikeFilename(s) {
  if (s.startsWith('.')) return true;
  if (/\.\w+$/.test(s)) return true;
  const known = ['id_rsa','id_dsa','id_ecdsa','id_ed25519','authorized_keys','known_hosts','makefile','dockerfile'];
  return known.includes(s.toLowerCase());
}

// Deterministic shell normalizer — handles the common bypass tricks BEFORE
// any semantic check, so OPA's literal matcher sees the canonical command.
// Specifically: variable assignment + interpolation, quote concatenation
// (.e""nv, ."env"). Doesn't try to be a full shell — just enough to defeat
// the obfuscation patterns AI judges keep getting wrong non-deterministically.
function normalizeShellCommand(cmd) {
  if (typeof cmd !== 'string' || !cmd) return cmd;
  const vars = {};
  const out = [];
  // Split on statement separators (; && ||) but NOT pipes (|).
  for (const rawPart of cmd.split(/\s*(?:;|&&|\|\|)\s*/)) {
    let part = rawPart;
    // Detect var assignment: NAME=value | NAME="value" | NAME='value'
    const m = part.match(/^(\w+)=(?:"([^"]*)"|'([^']*)'|([^\s;&|]*))\s*$/);
    if (m) {
      vars[m[1]] = m[2] ?? m[3] ?? m[4] ?? '';
      continue;
    }
    // Substitute ${var} then $var.
    part = part.replace(/\$\{(\w+)\}/g, (_, n) => vars[n] !== undefined ? vars[n] : '${' + n + '}');
    part = part.replace(/\$(\w+)/g, (_, n) => vars[n] !== undefined ? vars[n] : '$' + n);
    // Collapse quote-concat: a"b"c → abc, .e""nv → .env, ."env" → .env
    part = part.replace(/"([^"]*)"/g, '$1').replace(/'([^']*)'/g, '$1');
    out.push(part);
  }
  return out.join('; ');
}

// Normalize all shell-command-valued fields of an args object before tokenizing.
function normalizeArgs(args) {
  if (!args || typeof args !== 'object') return args;
  const fields = ['command', 'cmd', 'function', 'script', 'shell'];
  const copy = { ...args };
  for (const [k, v] of Object.entries(copy)) {
    if (fields.includes(k.toLowerCase()) && typeof v === 'string') {
      copy[k] = normalizeShellCommand(v);
    }
  }
  return copy;
}

function extractFilenames(args) {
  args = normalizeArgs(args);
  const names = new Set();
  // Strip surrounding/trailing quotes — `"…/secret.env"` must reduce to
  // `secret.env`, not `secret.env"` (a trailing quote breaks the *.env glob).
  const dequote = (t) => t.replace(/^["'`]+/, '').replace(/["'`]+$/, '');
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s)) continue;
    // Process EVERY whitespace-separated token, not just the last `/` segment of
    // the whole string. Multi-file commands (`rm a b c`) must check all of them.
    const tokens = s.includes(' ') ? s.split(/\s+/) : [s];
    const single = tokens.length === 1;
    for (let tok of tokens) {
      tok = dequote(tok);
      if (!tok || /^https?:\/\//i.test(tok)) continue;
      if (tok.includes('/') || tok.includes('\\')) {
        const b = dequote(tok.replace(/\\/g, '/').split('/').pop() || '');
        if (b && (single || looksLikeFilename(b))) names.add(b);
      } else if (looksLikeFilename(tok)) {
        names.add(tok);
      }
    }
  }
  return [...names];
}

function extractUrls(args) {
  const urls = new Set();
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s)) { urls.add(s); continue; }
    if (s.includes(' ')) {
      for (const tok of s.split(/\s+/)) {
        if (/^https?:\/\//i.test(tok)) urls.add(tok);
      }
    }
  }
  return [...urls];
}

function extractCommands(args) {
  args = normalizeArgs(args);
  const cmds = [];
  const fields = ['command', 'cmd', 'function', 'script', 'shell'];
  if (typeof args === 'object' && args) {
    for (const [k, v] of Object.entries(args)) {
      if (fields.includes(k.toLowerCase()) && typeof v === 'string') {
        for (const part of v.split(/\s*(?:&&|\|\||;|\|)\s*/)) {
          const trimmed = part.trim();
          if (trimmed) cmds.push(trimmed);
        }
      }
    }
  }
  return cmds;
}

function extractPaths(args, isExec) {
  const paths = [];
  const add = (t) => {
    if (!t || /^https?:\/\//i.test(t)) return;
    // Normalize Windows backslashes to forward slashes so paths match the
    // compiled Rego patterns (which are also normalized to "/"). OPA glob.match
    // does no separator translation, so raw "C:\..." never matched "/" patterns.
    if (t.includes('/') || t.includes('\\') || t.startsWith('.')) paths.push(t.replace(/\\/g, '/'));
  };
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s)) continue;
    if (isExec && /\s/.test(s)) {
      // A command line (exec tool): pull out individual path-like tokens instead
      // of treating the whole command as one path. Otherwise `node src/app.js`
      // becomes the path "node src/app.js", which no path glob can match — so a
      // path-scoped EXECUTE rule would never fire. Tokenizing yields "src/app.js".
      for (const tok of s.split(/[\s;|&><()`'"]+/)) add(tok);
    } else {
      add(s);
    }
  }
  return paths;
}

// Expand shell globs in an exec command's tokens to the REAL files they match in
// that one directory. A filename/path DENY rule matches literally — `*.env` never
// matches the token `staging.e*` — so a bare `cut config/sub/staging.e*` would
// dodge an *.env rule that a plain `cat config/sub/staging.env` trips. Resolving
// the glob to `staging.env` here lets the rule see (and block) it, regardless of
// WHICH reader the model used. Bounded to a single directory level; returns real
// absolute paths. cwd is the agent's working dir (see hook payload).
// The files a content-returning search rooted at these arguments could return.
//
// Bounded and fail-open by construction: this is hardening on top of the
// literal match, never the thing standing between a call and a decision, so an
// unreadable tree or an exhausted budget leaves the literal match on its own
// rather than denying.
const SEARCH_WALK_MAX_FILES = 2000;
const SEARCH_WALK_MAX_DEPTH = 8;
const SEARCH_SKIP_DIRS = new Set([
  '.git', 'node_modules', '.venv', 'venv', 'vendor', 'dist', 'build', 'target',
  '__pycache__', '.next', '.turbo',
]);

// `websearch` reaches the network, not the disk, and guessPermission already
// puts it in NETWORK.
function isContentSearchTool(tool) {
  const n = String(tool || '').toLowerCase();
  if (n.includes('websearch') || n.includes('web_search')) return false;
  return n.includes('grep') || n.includes('search') || n.includes('ripgrep');
}

function walkSearchRoot(root, budget, depth, out) {
  if (budget.n <= 0 || depth > SEARCH_WALK_MAX_DEPTH) return;
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (budget.n <= 0) return;
    const p = root + '/' + e.name;
    if (e.isDirectory()) {
      if (SEARCH_SKIP_DIRS.has(e.name)) continue;
      walkSearchRoot(p, budget, depth + 1, out);
      continue;
    }
    budget.n--;
    out.push(p);
  }
}

function expandSearchRoots(tool, args, cwd) {
  if (!isContentSearchTool(tool) || !args || typeof args !== 'object') return [];
  const base = cwd || process.cwd();
  const out = [];
  const budget = { n: SEARCH_WALK_MAX_FILES };
  for (const v of scanStrings(args)) {
    if (budget.n <= 0) break;
    if (/^https?:\/\//i.test(v) || !/[/\\]/.test(v)) continue;
    const root = v.startsWith('/') ? v : base + '/' + v;
    try {
      if (!statSync(root).isDirectory()) continue;
    } catch {
      continue;
    }
    walkSearchRoot(root.replace(/\/+$/, ''), budget, 0, out);
  }
  return out;
}

function expandCommandGlobs(args, cwd) {
  const out = [];
  try {
    const base = cwd || process.cwd();
    for (const cmd of extractCommands(args)) {
      for (const tok of String(cmd).split(/[\s'"|<>;&()]+/)) {
        if (!tok || tok.startsWith('-') || !/[*?\[]/.test(tok) || /^https?:\/\//i.test(tok)) continue;
        let g = tok; if (g.startsWith('~')) g = homedir() + g.slice(1);
        let abs; try { abs = isAbsolute(g) ? g : resolve(base, g); } catch { continue; }
        const dir = dirname(abs), b = abs.slice(dir.length + 1);
        if (!/[*?\[]/.test(b)) continue;
        // The run of `*` is collapsed FIRST, and here that is the load-bearing
        // step: this glob came out of the AGENT's own command line, so the
        // pattern is attacker-supplied. `[^/]*[^/]*…` backtracks catastrophically
        // and is then tested once per directory entry, so `ls ***********x` in a
        // directory with one longish name hangs this hook — which, being
        // fail-closed, hangs the tool call. `[^/]*[^/]*` accepts exactly what
        // `[^/]*` accepts, so collapsing costs nothing. See dlpGlobToRe.
        let re; try { re = new RegExp('^' + b.replace(/\*{2,}/g, '*').replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]') + '$'); } catch { continue; }
        let files; try { files = readdirSync(dir); } catch { continue; }
        for (const f of files) if (re.test(f)) out.push(join(dir, f).replace(/\\/g, '/'));
      }
    }
  } catch { /* fail open — glob expansion is a hardening add-on, never a blocker */ }
  return out;
}

// ── Hardcoded Tamper Protection ──
// Runs BEFORE policy evaluation. Cannot be disabled by editing policies.
// Even if all policy rules are removed, these stay enforced.
const TAMPER_GUARD_TOOLS_WRITE = new Set([
  'write', 'edit', 'multiedit', 'notebookedit',
  'create', 'update', 'delete', 'remove', 'move', 'rename', 'copy',
  'filesystem', 'fs_write', 'fs_edit', 'str_replace_editor',
]);
const TAMPER_GUARD_TOOLS_EXEC = new Set([
  'bash', 'powershell', 'shell', 'exec', 'run', 'eval', 'cmd',
]);
const TAMPER_HOME = resolve(homedir()).replace(/\\/g, '/').toLowerCase();
const TAMPER_SG = '/.solongate';
const TAMPER_CC = '/.claude';
// The OTHER two guarded clients register the guard in their own config, so those
// files are disarm vectors exactly like ~/.claude/settings.json: deleting our
// entry from ~/.codex/hooks.json (or setting `[features] hooks = false` /
// flipping a hook's trust state in ~/.codex/config.toml) turns the guard off for
// Codex; the same holds for ~/.gemini/config/hooks.json and Antigravity.
const TAMPER_CX = '/.codex';
const TAMPER_AGY = '/.gemini/config';
const TAMPER_PROTECTED_ABS = [
  TAMPER_HOME + TAMPER_CC + '/settings.json',
  TAMPER_HOME + TAMPER_CC + '/settings.local.json',
  TAMPER_HOME + TAMPER_CX + '/hooks.json',
  TAMPER_HOME + TAMPER_CX + '/config.toml',
  TAMPER_HOME + TAMPER_AGY + '/hooks.json',
  TAMPER_HOME + TAMPER_SG + '/hooks',
  TAMPER_HOME + TAMPER_SG + '/policy.json',
  TAMPER_HOME + TAMPER_SG + '/.policy-cache.json',
  // The cloud credential (contains the API key) — never readable via a tool.
  TAMPER_HOME + TAMPER_SG + '/cloud-guard.json',
];
const TAMPER_INSTALL = '/solongate';
const TAMPER_PROTECTED_GLOBS = [
  '**' + TAMPER_CC + '/settings.json',
  '**' + TAMPER_CC + '/settings.local.json',
  '**' + TAMPER_CX + '/hooks.json',
  '**' + TAMPER_CX + '/config.toml',
  '**' + TAMPER_AGY + '/hooks.json',
  '**' + TAMPER_SG + '/hooks/**',
  '**' + TAMPER_SG + '/policy.json',
  '**' + TAMPER_SG + '/.policy-cache.json',
  '**' + TAMPER_SG + '/.policy-cache-*.json',
  '**' + TAMPER_SG + '/.pi-config-cache.json',
  '**' + TAMPER_SG + '/cloud-guard.json',
  '**' + TAMPER_SG + '/.opa-wasm-*.json',
  '**' + TAMPER_SG + '/.ratelimit-*.json',
  // Persistent host data (DB + audit JSONL) at ~/.solongate/data
  '**' + TAMPER_SG + '/data/**',
  // Customer install layout (zip extracted as solongate/)
  '**' + TAMPER_INSTALL + '/compose/**',
  '**' + TAMPER_INSTALL + '/data/**',
  '**' + TAMPER_INSTALL + '/images/**',
  '**' + TAMPER_INSTALL + '/helm/**',
  '**' + TAMPER_INSTALL + '/solongate.exe',
  '**' + TAMPER_INSTALL + '/setup.sh',
];
const TAMPER_BASENAMES = [
  'guard.mjs', 'audit.mjs', 'stop.mjs', 'shield.mjs',
  'policy.json',
  // Prefixes (substring match) so per-agent runtime state can't be deleted or
  // rewritten via a shell command either — `.policy-cache-<agent>.json`,
  // `.ratelimit-<agent>.json`, `.opa-wasm-<agent>.json`. Editing these could
  // otherwise flip enforcement off until the next cloud refresh; deleting just
  // forces a refetch, but neither should be reachable from an agent tool call.
  '.policy-cache', '.ratelimit-', '.opa-wasm-', '.pi-config-cache',
  'cloud-guard.json',
  // Customer install: DB and wizard exe
  'solongate.db', 'solongate.exe',
];
const TAMPER_PATH_FIELDS = new Set([
  'file_path', 'path', 'target_file', 'notebook_path',
  'dest', 'destination', 'source', 'src', 'from', 'to',
  'directory', 'dir', 'folder',
  // Antigravity CLI file-tool arg names (camelCase, lowercased here): its
  // write/read/list tools carry the path in these, so tamper protection sees it.
  'targetfile', 'absolutepath', 'filepath',
]);

function normTamperPath(p) {
  return String(p || '').replace(/\\/g, '/').toLowerCase();
}

function isProtectedPath(p) {
  if (!p) return false;
  const np = normTamperPath(p);
  for (const abs of TAMPER_PROTECTED_ABS) {
    if (np === abs || np.startsWith(abs + '/')) return abs;
  }
  for (const g of TAMPER_PROTECTED_GLOBS) {
    if (matchPathGlob(np, g)) return g;
  }
  if (/\/\.claude\/settings(\.local)?\.json$/.test(np)) return 'settings.json';
  if (/\/\.solongate\/hooks(\/|$)/.test(np)) return 'solongate-hooks';
  if (/\/\.codex\/(hooks\.json|config\.toml)$/.test(np)) return 'codex-hooks';
  if (/\/\.gemini\/config\/hooks\.json$/.test(np)) return 'antigravity-hooks';
  return false;
}

function commandTargetsProtected(cmd) {
  const c = String(cmd || '').toLowerCase();
  if (!c) return false;
  for (const b of TAMPER_BASENAMES) {
    if (c.includes(b.toLowerCase())) return b;
  }
  if (/\.claude[\\/]+settings(\.local)?\.json/.test(c)) return 'settings.json';
  if (/\.solongate[\\/]+hooks/.test(c)) return 'solongate-hooks';
  if (/\.codex[\\/]+(hooks\.json|config\.toml)/.test(c)) return 'codex-hooks';
  if (/\.gemini[\\/]+config[\\/]+hooks\.json/.test(c)) return 'antigravity-hooks';
  // Customer install dirs
  if (/[\\/]solongate[\\/]+(compose|data|images|helm)[\\/]/.test(c)) return 'solongate-install';
  // Mutating API calls against policies / audit-logs endpoints
  const mutating = /\b(post|put|delete|patch)\b/.test(c) ||
                   /(-x|--request|-method)\s+(post|put|delete|patch)\b/.test(c);
  if (mutating && /api\/v1\/(policies|audit-logs)/.test(c)) return 'api-policies-mutation';
  return false;
}

function extractTargetPaths(args) {
  const out = [];
  if (typeof args !== 'object' || !args) return out;
  for (const [k, v] of Object.entries(args)) {
    const lk = k.toLowerCase();
    if (TAMPER_PATH_FIELDS.has(lk) && typeof v === 'string') out.push(v);
    if (Array.isArray(v)) {
      for (const item of v) {
        if (item && typeof item === 'object') {
          for (const [k2, v2] of Object.entries(item)) {
            if (TAMPER_PATH_FIELDS.has(k2.toLowerCase()) && typeof v2 === 'string') out.push(v2);
          }
        }
      }
    }
  }
  return out;
}

function tamperCheck(toolName, args) {
  const tn = String(toolName || '').toLowerCase();
  const isExec = TAMPER_GUARD_TOOLS_EXEC.has(tn) || /bash|shell|exec|powershell|cmd|run|eval/.test(tn);
  // ANY tool that targets a protected path is blocked — READ as well as write.
  // An AI must not even read SolonGate's own protection files. This is enforced
  // at the tool boundary; the hooks themselves are run by node directly (not via
  // a Claude Code tool), so node still loads/executes them normally.
  // Check the tool's TARGET PATH fields only (file_path, path, …) — never the
  // free-form content/body, which would false-positive on any file that merely
  // mentions a protected path in its text.
  for (const p of extractTargetPaths(args)) {
    const hit = isProtectedPath(p);
    if (hit) return 'Tamper protection: access to "' + p + '" is blocked (protected: ' + hit + ')';
  }
  if (isExec) {
    for (const cmd of extractCommands(args)) {
      const hit = commandTargetsProtected(cmd);
      if (hit) return 'Tamper protection: command references protected resource "' + hit + '" — blocked';
    }
  }
  return null;
}

// ── Extra security layers (rate limit, egress allowlist, DLP block) ──
// These are configured per-project in the dashboard and delivered to the guard
// via /policies/active (security). All fail OPEN: any error here returns null
// (allow) so a config glitch never bricks the agent. Tamper protection and
// policy are unaffected and still run.

// DLP patterns mirror the server's set (apps/api/src/lib/security-layers.ts).
// Mirrors apps/api/src/lib/security-layers.ts DLP_PATTERNS. Provider-specific
// rules plus generic Bearer / secret-assignment catch-alls for the long tail.
const DLP_PATTERNS = [
  { name: 'AWS access key', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'Private key block', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: 'Anthropic key', re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'OpenAI key', re: /sk-(proj-)?[A-Za-z0-9_-]{20,}/ },
  { name: 'GitHub token', re: /gh[pousr]_[A-Za-z0-9]{20,}/ },
  { name: 'GitHub fine-grained PAT', re: /github_pat_[A-Za-z0-9_]{20,}/ },
  { name: 'GitLab token', re: /glpat-[A-Za-z0-9_-]{20,}/ },
  { name: 'Slack token', re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: 'Stripe key', re: /[sr]k_(live|test)_[A-Za-z0-9]{20,}/ },
  { name: 'SendGrid key', re: /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/ },
  { name: 'Twilio key', re: /SK[0-9a-fA-F]{32}/ },
  { name: 'npm token', re: /npm_[A-Za-z0-9]{36}/ },
  { name: 'JWT', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: 'Bearer token', re: /bearer\s+[A-Za-z0-9._-]{20,}/i },
];

// A RUN of `*` collapses to one, and that is a fix rather than a tidy-up.
//
// `*` becomes `[^\s]*`, so `**` became `[^\s]*[^\s]*` — two unbounded
// quantifiers over the SAME character class, back to back. JavaScript's regex
// engine backtracks, and that shape is the textbook catastrophic case: on a
// subject that nearly matches, the cost doubles per extra star. Measured on this
// converter, against sixty characters of ordinary text: six stars took 0.9s,
// eight took 28s, ten took four minutes, and twenty-four did not finish.
//
// It is reachable from a pattern somebody types (`dlp add-custom --re '****x'`)
// and the scan runs over every tool result, so a handful of stars is a hung
// agent rather than a slow one — this hook is fail-closed, so a scan that never
// returns is a tool call that never returns.
//
// Collapsing changes NOTHING about what a glob accepts: `[^\s]*[^\s]*` matches
// exactly the strings `[^\s]*` matches. Go's twin is RE2, which has no
// backtracking and was never affected; it collapses too so the pair stays
// identical to read.
const dlpGlobCollapse = /\*{2,}/g;

// Custom patterns are GLOBs: `*` = any run of non-whitespace, same wildcard
// mechanic as the policy layer.
function dlpGlobToRe(glob) {
  let re = '';
  for (const ch of String(glob || '').replace(dlpGlobCollapse, '*')) {
    if (ch === '*') re += '[^\\s]*';
    else if ('.+?^${}()|[]\\'.indexOf(ch) !== -1) re += '\\' + ch;
    else re += ch;
  }
  return new RegExp(re, 'i');
}
// De-obfuscated VIEWS of the scanned text, so an agent can't smuggle a secret
// past the literal patterns by SPLITTING it (printf "AKIA""3XZ9…") or ENCODING it
// (echo <base64> | base64 -d). We scan every view. Not exhaustive — pattern DLP
// can never be — but it closes the two obvious bypasses.
function dlpViews(text) {
  const views = [text];
  try {
    // 1) Drop shell quotes + backslashes so a split secret collapses back to a
    //    contiguous run: "AKIA""3XZ9…" / 'AKIA'\''…' / AKIA\3XZ9 → AKIA3XZ9…
    const dequoted = text.replace(/[`'"\\]/g, '');
    if (dequoted !== text) views.push(dequoted);
    // 2) Decode base64-looking tokens (from both the raw and the dequoted view —
    //    the payload itself may be split too) and scan the decoded bytes.
    const src = dequoted !== text ? text + '\n' + dequoted : text;
    const toks = src.match(/[A-Za-z0-9+/]{16,}={0,2}/g) || [];
    let decoded = '';
    for (const t of toks.slice(0, 60)) {
      try {
        const d = Buffer.from(t, 'base64').toString('latin1');
        if (/[ -~]{8,}/.test(d)) decoded += d + '\n'; // keep printable decodes only
      } catch { /* not base64 */ }
    }
    if (decoded) views.push(decoded);
  } catch { /* fall back to the raw view */ }
  return views;
}
// Scan args against the enabled built-in patterns + any user custom patterns.
// `cfg` = { patterns: string[], custom: {name,re}[] }.
function dlpScan(args, cfg) {
  if (!cfg) return null;
  let text = '';
  try { text = JSON.stringify(args || {}); } catch { return null; }
  // Content that's ALREADY been redacted must not re-trigger DLP — otherwise you
  // can't write a report / save a diff / paste a ticket containing masked output
  // (the `[REDACTED:name]` marker can itself contain a pattern name that matches).
  // Strip those markers before scanning so a safe, masked value is never treated
  // as a live secret.
  text = text.replace(/\[REDACTED:[^\]]*\]/g, '');
  const views = dlpViews(text);
  const allow = new Set(Array.isArray(cfg.patterns) ? cfg.patterns : []);
  for (const p of DLP_PATTERNS) {
    if (allow.has(p.name) && views.some((v) => p.re.test(v))) return p.name;
  }
  for (const c of Array.isArray(cfg.custom) ? cfg.custom : []) {
    try { const re = dlpGlobToRe(c.re); if (views.some((v) => re.test(v))) return c.name || 'custom pattern'; } catch { /* skip invalid */ }
  }
  return null;
}

// Egress DLP: pattern DLP scans tool ARGUMENTS + tool OUTPUT, but a command like
// `curl --data-binary @.env <url>` reads the file ITSELF — the secret never
// appears in an argument or a tool result, so plain DLP misses it. Here, when a
// downloader/transfer command SENDS to an external host, we read the local files
// it would upload and scan THEM; a hit blocks the call. Only runs when DLP block
// is configured, and only for transfer commands (rare), so the extra file read
// is off the common hot path.
function egressSecretCheck(args, sec, cwd) {
  try {
    const dlp = sec && sec.dlpBlock;
    if (!dlp) return null;
    // Resolve the files a transfer command reads relative to the AGENT's cwd, not
    // the guard process's cwd. On Antigravity the hook runs with cwd set to the
    // hooks.json directory (~/.gemini/config), so a bare `resolve('config/x')`
    // would look in the wrong place and the egress check would silently miss.
    const base = cwd || process.cwd();
    for (const cmd of extractCommands(args)) {
      const c = String(cmd || '');
      const lc = c.toLowerCase();
      if (!/\b(curl|wget|scp|rsync|sftp|ftp|nc|netcat)\b/.test(lc)) continue;
      // Must actually send OUTWARD: an http(s) URL or a host:path target.
      if (!/https?:\/\//.test(lc) && !/@[\w.-]+:/.test(c) && !/\b\S+:\S/.test(c)) continue;
      // Local files the command reads to send (@file, -d/-T/--data* @file, cat, <).
      const files = new Set();
      let m;
      for (const re of [
        /@([^\s'"|>&]+)/g,
        /(?:-T|--upload-file|--data-binary|--data-raw|--data|-d|-F|--form)[=\s]+@?([^\s'"|>&]+)/g,
        /\bcat\s+([^\s'"|>&]+)/g,
        /<\s*([^\s'"|>&]+)/g,
      ]) {
        while ((m = re.exec(c))) {
          const f = m[1];
          if (f && f !== '-' && !/^https?:\/\//.test(f) && !/^[@{[]/.test(f)) files.add(f);
        }
      }
      for (let f of files) {
        if (f.startsWith('~')) f = homedir() + f.slice(1);
        let abs; try { abs = isAbsolute(f) ? f : resolve(base, f); } catch { continue; }
        let content = null;
        try { content = readFileSync(abs, 'utf-8'); } catch { continue; }
        if (!content) continue;
        const hit = dlpScan(content, dlp);
        if (hit) return 'DLP: outbound transfer of "' + f + '" is blocked - it contains a ' + hit + ' (egress protection)';
      }
    }
  } catch { /* fail open — never break a legitimate command on a scan error */ }
  return null;
}

// Mask every enabled secret in `text` as `[REDACTED:name]` (mirrors audit.mjs's
// output redaction so Antigravity gets the SAME masking Claude does).
function dlpRedactText(text, cfg) {
  if (!cfg || typeof text !== 'string') return text;
  let out = text;
  const allow = new Set(Array.isArray(cfg.patterns) ? cfg.patterns : []);
  for (const p of DLP_PATTERNS) {
    if (!allow.has(p.name)) continue;
    const g = p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g';
    try { out = out.replace(new RegExp(p.re.source, g), `[REDACTED:${p.name}]`); } catch {}
  }
  for (const c of Array.isArray(cfg.custom) ? cfg.custom : []) {
    try { const re = dlpGlobToRe(c.re); out = out.replace(new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'), `[REDACTED:${c.name || 'custom'}]`); } catch {}
  }
  return out;
}

// Antigravity read redaction via `overwrite` (hooks.md): agy can't rewrite tool
// OUTPUT, but it CAN rewrite the tool's ARGS before it runs. So when a read would
// surface a secret file, we write a REDACTED copy to a temp path and point the
// read at that copy — the agent sees `[REDACTED:…]` exactly like on Claude, no
// block needed. Works for the native read tool (swap the path arg) and shell
// reads (swap the file token in the command). FAIL-CLOSED: any uncertainty →
// `{block:true}` so a secret can never leak through a redaction that didn't apply.
function dlpRedactReadPlan(toolName, args, dlp, cwd) {
  try {
    if (!dlp || !args) return null;
    const base = cwd || process.cwd();
    const abends = (f) => { let x = f; if (x.startsWith('~')) x = homedir() + x.slice(1); return isAbsolute(x) ? x : resolve(base, x); };
    // Returns: 'SKIP' (not a readable file / too big) · 'CLEAN' (readable, no
    // secret) · a temp path (redacted copy written) · 'FAILED' (has a secret but
    // the copy couldn't be written → caller must BLOCK, never leak).
    const redactCopy = (abs) => {
      let content;
      try { const st = statSync(abs); if (!st.isFile() || st.size > 1048576) return 'SKIP'; content = readFileSync(abs, 'utf-8'); } catch { return 'SKIP'; }
      if (dlpScan(content, dlp) == null) return 'CLEAN';
      try {
        const dir = join(resolve(homedir(), '.solongate'), '.redacted');
        mkdirSync(dir, { recursive: true });
        const tmp = join(dir, createHash('sha256').update(abs).digest('hex').slice(0, 24) + '-' + (abs.split('/').pop() || 'f'));
        writeFileSync(tmp, dlpRedactText(content, dlp));
        return tmp;
      } catch { return 'FAILED'; }
    };
    // Native read tool: scan EVERY string arg that looks like a path (so an
    // unfamiliar arg name can't slip a secret file through), swap the one that is
    // a secret file for its redacted copy.
    for (const [k, v] of Object.entries(args)) {
      if (k === 'command' || typeof v !== 'string' || !v || !/[./]/.test(v)) continue;
      const r = redactCopy(abends(v));
      if (r === 'SKIP' || r === 'CLEAN') continue;
      if (r === 'FAILED') return { block: true };
      return { rewrite: { [k]: r } };
    }
    // Expand a shell glob token (`staging.e*`, `prod-*.txt`) to the real files it
    // matches in that ONE directory. Globs are the classic redaction dodge: the
    // filename rule can't match `staging.e*` against `*.env`, and a redacted-copy
    // swap can't statSync a path with a literal `*` in it — so a bare
    // `cat staging.e*` would read the secret unredacted. Expanding here closes it.
    const GLOB_META = /[*?\[]/;
    const expandGlob = (absGlob) => {
      try {
        const dir = dirname(absGlob);
        const base = absGlob.slice(dir.length + 1);
        if (!GLOB_META.test(base)) return [absGlob];
        // Runs of `*` collapsed first: the token is the agent's, and adjacent
        // `[^/]*` groups backtrack catastrophically. Same reasoning as
        // expandCommandGlobs, which this mirrors.
        const re = new RegExp('^' + base.replace(/\*{2,}/g, '*').replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]') + '$');
        return readdirSync(dir).filter((f) => re.test(f)).map((f) => join(dir, f));
      } catch { return []; }
    };
    // Shell read command: swap each secret file token for its redacted copy.
    // The command list is broad on purpose: agy can't redact tool OUTPUT, so any
    // text-processing tool that can print a file's contents is a redaction dodge
    // if it's missing here (the model reached for `cut`/`awk` the moment `cat` was
    // blocked). Enumerating every reader is a losing game (python -c, $(<f), while
    // read, …); this covers the common ones and the glob path below fails closed.
    const cmd = typeof args.command === 'string' ? args.command : '';
    if (cmd && /\b(cat|less|more|head|tail|bat|nl|od|xxd|hexdump|strings|grep|egrep|fgrep|rg|ag|cut|awk|gawk|sed|tr|sort|uniq|paste|join|comm|column|fold|tac|rev|pr|expand|unexpand|base64|base32|dd|mapfile|readarray)\b/.test(cmd.toLowerCase())) {
      let newCmd = cmd, changed = false;
      for (const tok of cmd.split(/[\s'"|<>;&()]+/)) {
        if (!tok || tok.startsWith('-') || !/[./]/.test(tok)) continue;
        // A glob can't be swapped for a single redacted copy — expand it and, if
        // ANY matched file holds a secret, BLOCK the whole read (fail-closed).
        if (GLOB_META.test(tok)) {
          for (const f of expandGlob(abends(tok))) {
            const rg = redactCopy(f);
            if (rg !== 'SKIP' && rg !== 'CLEAN') return { block: true };
          }
          continue;
        }
        const r = redactCopy(abends(tok));
        if (r === 'SKIP' || r === 'CLEAN') continue;
        if (r === 'FAILED') return { block: true };
        newCmd = newCmd.split(tok).join(r); changed = true;
      }
      if (changed) return { rewrite: { command: newCmd } };
    }
  } catch { return { block: true }; } // fail-closed: never leak on an error
  return null;
}

// DLP read-block for Antigravity ONLY. On Claude Code a secret in a file the
// agent reads is REDACTED by the PostToolUse audit hook. Antigravity runs no
// PostToolUse hook and its PreToolUse can't rewrite output, so redaction is
// impossible there — the only enforcement left is to DENY the read outright.
// So when DLP block is on, read the file the tool would surface and, if it holds
// a secret, block the call. Bounded (≤1MB) and gated to agy + read-ish tools.
function dlpReadCheck(args, dlp, cwd) {
  try {
    if (!dlp) return null;
    const files = new Set();
    for (const p of extractTargetPaths(args)) if (p) files.add(p);
    for (const cmd of extractCommands(args)) {
      const c = String(cmd);
      if (!/\b(cat|less|more|head|tail|bat|nl|od|xxd|strings|grep|egrep|rg|awk|sed)\b/.test(c.toLowerCase())) continue;
      for (const tok of c.split(/[\s'"|<>;&()]+/)) {
        const t = cleanShellToken(tok);
        if (t && !t.startsWith('-') && /[./]/.test(t)) files.add(t);
      }
    }
    const base = cwd || process.cwd();
    for (let f of files) {
      if (f.startsWith('~')) f = homedir() + f.slice(1);
      let abs; try { abs = isAbsolute(f) ? f : resolve(base, f); } catch { continue; }
      let content;
      try { const st = statSync(abs); if (!st.isFile() || st.size > 1048576) continue; content = readFileSync(abs, 'utf-8'); } catch { continue; }
      const hit = dlpScan(content, dlp);
      if (hit) return 'Security layer (DLP): reading "' + f + '" is blocked — it contains a ' + hit + '. Blocked by SolonGate.';
    }
  } catch { /* fail open */ }
  return null;
}

// Strip shell decoration from a token so it can be tested as a path:
// surrounding quotes, redirection operators, trailing punctuation.
function cleanShellToken(tok) {
  let t = String(tok || '').trim();
  t = t.replace(/^[<>|;&(]+/, '').replace(/[);&|]+$/, '');
  t = t.replace(/^['"]+/, '').replace(/['"]+$/, '');
  t = t.replace(/^\d*>>?/, ''); // strip leading redirection like 2>
  return t.trim();
}

// Multi-window sliding rate limit, persisted under ~/.solongate (tamper-protected
// from the agent, writable by the guard). One timestamps file per agent, pruned
// to the last 24h and capped for performance; counts this agent's calls within
// each enabled window (minute/hour/day). Returns the exceeded window or null.
const RL_WINDOWS = [
  { key: 'perDay', ms: 86400000, label: 'day' },
  { key: 'perHour', ms: 3600000, label: 'hour' },
  { key: 'perMinute', ms: 60000, label: 'minute' },
];
// One call = one fixed-width record, appended. 13 digits of epoch ms + newline;
// good until the year 2286, and fixed width is what lets the file be read by
// offset without parsing it all.
const RL_REC = 14;
const RL_MAX_READ = 1_048_576; // tail we scan: ~74k calls, far past any window
const RL_MAX_FILE = 4_194_304; // compact past this

/**
 * Rate limit, counted with an append-only log.
 *
 * This used to read a JSON array of timestamps, count, push one and write the
 * whole array back. Under a burst of parallel tool calls — the exact thing a
 * rate limit is for — every hook read the same array and wrote back its own
 * copy, so increments were lost and the limit did not hold: measured at 14
 * calls through a limit of 5, from 30 fired at once.
 *
 * An O_APPEND write of a short record does not interleave, so no call can erase
 * another's. The reservation is made BEFORE the decision, which is what makes
 * the count exact under concurrency: every process appends, then counts what is
 * in the window, and the ones past the limit are the ones refused. A refused
 * call therefore also occupies a slot, which is the honest reading of a rate
 * limit — thirty attempts in a minute IS thirty calls a minute, whatever came
 * back. (This is the same trick the guest allowance used for the same reason.)
 */
function rateLimitCheck(agentKey, limits) {
  try {
    const dir = resolve(homedir(), '.solongate');
    // New name: the old .json holds an array this format cannot read, and one
    // window resetting on upgrade is better than parsing ambiguity.
    const file = join(dir, '.ratelimit-' + agentKey + '.log');
    const now = Date.now();
    try { mkdirSync(dir, { recursive: true }); } catch {}
    // Reserve first. A failed append must not hand out a free call, so treat it
    // as "cannot account for this" and fall open the same way the catch does.
    try { appendFileSync(file, String(now).padStart(13, '0') + '\n'); } catch { return null; }

    let size = 0;
    try { size = statSync(file).size; } catch { return null; }
    const start = Math.max(0, size - RL_MAX_READ);
    // Align to a record boundary so a truncated head is never parsed.
    const from = start - (start % RL_REC);
    let buf = '';
    try {
      const fd = openSync(file, 'r');
      const b = Buffer.alloc(size - from);
      readSync(fd, b, 0, b.length, from);
      closeSync(fd);
      buf = b.toString('latin1');
    } catch { return null; }

    const stamps = [];
    for (let i = 0; i + RL_REC <= buf.length; i += RL_REC) {
      const t = parseInt(buf.slice(i, i + 13), 10);
      if (Number.isFinite(t) && now - t < 86400000) stamps.push(t);
    }
    // Our own record is in here, so the limit is crossed at > rather than >=.
    for (const w of RL_WINDOWS) {
      const limit = limits[w.key];
      if (limit > 0) {
        const count = stamps.reduce((n, t) => (now - t < w.ms ? n + 1 : n), 0);
        if (count > limit) return { window: w.label, limit };
      }
    }

    // Compaction, rarely: keep the last 24h. Written beside and renamed, so a
    // reader never sees a half-written file. An append landing during the swap
    // is lost, which costs one call of accuracy on a file this size.
    if (size > RL_MAX_FILE) {
      try {
        const tmp = file + '.' + process.pid + '.tmp';
        writeFileSync(tmp, stamps.map((t) => String(t).padStart(13, '0') + '\n').join(''));
        renameSync(tmp, file);
      } catch { /* keep growing rather than risk the file */ }
    }
    return null;
  } catch {
    return null; // fail open
  }
}

// Runs all enabled enforcement layers; returns a deny reason or null (allow).
function securityLayerCheck(toolName, args, cfg, agentKey) {
  if (!cfg) return null;
  try {
    if (cfg.dlpBlock) {
      const hit = dlpScan(args, cfg.dlpBlock);
      if (hit) return 'Security layer (DLP): blocked - arguments contain a ' + hit +
        '. Blocked by SolonGate - check your dashboard for details.';
    }
    if (cfg.rateLimit) {
      const hit = rateLimitCheck(agentKey, cfg.rateLimit);
      if (hit) {
        return 'Security layer (rate limit): exceeded ' + hit.limit + ' calls/' + hit.window +
          ' for this agent. Blocked by SolonGate - check your dashboard to review or adjust the limit.';
      }
    }
  } catch { /* fail open */ }
  return null;
}

// ── Policy Evaluation ──

// Permission filter: a rule with rule.permission set only applies to tool
// calls whose guessed permission category is in that list. Empty/missing =
// applies to all categories.
function permissionApplies(rule, toolName) {
  if (!rule.permission) return true;
  const perms = Array.isArray(rule.permission) ? rule.permission : [rule.permission];
  if (perms.length === 0) return true;
  const guessed = guessPermission(toolName);
  return perms.includes(guessed);
}

// Returns the first pattern that any of the rule's constraints matches against
// the args, or null if nothing matches. Used for both DENY (engine blocks on
// match) and ALLOW (whitelist mode requires at least one match).
// Each constraint may store its pattern list in either `denied` or `allowed`
// depending on which effect the rule was created with in the dashboard. The
// hook treats both as the same "pattern list" — the rule's effect determines
// whether a match means block (DENY) or pass (ALLOW in whitelist mode).
function patternsOf(constraint) {
  if (!constraint) return null;
  const list = constraint.denied || constraint.allowed;
  return Array.isArray(list) && list.length > 0 ? list : null;
}

function ruleMatches(rule, args, isExec) {
  const fnPats = patternsOf(rule.filenameConstraints);
  if (fnPats) {
    const filenames = extractFilenames(args);
    for (const fn of filenames) {
      for (const pat of fnPats) {
        if (matchGlob(fn, pat)) return { kind: 'filename', value: fn, pattern: pat };
      }
    }
  }
  const urlPats = patternsOf(rule.urlConstraints);
  if (urlPats) {
    const urls = extractUrls(args);
    for (const url of urls) {
      for (const pat of urlPats) {
        if (matchGlob(url, pat)) return { kind: 'URL', value: url, pattern: pat };
      }
    }
  }
  const cmdPats = patternsOf(rule.commandConstraints);
  if (cmdPats) {
    const cmds = extractCommands(args);
    for (const cmd of cmds) {
      for (const pat of cmdPats) {
        if (matchGlob(cmd, pat)) return { kind: 'command', value: cmd.slice(0, 60), pattern: pat };
      }
    }
  }
  const pathPats = patternsOf(rule.pathConstraints);
  if (pathPats) {
    const paths = extractPaths(args, isExec);
    for (const p of paths) {
      for (const pat of pathPats) {
        if (matchPathGlob(p, pat)) return { kind: 'path', value: p, pattern: pat };
      }
    }
  }
  return null;
}

// Evaluate policy. Two modes:
//   denylist (default): default ALLOW. Any DENY rule that matches → block.
//   whitelist (strict): default DENY. Must match at least one ALLOW rule to
//                       pass. DENY rules still override on top.
function evaluate(policy, args, toolName) {
  if (!policy || !policy.rules) return null;
  const enabledRules = policy.rules.filter(r => r.enabled !== false);
  const mode = policy.mode === 'whitelist' ? 'whitelist' : 'denylist';
  const isExec = /bash|shell|exec|powershell|cmd|run|eval/.test((toolName || '').toLowerCase());

  // DENY pass — runs in both modes. DENY wins over ALLOW.
  const denyRules = enabledRules
    .filter(r => r.effect === 'DENY' && permissionApplies(r, toolName))
    .sort((a, b) => (a.priority || 100) - (b.priority || 100));
  for (const rule of denyRules) {
    const m = ruleMatches(rule, args, isExec);
    if (m) return 'Blocked by policy: ' + m.kind + ' "' + m.value + '" matches "' + m.pattern + '"';
  }

  // Whitelist pass — only in strict mode. Must match at least one ALLOW rule.
  if (mode === 'whitelist') {
    const allowRules = enabledRules.filter(r => r.effect === 'ALLOW' && permissionApplies(r, toolName));
    if (allowRules.length === 0) {
      return 'Blocked by policy: strict whitelist mode is on and no ALLOW rule applies to ' + (toolName || 'this tool');
    }
    let matched = false;
    for (const rule of allowRules) {
      if (ruleMatches(rule, args, isExec)) { matched = true; break; }
    }
    if (!matched) {
      return 'Blocked by policy: strict whitelist mode — request does not match any ALLOW rule';
    }
  }

  return null;
}

// ── OPA WASM Evaluation (NIST SP 800-207 PDP) ──
//
// When the API has compiled this policy to an OPA WASM bundle AND the
// @open-policy-agent/opa-wasm runtime is resolvable, we evaluate through OPA
// instead of the hand-written evaluate() above. This is the same decision
// engine the MCP proxy uses (packages/policy-engine/src/opa).
//
// Graceful degradation is the contract: any missing piece (no bundle, no
// runtime, fetch/parse/eval error) makes evaluateWithOpa() return `undefined`,
// and the caller falls back to the legacy JS evaluate() — so air-gapped
// installs without OPA see ZERO behavior change.

// Cheap, dependency-free djb2 fingerprint to detect policy changes for caching.
function djb2(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}

// Extracts /policy.wasm from an OPA bundle. Mirrors
// packages/policy-engine/src/opa/opa-evaluator.ts extractWasmFromBundle().
// The bundle may be a gzipped tar (.tar.gz from `opa build -t wasm`) or raw WASM.
function extractWasmFromBundle(buf) {
  if (buf[0] === 0x1f && buf[1] === 0x8b) {
    const tar = gunzipSync(buf);
    let offset = 0;
    while (offset < tar.length - 512) {
      const nameEnd = tar.indexOf(0, offset);
      const name = tar.subarray(offset, Math.min(nameEnd, offset + 100)).toString('utf-8');
      if (!name || name.length === 0) break;
      const sizeStr = tar.subarray(offset + 124, offset + 136).toString('utf-8').trim();
      const size = parseInt(sizeStr, 8) || 0;
      offset += 512;
      if (name === 'policy.wasm' || name === './policy.wasm' || name.endsWith('/policy.wasm')) {
        return Buffer.from(tar.subarray(offset, offset + size));
      }
      offset += Math.ceil(size / 512) * 512;
    }
    throw new Error('policy.wasm not found in OPA bundle');
  }
  if (buf[0] === 0x00 && buf[1] === 0x61 && buf[2] === 0x73 && buf[3] === 0x6d) {
    return buf; // already raw WASM
  }
  throw new Error('Unknown OPA bundle format');
}

// Fetches the compiled WASM for this policy from the API, with a local cache
// keyed by a fingerprint of the policy so updates propagate. Returns the raw
// policy.wasm bytes (Uint8Array) or null when unavailable.
// The WASM cache is keyed by `fp`, a fingerprint of the policy rules+mode, so a
// real policy change invalidates it immediately regardless of age. The TTL is
// therefore only a backstop for a server-side recompile that keeps the same
// rules — a rare event — so we keep it long (24h) instead of re-downloading the
// bundle every 30s on the hot path.
const OPA_WASM_TTL_MS = 24 * 60 * 60 * 1000;
async function getOpaWasmBytes(policy) {
  if (!policy || !policy.id) return null;
  const fp = djb2(JSON.stringify(policy.rules || []) + '|' + (policy.mode || ''));
  const agentKey = (AGENT_ID || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
  const cacheFile = join(resolve(homedir(), '.solongate'), '.opa-wasm-' + agentKey + '.json');

  // Read any cached bundle. A "fresh" hit (same policy fingerprint, within TTL)
  // is returned immediately; otherwise we keep it as `stale` to fall back on if
  // the API is momentarily unreachable — so transient downtime never drops OPA.
  //
  // ONLY when the fingerprint still matches. A bundle compiled from a DIFFERENT
  // policy is not "last known good", it is the wrong policy: it enforces rules
  // the user has deleted and misses the ones they just wrote. That is what a
  // stale hit did until now, and it is invisible from the outside — the denial
  // cites a rule id that is no longer in `policy active`, and the user's only
  // clue is that their own policy does not contain the rule that just fired.
  //
  // Dropping it here does not disarm anything. With no bundle the guard falls
  // through to its deterministic evaluator, which reads the policy it actually
  // has, so a fingerprint mismatch costs the OPA-only behaviours and keeps the
  // rules correct. Enforcing a deleted rule is the worse of the two.
  let stale = null;
  try {
    if (existsSync(cacheFile)) {
      const c = JSON.parse(readFileSync(cacheFile, 'utf-8'));
      if (c && c.wasm && c.fp === fp) {
        stale = new Uint8Array(Buffer.from(c.wasm, 'base64'));
        if (c._ts && Date.now() - c._ts < OPA_WASM_TTL_MS) {
          return stale;
        }
      }
    }
  } catch {}

  // Fetch the compiled bundle from the API (route already exists).
  try {
    const res = await fetch(
      API_URL + '/api/v1/policies/' + encodeURIComponent(policy.id) + '/wasm',
      { headers: AUTH_HEADERS, signal: AbortSignal.timeout(2500) },
    );
    if (!res.ok) return stale; // API has no compiled WASM right now → last known good
    const bundle = Buffer.from(await res.arrayBuffer());
    const wasm = extractWasmFromBundle(bundle);
    try {
      mkdirSync(resolve(homedir(), '.solongate'), { recursive: true });
      writeFileSync(cacheFile, JSON.stringify({ _ts: Date.now(), fp, wasm: Buffer.from(wasm).toString('base64') }));
    } catch {}
    return new Uint8Array(wasm);
  } catch {
    return stale; // transient network failure → last known good
  }
}

// Lazily load the opa-wasm runtime. Returns the loadPolicy fn or null if the
// package isn't installed in this environment (typical for air-gapped hooks).
let _loadPolicyFn = null;
let _loadPolicyTried = false;
async function getLoadPolicy() {
  if (_loadPolicyTried) return _loadPolicyFn;
  _loadPolicyTried = true;
  try {
    const mod = await import('@open-policy-agent/opa-wasm');
    _loadPolicyFn = mod.loadPolicy || (mod.default && mod.default.loadPolicy) || null;
  } catch {
    _loadPolicyFn = null;
  }
  return _loadPolicyFn;
}

// Evaluates the policy through OPA WASM. Returns:
//   - a reason string  → DENY
//   - null             → ALLOW (OPA decided, no violation)
//   - undefined        → OPA unavailable, caller must fall back to evaluate()
async function evaluateWithOpa(policy, args, toolName, cwd) {
  if (!policy || !policy.rules) return undefined;
  try {
    const loadPolicy = await getLoadPolicy();
    if (!loadPolicy) return undefined;
    const wasmBytes = await getOpaWasmBytes(policy);
    if (!wasmBytes) return undefined;

    const opaPolicy = await loadPolicy(wasmBytes, { initial: 5 });
    // trust_level is fixed to 'TRUSTED' to preserve legacy guard.mjs behavior,
    // which never evaluated minimumTrustLevel constraints.
    // If the tool call references files (bash X.sh, source X, etc.), inline
    // their contents so the SAME deterministic extractors see hidden commands.
    // The hook reads files itself; OPA gets a flat, expanded view — no LLM
    // needed for hidden-in-file detection at this layer.
    // Inline referenced-file CONTENT only for tools that EXECUTE a script
    // (`bash X.sh` → X.sh would run, so its contents matter). For read/write
    // tools the file is data, not code — inlining its content there causes false
    // positives (e.g. reading a file that merely mentions ".env" tripping an
    // *.env rule, or reading a script that documents `rm -rf`).
    const isExecTool = /bash|shell|exec|powershell|cmd|run|eval/.test((toolName || '').toLowerCase());
    const refFiles = (isExecTool && typeof readReferencedFiles === 'function')
      ? readReferencedFiles(args, cwd || process.cwd())
      : {};
    const expandedArgs = { ...((args && typeof args === 'object') ? args : {}) };
    for (const [, content] of Object.entries(refFiles)) {
      const lines = String(content).split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
      if (lines.length > 0) {
        const extra = lines.join('; ');
        if (typeof expandedArgs.command === 'string') {
          expandedArgs.command = expandedArgs.command + '; ' + extra;
        } else {
          expandedArgs.command = extra;
        }
      }
    }
    // Matching a filename/URL/path that appears in a tool BODY (content,
    // new_string, text, …) only makes sense for EXEC tools, where that text would
    // RUN. For read/write tools the body is data, not access — writing a doc that
    // merely mentions a secret-file pattern is not accessing one. So strip body
    // fields before extracting access targets; the command fields (what actually
    // executes) are always scanned via extractCommands.
    // (isExecTool already computed above for the referenced-file inlining gate.)
    // For NON-exec tools, only the explicit path/target fields are an "access" —
    // arbitrary text fields (a question, a description, a file body) are data, not
    // access, and must not be matched against filename/path/url rules. So scan an
    // ALLOWLIST of target fields only. Exec tools scan the full command instead.
    // Includes network/url-bearing fields (url, uri, …) so non-exec network
    // tools (Fetch/WebFetch) keep their access target — otherwise the url field
    // is stripped here, input.urls comes out empty, and urlConstraints DENY
    // rules never match (a fetch to a blocked host slips through).
    // Antigravity read/write tools carry the path in camelCase args (absolutePath,
    // targetFile, filePath → lowercased here). Without them, a non-exec agy read's
    // access target is stripped, input.paths/filenames come out empty, and
    // path/filename DENY rules (`*.env`, `*secrets/*`) never match on agy — the
    // read then falls through to DLP redaction instead of being blocked. Mirror of
    // TAMPER_PATH_FIELDS's agy names.
    const ACCESS_FIELDS = new Set(['file_path', 'path', 'target_file', 'notebook_path', 'filename', 'dest', 'destination', 'source', 'src', 'from', 'to', 'directory', 'dir', 'folder', 'url', 'urls', 'uri', 'href', 'link', 'endpoint', 'absolutepath', 'targetfile', 'filepath']);
    let accessArgs = expandedArgs;
    if (!isExecTool && expandedArgs && typeof expandedArgs === 'object') {
      accessArgs = {};
      for (const [k, v] of Object.entries(expandedArgs)) {
        if (ACCESS_FIELDS.has(k.toLowerCase())) accessArgs[k] = v;
      }
    }
    const input = {
      tool_name: toolName || '',
      permission: guessPermission(toolName),
      trust_level: 'TRUSTED',
      arguments: expandedArgs,
      paths: extractPaths(accessArgs, isExecTool),
      commands: extractCommands(expandedArgs),
      urls: extractUrls(accessArgs),
      filenames: extractFilenames(accessArgs),
    };
    // Defeat glob dodges (`cut staging.e*` in place of `staging.env`): resolve any
    // globbed file token in the command to its real path so filename/path rules
    // match it. Exec tools only — a non-exec read carries a literal path, not a glob.
    if (isExecTool) {
      for (const gp of expandCommandGlobs(expandedArgs, cwd)) {
        input.paths.push(gp);
        const bn = gp.split('/').pop();
        if (bn) input.filenames.push(bn);
      }
    }
    // A grep-style tool is a READ of every file under its root, and its
    // arguments say none of that: they carry the root and a query, never the
    // files whose contents come back. So the guard saw a search of a directory
    // no rule mentions, matched nothing, and allowed it — the rule held against
    // the read tool and was walked past by the search tool beside it.
    //
    // Measured on Antigravity: view_file on a denied path is refused, and
    // grep_search rooted at the workspace returns the same file's contents.
    //
    // Same move as the glob expansion above: resolve what the call will actually
    // reach so the rules already written can see it. Every bound fails OPEN.
    for (const sp of expandSearchRoots(toolName, expandedArgs, cwd)) {
      input.paths.push(sp);
      const bn = sp.split('/').pop();
      if (bn) input.filenames.push(bn);
    }
    if (process.env.SOLONGATE_DEBUG) {
    }
    const results = opaPolicy.evaluate(input);
    const decision = results && results[0] && results[0].result;
    if (!decision || !decision.effect) return null;

    // The generated Rego always has `default decision := DENY` (whitelist
    // semantics). We must re-apply the policy mode here so denylist policies
    // keep their default-ALLOW behavior, matching legacy evaluate():
    //   - denylist: default-allow → block ONLY when a DENY rule actually
    //     matched (matched_rule != null). Default DENY means "no rule matched".
    //   - whitelist: default-deny → block on any DENY (default or matched).
    // Routing per policy mode semantics:
    //
    //   DENYLIST (default-allow):
    //     DENY match  → BLACK (block)
    //     no match    → WHITE (default-allow, skip AI Judge — this IS the
    //                   semantics of denylist: "block these, allow the rest")
    //     REVIEW match → GRAY (only this explicit effect calls AI Judge)
    //
    //   WHITELIST (default-deny):
    //     ALLOW match → WHITE (skip AI Judge)
    //     DENY match  → BLACK
    //     REVIEW match → GRAY
    //     no match    → BLACK (default-deny)
    //
    // AI Judge runs ONLY when a rule explicitly says "this needs semantic
    // review" — never as a fallback for "I'm not sure". That keeps token cost
    // proportional to actual ambiguity and avoids running the model on every
    // routine call.
    const mode = policy.mode === 'whitelist' ? 'whitelist' : 'denylist';
    const matched = decision.matched_rule != null;
    const eff = decision.effect;
    if (mode === 'denylist') {
      if (eff === 'DENY' && matched) return '[SolonGate OPA] ' + (decision.reason || 'Blocked by policy');
      if (eff === 'REVIEW' && matched) return { white: false, reason: decision.reason, ruleId: decision.matched_rule };
      return { white: true, ruleId: matched ? decision.matched_rule : null };
    }
    // whitelist
    if (eff === 'DENY' && matched) return '[SolonGate OPA] ' + (decision.reason || 'Blocked by policy');
    if (eff === 'REVIEW' && matched) return { white: false, reason: decision.reason, ruleId: decision.matched_rule };
    if (eff === 'ALLOW' && matched) return { white: true, ruleId: decision.matched_rule };
    return '[SolonGate OPA] ' + (decision.reason || 'Blocked by policy: no ALLOW rule matched');
  } catch {
    return undefined; // any failure → fall back to legacy evaluator
  }
}

// ── Translator (input side) ──
// Normalize ANY client's raw hook payload into ONE canonical shape the whole
// guard reasons over: Claude's flat {tool_name,tool_input,session_id,cwd} and
// Antigravity's nested {toolCall:{name,args:{CommandLine,Cwd}},conversationId,
// workspacePaths} come out identical here. EVERY tool call passes through this
// before any check runs; the decision is emitted back per-client by blockTool/
// allowTool/rewriteTool (the output side of the translator). New client = extend
// only these two ends — the checks in between never see client-specific shapes.
// Codex sends every file edit as ONE tool call: tool_name "apply_patch" with
// tool_input { command: "*** Begin Patch\n*** Update File: src/a.ts\n…" }. The
// target paths live INSIDE that patch text, so without this every path-scoped
// rule (policy DENY, tamper, DLP) would see no path at all and a Codex
// edit to a protected file would sail through. Lift them into the canonical
// fields the rest of the guard already reads: file_path (first target) and an
// edits[] array of {file_path} (what extractTargetPaths walks for the rest).
function applyPatchTargets(patch) {
  const out = [];
  if (typeof patch !== 'string' || !patch.includes('*** ')) return out;
  const re = /^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s*(.+?)\s*$/gm;
  let m;
  while ((m = re.exec(patch))) if (m[1]) out.push(m[1]);
  // `*** Move to: <path>` renames the file named by the preceding Update File.
  const mv = /^\*\*\*\s+Move\s+to:\s*(.+?)\s*$/gm;
  while ((m = mv.exec(patch))) if (m[1]) out.push(m[1]);
  return out;
}

// Some clients hide their real targets inside free text instead of putting them
// in an argument. Codex does this with apply_patch: one call, every touched path
// living inside the patch body. Keyed on the patch TEXT rather than the tool
// name, so this runs for any client that adopts the same format. Without it, no
// path-scoped layer (policy, tamper, DLP) sees a path at all and an edit
// to a protected file passes unexamined. The body is left intact so DLP can
// still scan what is about to be written.
function liftFreeformPatchPaths(call) {
  const cmd = call.command;
  if (call.tool !== 'apply_patch' && !(typeof cmd === 'string' && cmd.startsWith('*** Begin Patch'))) return;
  const targets = applyPatchTargets(cmd);
  if (!targets.length) return;
  call.args = { ...call.args };
  if (!call.args.file_path) call.args.file_path = targets[0];
  if (!Array.isArray(call.args.edits)) call.args.edits = targets.map((f) => ({ file_path: f }));
}

// Translator, input side. Hands the raw payload to the adapter for whichever
// client is running, then applies the client-agnostic enrichment above. Returns
// the neutral CALL every layer below reasons over. Nothing past this point knows
// which client sent the call.
function normalizeToolCall(raw) {
  const parsed = CLIENT.parse(raw) || {};
  const tool = parsed.tool || '';
  const call = {
    client: AGENT_TYPE,
    // The client's own tool name, kept verbatim for logs and audit. Layers must
    // NOT branch on it: clients name the same capability differently (Bash /
    // run_command / shell). `permission` below is the neutral classification.
    tool,
    permission: guessPermission(tool),
    args: parsed.args || {},
    command: parsed.command ?? null,
    cwd: parsed.cwd || process.cwd(),
    sessionId: parsed.sessionId || '',
    response: parsed.response || {},
    raw,
  };
  liftFreeformPatchPaths(call);
  return call;
}

// ── Main ──
let input = '';
// Read the contents of files a tool call references, so the AI Judge can see a
// command HIDDEN inside a script/file (e.g. `bash deploy.sh`). Bounded: at most
// a few small text files. Returns { name: content }.
function readReferencedFiles(args, cwd) {
  const out = {};
  const MAX_FILES = 3, MAX_BYTES = 65536;
  const cands = new Set();
  // Only inline a file that is actually EXECUTED by an interpreter — `bash x.sh`,
  // `python x.py`, `source x`, `. x`. A file that is merely an argument (rm/cp/cat
  // x, or a read/write target) is NOT run, so its content must NOT be scanned —
  // otherwise deleting a file whose text mentions a blocked name would false-block.
  const INTERP = /^(?:bash|sh|zsh|ksh|dash|ash|python3?|node|deno|bun|ruby|perl|php|pwsh|powershell|source|\.)$/i;
  if (args && typeof args === 'object') {
    for (const f of ['command', 'cmd', 'script', 'shell', 'code']) {
      const v = args[f];
      if (typeof v !== 'string') continue;
      const toks = v.split(/[\s'"();|&<>]+/).filter(Boolean);
      for (let i = 0; i < toks.length - 1; i++) {
        if (!INTERP.test(toks[i])) continue;
        // The first non-flag token after the interpreter is the script it runs.
        let j = i + 1;
        while (j < toks.length && toks[j].startsWith('-')) j++;
        if (j < toks.length) cands.add(toks[j]);
      }
    }
  }
  let n = 0;
  for (const c of cands) {
    if (n >= MAX_FILES) break;
    try {
      const p = resolve(cwd || process.cwd(), c);
      if (!existsSync(p)) continue;
      const st = statSync(p);
      if (!st.isFile() || st.size > MAX_BYTES) continue;
      out[c] = readFileSync(p, 'utf-8').slice(0, MAX_BYTES);
      n++;
    } catch {}
  }
  return out;
}

// The payload was read at the top of this file, synchronously from fd 0, before
// the Go guard was offered the call — see SG_STDIN. It is reused rather than
// re-read for two reasons: fd 0 is already at EOF so a second read would return
// nothing, and the fallback only means anything if Node still holds what the
// binary was given.
//
// Reading fd 0 synchronously rather than through the process.stdin stream is
// itself deliberate. On Windows + Node 24, calling process.exit() from inside the
// stdin stream's 'end' callback aborts with `Assertion failed: !(handle->flags &
// UV_HANDLE_CLOSING), file src\win\async.c` — libuv double-closes the stdin pipe
// handle mid-teardown, the hook crashes before its exit code lands, and Claude
// Code treats the DENY as a non-blocking hook failure (so the block never
// applies). Reading fd 0 to EOF never creates that pipe handle, and the exit
// below no longer runs inside a stream callback, so the loop tears down cleanly.
if (!REFRESH_MODE) { input += SG_STDIN; }
;(async () => {
 // Safety backstop ONLY: the normal path exits by natural drain (~1ms after work
 // finishes). If the loop somehow fails to drain, force-exit — 8s is well past every
 // fetch timeout (≤3s) so the threadpool is idle and exit() can't hit the abort.
 try { setTimeout(() => { try { process.exit(process.exitCode || 0); } catch {} }, 8000).unref(); } catch {}
 try {
  // Background-refresh invocation has no tool call to evaluate — it already ran
  // refreshPolicyCache() at startup; do nothing on the (empty) stdin.
  if (REFRESH_MODE) return;
  // No policy selected => no enforcement. A plain launch (no SOLONGATE_AGENT_ID)
  // is intentionally unrestricted.
  if (process.env.SOLONGATE_DEBUG) {
  }
  // Cloud gate: the API key IS the policy selector — it identifies the project
  // and its active policy. No key → nothing to enforce → allow. (Air-gap gated
  // on SOLONGATE_AGENT_ID instead; here the key does that job.)
  if (!API_KEY) {
    allowTool();
    return;
  }
  // NOT `Date.now()`. Every `Date.now() - _evalStart` below becomes an
  // evaluation_time_ms in the audit log — the number the dashboard, the dataroom
  // and the TUI print as what this call paid to be guarded. Measured from here
  // it excluded Node's boot and this file's parse, which is most of the cost,
  // and reported ~1ms for a hook that was really taking tens. See SG_ORIGIN_MS.
  const _evalStart = SG_ORIGIN_MS;
  try {
    const raw = JSON.parse(input);

    // Debug: append guard invocation to a cwd-local log. Opt-in only — set
    // SOLONGATE_DEBUG=1 to enable. Off by default so it doesn't litter every
    // working directory with .solongate/.debug-guard-log.
    if (process.env.SOLONGATE_DEBUG) {
      try {
        const { appendFileSync: afs, mkdirSync: mds } = await import('node:fs');
        mds(resolve('.solongate'), { recursive: true });
        const debugLine = JSON.stringify({ ts: new Date().toISOString(), hook: 'guard', argv: process.argv.slice(2), tool_name: raw.tool_name || raw.toolName || raw.command, agent_id: AGENT_ID }) + '\n';
        afs(resolve('.solongate', '.debug-guard-log'), debugLine);
      } catch {}
    }

    // Capture the call's identity from the RAW payload (pre-normalization, so
    // the value matches what the PostToolUse audit hook will see) for the deny
    // flag. tool_use_id is the exact call on clients that send it (Codex always
    // does); the fingerprint covers the rest.
    CALL_ID = String(raw.tool_use_id || raw.toolUseId || raw.tool_call_id || '');
    try { CALL_FP = callFingerprint(JSON.stringify(raw.tool_input || raw.toolInput || raw.params || {})); } catch { CALL_FP = ''; }

    // Translator: every client's payload (Claude flat, Antigravity toolCall, …)
    // → one canonical shape. All checks below reason over `data` only.
    const call = normalizeToolCall(raw);
    const args = call.args;
    const toolName = call.tool;

    // Diagnostic: print the neutral CALL the translator produced. Feed the same
    // logical call from different clients with SOLONGATE_DEBUG=1 and this line
    // comes out identical for all of them — that identity IS the standardization.
    // Off unless explicitly enabled, so it never adds noise to a normal run.
    if (process.env.SOLONGATE_DEBUG) {
      try {
        process.stderr.write('[SolonGate CALL] ' + JSON.stringify({
          permission: call.permission, args: call.args, command: call.command,
          cwd: call.cwd, sessionId: call.sessionId,
        }) + '\n');
      } catch {}
    }

    // ── FAST tamper path (hook v40) ───────────────────────────────────────
    // Tamper protection is independent of the cloud policy, so decide it BEFORE
    // the slow policy resolution (cache read + WASM + background refresh). That
    // slow work made the earliest guard processes in a concurrent denial burst
    // exceed Claude Code's PreToolUse hook timeout and get SIGKILLed mid-write,
    // dropping the local log. Here we cheap-read the cache for selfProtect +
    // localLogs config and, on a tamper hit, log + block IMMEDIATELY — no WASM,
    // no refresh — so the process is fast and never killed. Falls through
    // untouched when there is no tamper hit.
    try {
      const _ak = (AGENT_ID || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
      const _cf = join(resolve(homedir(), '.solongate'), '.policy-cache-' + _ak + '.json');
      let _selfProt = true, _sec = null, _cacheOk = false;
      try {
        const _c = JSON.parse(readFileSync(_cf, 'utf-8'));
        _cacheOk = true;
        if (_c && typeof _c.selfProtect === 'boolean') _selfProt = _c.selfProtect;
        if (_c && _c.security !== undefined) _sec = _c.security;
      } catch {}
      // Only fast-path when we actually read the cache (so _sec is the real
      // localLogs config). On a cache miss, fall through to the full flow, which
      // resolves the policy properly and still blocks tamper.
      const _tr = (_cacheOk && _selfProt) ? tamperCheck(toolName, args) : null;
      // Egress DLP: block a transfer command that would upload a local secret file.
      const _er = (!_tr && _cacheOk) ? egressSecretCheck(args, _sec, call.cwd) : null;
      const _deny = _tr || _er;
      if (_deny) {
        const _logEntry = {
          tool: toolName, arguments: args,
          decision: 'DENY', reason: _deny,
          permission: guessPermission(toolName),
          source: `${AGENT_TYPE}-guard`,
          agent_id: AGENT_TYPE, agent_name: AGENT_NAME,
          session_id: call.sessionId,
          evaluation_time_ms: Date.now() - _evalStart,
        };
        try { writeLocalLog(_sec, { ts: new Date().toISOString(), ..._logEntry }); } catch {}
        try {
          if (!localLogsOnly(_sec)) postAuditDetached(_logEntry);
        } catch {}
        // Not on Codex: its block reason IS the hook's stderr (see the ROUTE
        // write at the end of the slow path for the full rationale).
        if (AGENT_TYPE !== 'codex') process.stderr.write(`[SolonGate ROUTE] BLACK (block)\n`);
        writeDenyFlag(toolName);
        blockTool(_deny); // throws SG_DONE — skips the slow policy path entirely
      }
    } catch (_e) { if (_e === SG_DONE) throw _e; /* else: fall through to full flow */ }

    // (self-protection + PI hook layers removed per project decision)

    // Load policy. Priority:
    //   1. Dashboard-managed policy (GET /api/v1/policies/active, cached 10s)
    //   2. Local policy.json next to cwd
    // The dashboard is the source of truth — local policy.json is only a
    // fallback for when the API is unreachable.
    const hookCwd = call.cwd || process.cwd();
    let policy;
    // Self-protection (tamper guard) defaults ON. The cloud per-project setting
    // can turn it off; delivered via /policies/active and cached alongside the
    // policy. Any failure to read it leaves protection ON (fail safe).
    let selfProtectEnabled = true;
    // Extra security layers (rate limit, egress, DLP block) delivered by the
    // cloud. Null = none configured. Fail open if unread.
    let securityCfg = null;
    // Cache keyed by agent_id so different agents in different terminals
    // don't share a stale cached policy.
    const agentKey = (AGENT_ID || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
    const policyCacheFile = join(resolve(homedir(), '.solongate'), '.policy-cache-' + agentKey + '.json');
    // Serve the cached policy without any network for TTL seconds. This is a HOT
    // PATH — it runs before every tool call. The original 3s TTL was slow not
    // because of the number but because it paired an 8s-timeout blocking fetch
    // with an every-3s cadence (and stacked behind the WASM fetch + a shared
    // rate limit). With those fixed — 2s timeout, WASM decoupled (24h/fp),
    // last-known-good stale fallback — a short TTL is cheap again: one small
    // ~200ms GET on a single call per window, others read the cache with no
    // network. So keep freshness tight (10s propagation) at negligible cost.
    const POLICY_TTL_MS = 10_000;
    try {
      let dashboardPolicy = null;
      // Last-known-good cache, kept even past the TTL so we can fall back on it
      // when the API is slow/unreachable instead of blocking or dropping the policy.
      let staleCache = null;
      // Whether the TTL has elapsed since our last refresh ATTEMPT. Gating the
      // fetch on the attempt timestamp (not on "do we already have a policy") is
      // what makes the back-off actually work when the endpoint is slow: a failed
      // or timed-out attempt still advances _ts, so we don't re-hit it — and eat
      // the full 2s timeout — on every single call. Before this, _ts only moved on
      // a SUCCESSFUL fetch, so a slow /policies/active meant ~2s on EVERY call and
      // the 10s TTL never engaged (the cache never looked "fresh").
      let refreshDue = true;
      try {
        if (existsSync(policyCacheFile)) {
          const cached = JSON.parse(readFileSync(policyCacheFile, 'utf-8'));
          // Kept whenever it parses, NOT only when it carries a policy. The
          // security layers (DLP, rate limit) are configured separately
          // from the policy, so gating the last-known-good on a policy existing
          // meant a project with DLP on and no policy lost DLP entirely the
          // moment this cache went past its 10s TTL — which is almost always,
          // since it only refreshes on activity.
          if (cached) staleCache = cached;
          if (cached && cached._ts && Date.now() - cached._ts < POLICY_TTL_MS) {
            refreshDue = false;
            if (cached.policy) dashboardPolicy = cached.policy;
            if (typeof cached.selfProtect === 'boolean') selfProtectEnabled = cached.selfProtect;
            if (cached.security !== undefined) { securityCfg = cached.security; writeLocalMarker(securityCfg); }
            if (cached.hookVersions) CLOUD_HOOK_VERSIONS = cached.hookVersions;
          }
        }
      } catch {}
      // Cache stale → DO NOT block the tool on the network. Serve the last-known-good
      // policy right now (or the local policy.json fallback below if there is none)
      // and kick off a DETACHED background refresh that rewrites the cache for the
      // NEXT call. Stale-while-revalidate: tool calls stay instant (~ms), yet a
      // policy change still lands within ~one call, because the fetch runs in
      // parallel instead of on the hot path.
      if (refreshDue) {
        if (!dashboardPolicy && staleCache) {
          dashboardPolicy = staleCache.policy;
          if (typeof staleCache.selfProtect === 'boolean') selfProtectEnabled = staleCache.selfProtect;
          if (staleCache.security !== undefined) securityCfg = staleCache.security;
          if (staleCache.hookVersions) CLOUD_HOOK_VERSIONS = staleCache.hookVersions;
        }
        // Debounce: at most one background refresh in flight per ~3s, so a burst of
        // stale calls (or several agents sharing this cache) doesn't spawn a swarm.
        if (API_KEY) {
          try {
            const lock = join(resolve(homedir(), '.solongate'), '.policy-refresh-' + agentKey + '.lock');
            const due = !existsSync(lock) || (Date.now() - statSync(lock).mtimeMs) > 3000;
            if (due) {
              try { writeFileSync(lock, String(Date.now())); } catch {}
              spawn(process.execPath, [process.argv[1], AGENT_TYPE, AGENT_NAME, '--sg-refresh-policy'], { detached: true, stdio: 'ignore', env: process.env }).unref();
            }
          } catch {}
        }
      }

      if (process.env.SOLONGATE_DEBUG) {
      }
      if (dashboardPolicy) {
        policy = dashboardPolicy;
      } else {
        // Fall back to ~/.solongate/policy.json (where the wizard writes the
        // default), then a per-project policy.json next to cwd.
        const candidates = [
          join(resolve(homedir(), '.solongate'), 'policy.json'),
          resolve(hookCwd, 'policy.json'),
        ];
        for (const p of candidates) {
          if (existsSync(p)) {
            try { policy = JSON.parse(readFileSync(p, 'utf-8')); break; } catch {}
          }
        }
      }
    } catch {
      // Couldn't load any policy — leave policy undefined; evaluate() returns null.
    }

    if (process.env.SOLONGATE_DEBUG) {
    }
    // Agent scoping
    {
      const scope = (policy && Array.isArray(policy.agents) && policy.agents.length > 0)
        ? policy.agents
        : ['*'];
      if (!scope.includes('*') && !scope.includes(AGENT_TYPE)) {
    allowTool();
        return;
      }
    }

    if (process.env.SOLONGATE_DEBUG) {
    }
    // Tamper / self-protection — runs before policy eval. ON by default; the
    // per-project cloud setting can disable it (fail safe: stays on if unread).
    let reason = selfProtectEnabled ? tamperCheck(toolName, args) : null;
    // Extra security layers run after tamper, before policy. Block reason wins
    // immediately (BLACK). Fail-open by design.
    if (!reason) reason = securityLayerCheck(toolName, args, securityCfg, agentKey);
    if (process.env.SOLONGATE_DEBUG) {
    }
    // OPA WASM is the SOLE policy engine. With no policy configured for this
    // agent we skip evaluation entirely (allow). With a policy present,
    // evaluateWithOpa returns a reason (DENY), null (ALLOW), or undefined when
    // the WASM bundle could not be obtained at all — in which case we fall back
    // to the policy mode's default (whitelist → fail closed, denylist → fail
    // open); see the branch below. (The legacy JS evaluate() below is retained
    // but no longer on the decision path — OPA decides everything.)
    // Cloud routing is BINARY — WHITE (allow) / BLACK (block). There is NO AI
    // Judge in the cloud (that is an air-gap-only feature), so there is no GRAY
    // "send to the judge" lane: the OPA policy alone decides. Tamper protection
    // and any DENY (incl. fail-closed) → BLACK; everything else → WHITE. A REVIEW
    // rule with no judge to escalate to is treated as allow under denylist.
    let opaRoute = 'white';
    if (reason) {
      opaRoute = 'black'; // hardcoded tamper protection blocked it
    } else if (policy && policy.rules) {
      const opaResult = await evaluateWithOpa(policy, args, toolName, hookCwd);
      if (opaResult === undefined) {
        // OPA produced no decision (no WASM bundle yet, runtime missing, fetch
        // error). This happens on COLD START — the first call(s) in a session
        // before the policy + WASM are cached. Don't leave an enforcement gap:
        // run the deterministic, WASM-free JS evaluator so DENY rules (e.g.
        // secret-file protection) and whitelist defaults apply IMMEDIATELY, from
        // the very first call. evaluate() implements both modes:
        //   - returns a deny reason  → block (DENY match, or whitelist no-match)
        //   - returns null           → allow (denylist default / whitelist match)
        // This closes the "worked, but late" window where a denylist policy used
        // to fail OPEN until WASM warmed up.
        const legacy = evaluate(policy, args, toolName);
        if (typeof legacy === 'string') {
          reason = legacy;
          opaRoute = 'black';
        } else {
          opaRoute = 'white';
        }
      } else if (typeof opaResult === 'string') {
        reason = opaResult; // explicit DENY
        opaRoute = 'black';
      } else {
        opaRoute = 'white'; // allow (rule match, default-allow, or review w/o judge)
      }
    }

    // Antigravity / Codex read redaction — runs LAST, only when the call is
    // otherwise ALLOWED (no tamper/security/policy DENY). Claude redacts a
    // secret in a read's OUTPUT via its PostToolUse audit; neither agy nor Codex
    // can rewrite tool OUTPUT (agy has no PostToolUse at all; Codex has one but
    // explicitly rejects an output rewrite from it), so for both we redact the
    // file into a temp copy and point the read at it BEFORE it runs — via
    // `overwrite` on agy, `updatedInput` on Codex.
    // It MUST come after policy eval: a file a DENY rule blocks (a `.env` filename
    // or `secrets/` path) must never be served — not even redacted. Putting this
    // before OPA (as it once was) let a redaction rewrite terminate the hook and
    // silently bypass the policy block. Fail-closed: a secret we can't redact
    // becomes a block.
    if (!reason && !CLIENT.redactsOutput && securityCfg && (securityCfg.dlpBlock || securityCfg.dlpRedact)) {
      const dlpCfg = securityCfg.dlpBlock || securityCfg.dlpRedact;
      const plan = dlpRedactReadPlan(toolName, args, dlpCfg, hookCwd);
      if (plan && plan.block) {
        reason = 'Security layer (DLP): reading a file that contains a secret is blocked. Blocked by SolonGate.';
        opaRoute = 'black';
      } else if (plan && plan.rewrite) {
        rewriteTool(plan.rewrite); // verdict first, update later
      }
    }

    // Diagnostic line for the terminal. NOT written on Codex: there the hook's
    // ENTIRE stderr becomes the block reason shown to the model (exit 2), so this
    // would prefix every denial with "[SolonGate ROUTE] BLACK (block)".
    if (AGENT_TYPE !== 'codex') process.stderr.write(`[SolonGate ROUTE] ${opaRoute.toUpperCase()} (${reason ? 'block' : 'allow'})\n`);

    // Hand the measured policy-eval time to the audit hook: PostToolUse logs the
    // ALLOW path and can't time the guard itself, so it reads this file back.
    // Keyed by tool + session so the audit hook can match THIS invocation even
    // when the tool itself runs for minutes (a bare timestamp TTL lost those).
    try {
      const _fd = projectFlagDir(); mkdirSync(_fd, { recursive: true });
      sweepLegacyFlagDir(); // every call, not just denials
      const _rec = { ms: Date.now() - _evalStart, ts: Date.now(), tool: toolName, session: call.sessionId };
      writeFileSync(join(_fd, '.last-eval'), JSON.stringify(_rec));
      // Also append to a short ring. When many tool calls run in PARALLEL they all
      // race on the single .last-eval above (overwrite / torn read → blank eval
      // time in the log). appendFileSync lines are atomic, so the PostToolUse
      // audit hook can recover a value by averaging the recent same-session
      // records — a parallel burst then shares one arithmetic-mean eval time.
      try {
        const ring = join(_fd, '.eval-ring.jsonl');
        appendFileSync(ring, JSON.stringify(_rec) + '\n');
        try { if (statSync(ring).size > 16384) writeFileSync(ring, readFileSync(ring, 'utf-8').split('\n').filter(Boolean).slice(-50).join('\n') + '\n'); } catch {}
      } catch {}
    } catch {}

    // Only log DENY decisions from guard hook.
    // ALLOW decisions are logged by the audit hook (PostToolUse) to avoid double-counting.
    if (reason) {
      if (true) {
        try {
          const logEntry = {
            tool: toolName, arguments: args,
            decision: 'DENY', reason,
            permission: guessPermission(toolName),
            source: `${AGENT_TYPE}-guard`,
            agent_id: AGENT_TYPE, agent_name: AGENT_NAME,
            session_id: call.sessionId,
            evaluation_time_ms: Date.now() - _evalStart,
          };
          writeLocalLog(securityCfg, { ts: new Date().toISOString(), ...logEntry });
          // PI hook layer removed — piResult fields no longer attached.
          // Local-only mode: keep the log on the user's machine, skip the cloud.
          if (!localLogsOnly(securityCfg)) postAuditDetached(logEntry);
        } catch {}
      }
      writeDenyFlag(toolName);
      // The verdict is emitted BEFORE the hook self-update, never after.
      // maybeSelfUpdate() fetches three hooks at up to 5s each, and the
      // whole process carries an 8s backstop that force-exits with
      // `process.exitCode || 0` — i.e. ALLOW. So a slow network on the update
      // path turned a decided DENY into a permitted call. Measured: 8043ms,
      // exit 0, on a call DLP had already refused. Updating is a background
      // nicety; it still runs on every allow, which is nearly every call.
      blockTool(reason);
    }
  } catch {}
  await maybeSelfUpdate();
  allowTool();
 } catch (e) {
  // SG_DONE is the normal terminator (exitCode already set); anything else is an
  // unexpected error — fail OPEN (exit 0) so a hook bug never wedges the agent.
  if (e !== SG_DONE) { process.exitCode = process.exitCode || 0; }
 }
})();

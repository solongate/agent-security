#!/usr/bin/env node
/**
 * The policy guard (PreToolUse) — the decision every tool call passes through.
 *
 * Installed globally (~/.claude/settings.json) it sees EVERY tool call from EVERY
 * session on the machine. Exit code 2 = BLOCK, exit code 0 = ALLOW.
 *
 * WHERE THE POLICY COMES FROM, in order:
 *
 *   1. ~/.solongate/policy.json — this machine's own file.
 *   2. policy.json beside the working directory, which may add RULES and nothing
 *      else: it lives in a repository the agent can write to, so `selfProtect`
 *      and `security` there are ignored — the thing being policed does not get
 *      to switch off the policing.
 *
 * There used to be a step above both: a service, when a credential named one,
 * cached for ten seconds and refreshed off the hot path. It is gone, and so is
 * everything that reached it. NEITHER FILE IS REQUIRED — with no policy at all
 * there is nothing to enforce and the call is allowed.
 *
 * The engine is the same whichever answered: OPA WASM, NIST SP 800-207 PDP,
 * fail-closed. Routing is binary — WHITE (allow) / BLACK (block). Nothing is
 * escalated to a model and there is no judge.
 *
 * Denials are recorded to disk, which is the only place they go. ALLOWs are
 * recorded by audit.mjs.
 *
 * There is a Go twin of all of this in packages/guard-go, deliberately identical,
 * because which of the two decides a call depends only on whether a machine has
 * the binary. The conformance suite in packages/proxy/test runs against both.
 *
 * Auto-installed by: npx @solongate/proxy init --global
 */
import { readFileSync, existsSync, statSync, readdirSync, writeFileSync, mkdirSync, chmodSync, renameSync, appendFileSync, rmSync, rmdirSync, openSync, readSync, closeSync, accessSync, constants } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { resolve, join, dirname, isAbsolute } from 'node:path';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';
// The decision engine, shared with the MCP proxy so a policy cannot mean one
// thing to a hook and another to the proxy. esbuild inlines this file.
import {
  evaluate,
  extractCommands,
  extractFilenames,
  extractPipelines,
  extractPaths,
  extractUrls,
  guessPermission,
  matchGlob,
  matchPathGlob,
  normalizeArgs,
  scanStrings,
} from './policy-eval.mjs';
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

// Bump on every change to this file. An installed hook is replaced by the
// INSTALLER, which is the only thing that writes one now: this hook used to fetch
// replacement hooks from a service and swap its own file, and there is no service
// to serve them. The number is still how `doctor` and the Settings panel say an
// installation is behind the package.
// 92 closes a disarm: this hook's own per-agent state — the policy cache above
// all — was writable through a path-taking tool, because matchPathGlob does not
// treat `*` as a wildcard after a `**`. See isProtectedPath.
//
// 91 collapsed a run of `*` in a glob before compiling it, and stat'd a file
// before the egress scan read it. Both are resource fixes on agent-supplied
// input: see dlpGlobToRe and DLP_MAX_FILE_BYTES.
//
// 99 RESTORES THE EGRESS CHECK, which had stopped running altogether. It lived
// inside a fast path that first read a policy CACHE and gave up when there was
// none, and nothing writes that cache any more -- so a `curl -d @creds.env
// https://...` uploading a file full of keys was allowed, with dlpBlock configured
// and working everywhere else. The Go guard blocked it, so the two disagreed about
// a secret leaving the machine. 99 also stops this hook reading a credential at
// all: two file reads leave the hot path of every tool call.
//
// This number is how a machine compares the hook it has with the one in a
// checkout, and a fix nobody picks up is not a fix.
const HOOK_VERSION = 99;

// SG_DIR_MODE is the mode for ~/.solongate.
//
// Owner-only, because the directory holds the credential and the policy cache.
// sgshared declares the same number on the Go side, and it has to be the same
// number: several programs create this ONE directory — this hook, the audit hook,
// the CLI, the guard binary — and mkdirSync and MkdirAll both apply a mode only
// when they CREATE, so the first one to run on a machine decides it for all of
// them. They disagreed, and this hook runs on every tool call, which made it the
// one most likely to get there first.
//
// Declared up here, above every use, because some of the code below runs during
// module initialisation — a `const` further down would be in its temporal dead
// zone for those paths.
const SG_DIR_MODE = 0o700;

// SG_FILE_MODE is the mode for what this hook writes there.
//
// Owner-only for the same reason, and the local audit log is the sharpest case:
// it records every command, path and URL the agent was told no about, which is a
// log of what somebody was working on. It was being created 0644 inside a 0755
// directory, so on a shared machine any other account could read it. Both sides
// matter — a tight file inside a listable directory still leaks the filenames.
const SG_FILE_MODE = 0o600;

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

// The one read of fd 0 in this process. Everything downstream uses this string.
//
// It used to be conditional. `guard.mjs <client> --sg-refresh-policy` was a second
// way to invoke this file — spawned detached by the installer, once per registered
// client, to fetch the policy so the first real tool call was judged against
// something instead of being waved through while the fetch ran. That invocation had
// no tool call on stdin, and its stdin was a pipe nobody closed, so reading it would
// have hung the hook forever; hence the branch. There is nothing to fetch and no
// cache to warm, both installers stopped spawning it, and a file needs no warming.
const SG_STDIN = (() => {
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

if (process.env.SOLONGATE_NO_GO_GUARD !== '1') {
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
// The policy a machine enforces when there is no service to ask.
//
// No credential is NOT an unconfigured machine. It is the ordinary deployment of
// this program: the policy lives in a file, nothing is fetched, and nothing
// leaves the device. So the file is a SOURCE here rather than a fallback for a
// failed fetch — it used to be reachable only after a fetch had failed, which
// meant a machine with no credential allowed every call while its policy sat on
// disk unread.
//
// Two spellings are accepted. /policies/active answers with an envelope, and a
// hand-written file is usually just the policy:
//
//   { "policy": {…}, "security": {…}, "selfProtect": true }   what the API sends
//   { "mode": "denylist", "rules": [ … ] }                     the policy alone
//
// The envelope is what makes the rate limit, the egress rules and the DLP
// scanner configurable with no service: they arrive in `security`, and a local
// machine had no way to set them at all.
//
// Order: this machine's own ~/.solongate/policy.json first, then a per-project file
// beside the working directory. Home first is deliberate — the project file
// lives inside a repository the agent can write to, so it can only apply where
// the person running this set nothing themselves.
function loadLocalPolicyFile(cwd) {
  for (const p of [
    join(resolve(homedir(), '.solongate'), 'policy.json'),
    cwd ? resolve(cwd, 'policy.json') : '',
  ]) {
    if (!p || !existsSync(p)) continue;
    try {
      const obj = JSON.parse(readFileSync(p, 'utf-8'));
      if (!obj || typeof obj !== 'object') continue;
      // Only THIS MACHINE's own file is trusted with more than rules. The
      // project file sits in a repository the agent can write to: letting it
      // carry selfProtect would be a one-line disarm of the tamper guard, and
      // letting it carry `security` would switch off the DLP scanner from inside
      // the checkout. It may add rules, and nothing else.
      const own = !cwd || p !== resolve(cwd, 'policy.json');
      // A policy DOCUMENT may carry `security` inside it. That is how the
      // service stores it (SecurityLayersIn reads exactly that), so it is the
      // shape a policy exported from one arrives in — and reading the envelope
      // only would have made a hand-copied policy's DLP config a silent no-op.
      // The envelope wins when both are present: it is the outer, more specific
      // statement.
      const inner = own && obj.policy && typeof obj.policy === 'object' ? obj.policy.security : undefined;
      if (obj.policy && typeof obj.policy === 'object') {
        return {
          policy: obj.policy,
          security: own && obj.security !== undefined ? obj.security : inner,
          selfProtect: own && typeof obj.selfProtect === 'boolean' ? obj.selfProtect : undefined,
          path: p,
        };
      }
      return {
        policy: obj,
        security: own && obj.security !== undefined ? obj.security : undefined,
        selfProtect: undefined,
        path: p,
      };
    } catch { /* an unreadable file is not a reason to stop looking at the next */ }
  }
  return null;
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
      mkdirSync(resolve(homedir(), '.solongate'), { recursive: true, mode: SG_DIR_MODE });
      writeFileSync(resolve(homedir(), '.solongate', '.local-logs-invalid-path'),
        JSON.stringify({ configured: dir, fallback, ts: Date.now() }));
    } catch { /* ignore */ }
  }
  return fallback;
}

// Local log storage (opt-in): write solongate-audit.jsonl inside the user's
// chosen FOLDER. The audit hook does the ALLOW path; the guard does DENY (a
// blocked call never reaches PostToolUse). `security` is the resolved config.
// accountMark lived here: a 16-character hash prefix of the key, stamped onto every
// local log line as `acct`. The machine-local log is one file, and after pairing a
// different account the viewers presented the previous one's calls as yours — so a
// reader could keep its own lines without deleting anybody's history.
//
// There is one account's worth of calls on a machine now, and it is not an account:
// nothing pairs, nothing reads `acct`, and the only thing left that wanted a
// credential was this. Its removal is what lets the guard stop reading a credential
// file on the hot path of every tool call.

function writeLocalLog(security, entry) {
  try {
    const l = security && security.localLogs;
    // No usable folder in the resolved config. The answer can still be "local is
    // on" from the persisted marker alone, i.e. WITHOUT a resolved config (empty
    // or cold policy cache, or a refresh that failed while the key was being
    // rotated) — in which case keep the copy in the per-device default folder
    // rather than dropping it.
    if (!l || typeof l.path !== 'string' || !l.path.trim()) {
      // No folder named, so the per-device default. RECORDING IS NOT OPTIONAL:
      // this used to return early when the configuration said local logging was
      // off, which made sense while there was a service to POST to instead. With
      // that gone, returning here loses the record entirely — the only thing the
      // setting can still choose is WHERE.
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

// NO CREDENTIAL IS READ HERE ANY MORE, and two file reads leave the hot path of
// every tool call with it.
//
// What stood here was the resolution of an API key, from three places in a
// deliberate order — the environment, then ~/.solongate/cloud-guard.json (written by
// the installer, absolute because a global hook runs from an arbitrary cwd), then a
// project-local .env. The order mattered: .env used to win, and a forgotten key in
// the folder an agent happened to start in would shadow the paired credential, so
// every call from that directory logged nothing while the same agent one folder over
// logged fine — no symptom, because enforcement never needed the network. There was
// an isRealKey filter too, so a sample `sg_live_your_key_here` could not shadow a
// working key and fail every call closed.
//
// All of it existed to answer requests that are gone. The last thing holding on was
// accountMark, which hashed the key into a `acct` stamp on each local log line so a
// machine paired to two accounts could tell whose calls were whose. There are no
// accounts, and nothing read the stamp.
//
// The cost was not only the code: loadEnvKey and loadGlobalCloudConfig ran a stat
// and a read each, on every tool call, before a single rule was evaluated.

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
        // The mode on appendFileSync applies only when it CREATES the file, so a
        // log this hook already wrote 0644 would keep it forever. Narrowed
        // afterwards as well. This runs in the DETACHED writer, never on the hot
        // path, so the extra syscall costs the tool call nothing.
        const _narrow = (f) => { try { chmodSync(f, SG_FILE_MODE); } catch {} };
        try {
          mkdirSync(_dir, { recursive: true, mode: SG_DIR_MODE });
          const _f = join(_dir, 'solongate-audit.jsonl');
          appendFileSync(_f, _pl.line, { mode: SG_FILE_MODE });
          _narrow(_f);
        } catch {
          const _fb = join(resolve(homedir(), '.solongate'), 'local-logs');
          try { mkdirSync(_fb, { recursive: true, mode: SG_DIR_MODE }); } catch {}
          try {
            const _f = join(_fb, 'solongate-audit.jsonl');
            appendFileSync(_f, _pl.line, { mode: SG_FILE_MODE });
            _narrow(_f);
          } catch {}
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

// Terminate the hook WITHOUT forcing process.exit().
//
// The reason was a fetch: on Windows + Node 24, process.exit() right after one — the
// audit POST — aborted with `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING),
// file src\win\async.c`, because the fetch's DNS and socket teardown was still
// settling in libuv's threadpool and exit() double-closed the loop's async handle.
// The abort REPLACED exit code 2, so Claude Code saw a non-blocking hook failure and
// ran the tool anyway: the guard computed DENY and never blocked.
//
// There is no fetch left in this hook. The drain stays anyway, and not out of
// caution: setting process.exitCode and letting the loop end on its own is what makes
// the LATCH possible, and the latch is doing the real work here. It preserves the
// FIRST code, so a later allowTool() reached on a fall-through path cannot overwrite a
// block — which is a correctness property about the decision, not about libuv.
// SG_DONE unwinds the stack; the unref'd backstop force-exits only if a handle is
// stuck.
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
// Terminate WITHOUT ever calling process.exit() on the hot path — see SG_DONE above
// for the Windows abort this began as, and for why the latch is the part that still
// matters now that no request is ever in flight. The unref'd backstop armed at the top
// of the handler is the only place exit() may run.
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
  // Anything in ~/.solongate whose name the command side already protects.
  //
  // THE GLOBS ABOVE DID NOT COVER THE PER-AGENT FILES HERE, and the reason is a
  // difference between this matchPathGlob and the Go one it is supposed to match:
  //
  //   here  a pattern containing `**` is split on it, and each remaining piece is
  //         substring-tested against the path — so the `*` in the per-agent entry
  //         stays a literal asterisk, and no real filename contains one.
  //   Go    MatchPathGlob compiles the pattern to a regex, where that `*` is a
  //         real wildcard and the file matches.
  //
  // So this hook was reachable by PATH where the binary was not, and a machine
  // gets whichever one it has. Deleting the policy cache with a shell command was
  // refused on both; a Write tool aimed at the same path went through here, and
  // every coding agent has one. Overwriting that file with `{}` leaves the guard
  // with no policy to apply, so the next call is allowed — and the refresh that
  // would repair it is debounced for three seconds, so it repeats. Measured:
  // Write, Edit and Read all allowed before this, all refused after.
  //
  // Fixed by basename rather than by touching matchPathGlob, which the policy
  // layer also uses: changing how a `*` behaves there would change what customer
  // rules match, which is not a thing to do from a tamper fix.
  //
  // Scoped to the directory on purpose. The names below are matched as PREFIXES,
  // and `policy.json` is a name somebody's own project may well use — protecting
  // it everywhere would block a file that has nothing to do with this product.
  if (/(^|\/)\.solongate\//.test(np)) {
    const base = np.slice(np.lastIndexOf('/') + 1);
    for (const b of TAMPER_BASENAMES) {
      if (base.startsWith(b.toLowerCase())) return b;
    }
  }
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

  // Kept in step with packages/guard-go/dlp.go, name for name and
  // expression for expression. The two lists had drifted to 14 here
  // against 74 there, and a name this list does not carry silently stops
  // being enforced on every machine that runs the hook rather than the
  // binary — which is every machine by default. dlp-parity.mjs holds them
  // together now.
  { name: 'Google API key', re: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'Slack webhook', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/_+-]{40,}/ },
  { name: 'Twilio account SID', re: /AC[0-9a-fA-F]{32}/ },
  { name: 'Mailgun key', re: /key-[0-9a-f]{32}/ },
  { name: 'Mailchimp key', re: /[0-9a-f]{32}-us[0-9]{1,2}/ },
  { name: 'DigitalOcean token', re: /dop_v1_[0-9a-f]{64}/ },
  { name: 'Databricks token', re: /dapi[0-9a-f]{32}/ },
  { name: 'Shopify token', re: /shp(at|ca|pa|ss)_[0-9a-fA-F]{32}/ },
  { name: 'Square token', re: /sq0(atp|csp)-[0-9A-Za-z_-]{22,43}/ },
  { name: 'Telegram bot token', re: /[0-9]{8,10}:AA[0-9A-Za-z_-]{33}/ },
  { name: 'Postman key', re: /PMAK-[0-9a-f]{24}-[0-9a-f]{34}/ },
  { name: 'Doppler token', re: /dp\.(pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}/ },
  { name: 'HashiCorp Vault token', re: /hvs\.[A-Za-z0-9_-]{24,}/ },
  { name: 'New Relic key', re: /NRAK-[A-Z0-9]{27}/ },
  { name: 'Grafana token', re: /glc_[A-Za-z0-9+\/=_-]{32,}/ },
  { name: 'Razorpay key', re: /rzp_(live|test)_[0-9A-Za-z]{14}/ },
  { name: 'Linear key', re: /lin_api_[0-9A-Za-z]{40,}/ },
  { name: 'Figma token', re: /figd_[0-9A-Za-z_-]{40,}/ },
  { name: 'Atlassian token', re: /ATATT3[0-9A-Za-z_=.-]{20,}/ },
  { name: 'Google OAuth token', re: /ya29\.[0-9A-Za-z_-]{50,}/ },
  { name: 'Google OAuth refresh', re: /1\/\/0[0-9A-Za-z_-]{30,}/ },
  { name: 'Alibaba access key', re: /LTAI[0-9A-Za-z]{20}/ },
  { name: 'Tencent secret id', re: /AKID[0-9A-Za-z]{13,40}/ },
  { name: 'Hugging Face token', re: /hf_[0-9A-Za-z]{34,}/ },
  { name: 'Replicate token', re: /r8_[0-9A-Za-z]{37,}/ },
  { name: 'Groq key', re: /gsk_[0-9A-Za-z]{48,}/ },
  { name: 'OpenRouter key', re: /sk-or-v1-[0-9a-f]{64}/ },
  { name: 'Perplexity key', re: /pplx-[0-9A-Za-z]{40,}/ },
  { name: 'xAI key', re: /xai-[0-9A-Za-z]{40,}/ },
  { name: 'LangSmith key', re: /lsv2_(pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}/ },
  { name: 'Stripe webhook secret', re: /whsec_[0-9A-Za-z]{32,}/ },
  { name: 'Plaid token', re: /access-(sandbox|development|production)-[0-9a-f-]{36}/ },
  { name: 'Braintree token', re: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/ },
  { name: 'Discord bot token', re: /[MNO][0-9A-Za-z_-]{23}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27}/ },
  { name: 'Discord webhook', re: /https:\/\/discord(app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[0-9A-Za-z_-]{60,}/ },
  { name: 'Slack app token', re: /xapp-[0-9]-[0-9A-Za-z]+-[0-9]+-[0-9a-f]+/ },
  { name: 'Sentry DSN', re: /https:\/\/[0-9a-f]{32}@[0-9a-z.-]+sentry\.io\/[0-9]+/ },
  { name: 'Supabase token', re: /sbp_[0-9a-f]{40}/ },
  { name: 'PlanetScale token', re: /pscale_tkn_[0-9A-Za-z._-]{32,}/ },
  { name: 'PlanetScale password', re: /pscale_pw_[0-9A-Za-z._-]{32,}/ },
  { name: 'Airtable token', re: /pat[0-9A-Za-z]{14}\.[0-9a-f]{64}/ },
  { name: 'Cloudinary URL', re: /cloudinary:\/\/[0-9]{12,}:[0-9A-Za-z_-]{20,}@[0-9a-z-]+/ },
  { name: 'MongoDB SRV URI', re: /mongodb\+srv:\/\/[^\s:@]+:[^\s:@]+@[0-9a-z.-]+/ },
  { name: 'Terraform Cloud token', re: /[0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z_-]{60,}/ },
  { name: 'PyPI token', re: /pypi-AgEIcHlwaS[0-9A-Za-z_-]{50,}/ },
  { name: 'RubyGems key', re: /rubygems_[0-9a-f]{48}/ },
  { name: 'NuGet key', re: /oy2[a-z0-9]{43}/ },
  { name: 'Docker Hub token', re: /dckr_pat_[0-9A-Za-z_-]{27,}/ },
  { name: 'Notion token', re: /ntn_[0-9A-Za-z]{40,}/ },
  { name: 'Dropbox token', re: /sl\.[0-9A-Za-z_-]{130,}/ },
  { name: 'Sentry auth token', re: /sntrys_[0-9A-Za-z_=+\/-]{40,}/ },
  { name: 'Contentful token', re: /CFPAT-[0-9A-Za-z_-]{40,}/ },
  { name: 'Typeform token', re: /tfp_[0-9A-Za-z_-]{40,}/ },
  { name: 'Pinecone key', re: /pcsk_[0-9A-Za-z_-]{40,}/ },
  { name: 'WooCommerce key', re: /c[ks]_[0-9a-f]{40}/ },
  { name: 'PostHog key', re: /ph[cs]_[0-9A-Za-z]{40,}/ },
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

// DLP_MAX_FILE_BYTES is the ceiling on any file this hook opens to scan.
//
// Every one of those paths comes from the AGENT — a file it asked to read, or one
// it named in a transfer command — so the size is the agent's choice and the
// ceiling is what keeps it from being this process's memory footprint. Scanning
// also builds de-obfuscated VIEWS of the text, so the peak is a multiple of the
// file.
//
// The number was already written three times as a literal and missing from a
// fourth place that needed it; it lives here now so the four cannot drift.
// Mirrors dlpMaxFileBytes in the Go guard.
const DLP_MAX_FILE_BYTES = 1048576;

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
    // PIPELINES, not commands. extractCommands splits on `|` too, which is right for
    // a policy rule and wrong here: `cat creds.env | curl -d @- https://…` split into
    // a half with no transfer command and a half whose only file is `-`, so a secret
    // piped into an upload was seen by neither. Both implementations had it.
    for (const cmd of extractPipelines(args)) {
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
      // POSITIONAL sources, for the transfers that take them: `scp creds.env
      // user@host:/tmp/x` names its file with no flag in front of it, so none of the
      // regexes above saw it and the commonest way to copy a file off a machine went
      // unchecked. Every token that could be a path is a candidate; what decides is
      // still the content scan below, and a token that is not a file fails the stat.
      if (/\b(scp|rsync|sftp)\b/.test(lc)) {
        for (const tok of c.split(/\s+/).slice(1)) {
          if (!tok || tok.startsWith('-')) continue;      // a flag
          if (/^[\w.-]*@?[\w.-]+:/.test(tok)) continue;    // user@host:path — the DESTINATION
          if (/^https?:\/\//.test(tok)) continue;
          files.add(tok.replace(/^@/, ''));
        }
      }
      for (let f of files) {
        if (f.startsWith('~')) f = homedir() + f.slice(1);
        let abs; try { abs = isAbsolute(f) ? f : resolve(base, f); } catch { continue; }
        let content = null;
        // STAT BEFORE READ, and skip anything over the scan ceiling.
        //
        // The path is one the AGENT put in a transfer command, so its size is the
        // agent's choice. Reading it whole meant `curl -T big.bin` made this hook
        // allocate the whole file — and then dlpScan builds de-obfuscated VIEWS of
        // it, so the peak is a multiple of that. The guard runs before every tool
        // call and is fail-closed, so an out-of-memory kill here is a stalled
        // agent rather than a missed scan.
        //
        // One megabyte is not a new rule: it is DLP_MAX_FILE_BYTES, already the
        // ceiling on the read-redaction path and on dlpReadCheck. Only this one
        // spot was missing it. The trade is explicit — a secret in a file over the
        // ceiling is not caught HERE — and it is the trade the other two paths
        // already made, which is the reason to make it the same rather than
        // inventing a second answer.
        try {
          const st = statSync(abs);
          if (!st.isFile() || st.size > DLP_MAX_FILE_BYTES) continue;
        } catch { continue; }
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
      try { const st = statSync(abs); if (!st.isFile() || st.size > DLP_MAX_FILE_BYTES) return 'SKIP'; content = readFileSync(abs, 'utf-8'); } catch { return 'SKIP'; }
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
      try { const st = statSync(abs); if (!st.isFile() || st.size > DLP_MAX_FILE_BYTES) continue; content = readFileSync(abs, 'utf-8'); } catch { continue; }
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
      // A DENIAL NAMES WHAT A PERSON CAN CHANGE. This said "check your dashboard for
      // details", which on this build is an instruction to go and look at nothing —
      // and the agent repeats it to whoever is reading, so the one message that has to
      // be actionable sent them somewhere that does not exist. The file is the whole
      // configuration, and it is the same file in every message here.
      if (hit) return 'Security layer (DLP): blocked - arguments contain a ' + hit +
        '. Blocked by SolonGate (DLP). Edit ~/.solongate/policy.json to change what is refused.';
    }
    if (cfg.rateLimit) {
      const hit = rateLimitCheck(agentKey, cfg.rateLimit);
      if (hit) {
        return 'Security layer (rate limit): exceeded ' + hit.limit + ' calls/' + hit.window +
          ' for this agent. Blocked by SolonGate (rate limit). Edit ~/.solongate/policy.json to review or adjust it.';
      }
    }
  } catch { /* fail open */ }
  return null;
}

// ── Policy Evaluation ──





// ── OPA IS OUT OF THE DECISION PATH ──
//
// It read a bundle a SERVICE compiled, and there is no service to compile one.
// What decided when a bundle could not be obtained — which was every cold start,
// every air-gapped install and now every call — is hooks/policy-eval.mjs, shared
// with the MCP proxy so a policy cannot mean one thing to a hook and another to
// the proxy.
//
// The bundle reader below stays: it is pure, it is tested, and reading a bundle
// somebody supplies is a smaller step to take later than writing one again.

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

// Lazily load the opa-wasm runtime. Returns the loadPolicy fn or null if the
// package isn't installed in this environment (typical for air-gapped hooks).
let _loadPolicyFn = null;
let _loadPolicyTried = false;

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
input += SG_STDIN;
;(async () => {
 // Safety backstop ONLY: the normal path exits by natural drain (~1ms after work
 // finishes). If the loop somehow fails to drain, force-exit — 8s is well past every
 // fetch timeout (≤3s) so the threadpool is idle and exit() can't hit the abort.
 try { setTimeout(() => { try { process.exit(process.exitCode || 0); } catch {} }, 8000).unref(); } catch {}
 try {
  // THERE IS NO CREDENTIAL GATE HERE, and its absence is the point.
  //
  // This used to be `if (!API_KEY) { allowTool(); return; }` — the key was the
  // whole test, on the reasoning that the key selects the project and therefore
  // the policy. That reasoning holds for a machine that has a service to ask. It
  // makes the guard a NO-OP on every machine that does not, which is how this
  // program is ordinarily run: the policy is a file, and it was never read.
  //
  // Nothing needs to be allowed early for that case anyway. With no policy
  // resolved, evaluate() returns null and the call falls through to allowTool()
  // at the end, and with no key the refresh spawn and the audit POST are both
  // skipped where they are written. What the early return also skipped was the
  // tamper guard, so a machine with no credential could not protect its own
  // state — and that state is exactly what a local policy is kept in.
  if (process.env.SOLONGATE_DEBUG) {
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

    // THE FAST TAMPER PATH IS GONE, and removing it fixes an enforcement hole.
    //
    // It existed for a real reason: the slow path below used to mean a cache read, an
    // OPA WASM instantiation and a detached background refresh, and doing all that
    // before deciding a tamper block made the earliest guard processes in a
    // concurrent denial burst exceed Claude Code's PreToolUse timeout and get
    // SIGKILLed partway through writing their log. So tamper — which never depended
    // on the policy — was decided first, from a cheap read of the policy CACHE.
    //
    // Two things changed. The slow path is no longer slow: no WASM, no refresh, one
    // file read and a deterministic evaluator. And NOTHING WRITES THE CACHE, so the
    // cheap read always missed — which mattered far more than the speed, because the
    // egress check was gated on it:
    //
    //     const _er = (!_tr && _cacheOk) ? egressSecretCheck(args, _sec, call.cwd) : null;
    //
    // _cacheOk was false on every call, so egressSecretCheck NEVER RAN. A `curl -d
    // @creds.env https://…` that uploads a file holding an AWS key was allowed, with
    // dlpBlock configured and working for every other surface. The Go twin ran the
    // same check off the policy file and blocked it — the two disagreed about a
    // secret leaving the machine, which is the worst place for them to disagree.
    //
    // Egress now runs below, from the file, in the Go guard's order: tamper, then
    // egress, then the layers, then the policy.

    // (self-protection + PI hook layers removed per project decision)

    // Load policy. In order:
    //   1. a service, when one is configured (GET /api/v1/policies/active, ~10s)
    //   2. ~/.solongate/policy.json, this machine's own file
    //   3. policy.json beside cwd, rules only
    //
    // A configured service outranks the file, because on a machine that has one
    // the file is how somebody would work around it. The file is NOT a fallback
    // for a failed fetch, though — it used to be reachable only that way, which
    // made a machine with no service enforce nothing at all.
    const hookCwd = call.cwd || process.cwd();
    let policy;
    // Self-protection (tamper guard) defaults ON. The cloud per-project setting
    // can turn it off; delivered via /policies/active and cached alongside the
    // policy. Any failure to read it leaves protection ON (fail safe).
    let selfProtectEnabled = true;
    // Extra security layers (rate limit, egress, DLP block) delivered by the
    // cloud. Null = none configured. Fail open if unread.
    let securityCfg = null;
    // agentKey names this agent's own rate-limit counter. It used to name a POLICY
    // CACHE too — a service's answer kept close at hand with a 10s TTL, a
    // last-known-good fallback, a detached refresh and a debounce lock in front of
    // it. Nothing writes that cache now, so every read of it missed and every
    // branch below it stood in front of the one source there is.
    const agentKey = (AGENT_ID || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
    try {
      {
        const local = loadLocalPolicyFile(hookCwd);
        if (local) {
          policy = local.policy;
          // The layers and the tamper flag travel with the policy, and this file is
          // the only thing that carries them now. `undefined` means the file said
          // nothing, which is not the same as saying off.
          if (local.security !== undefined) securityCfg = local.security;
          if (local.selfProtect !== undefined) selfProtectEnabled = local.selfProtect;
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
    // Tamper / self-protection — runs before policy eval. ON by default; the file
    // can turn it off (fail safe: stays on if the file is silent or unreadable).
    let reason = selfProtectEnabled ? tamperCheck(toolName, args) : null;
    // A secret leaving the machine in the ARGUMENTS of a call — as opposed to one
    // read out of a file, which is the redaction plan's job. Second, exactly as in
    // guard-go/main.go: it is the check with the narrowest trigger (a transfer
    // command with an outward target) and the heaviest consequence.
    if (!reason) reason = egressSecretCheck(args, securityCfg, call.cwd);
    // Extra security layers run after tamper and egress, before policy. A block
    // reason wins immediately (BLACK). Fail-open by design.
    if (!reason) reason = securityLayerCheck(toolName, args, securityCfg, agentKey);
    if (process.env.SOLONGATE_DEBUG) {
    }
    // ROUTING IS BINARY — WHITE (allow) / BLACK (block). Nothing is escalated to a
    // model and there is no judge, so a REVIEW rule reads as allow under denylist.
    //
    // The decision is hooks/policy-eval.mjs, shared with the MCP proxy. It used to
    // be OPA WASM with this as the cold-start fallback — "run the deterministic,
    // WASM-free JS evaluator so DENY rules and whitelist defaults apply
    // IMMEDIATELY, from the very first call" — and the bundle came from a service.
    // With no service there is no bundle, on every call rather than only the first.
    let opaRoute = 'white';
    if (reason) {
      opaRoute = 'black'; // hardcoded tamper protection blocked it
    } else if (policy && policy.rules) {
      const verdict = evaluate(policy, args, toolName);
      if (typeof verdict === 'string') {
        reason = verdict;
        opaRoute = 'black';
      } else {
        opaRoute = 'white';
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
        } catch {}
      }
      writeDenyFlag(toolName);
      // The verdict used to be emitted before a hook self-update, and the reason
      // is worth keeping even though the update is gone: that update fetched three
      // hooks at up to 5s each, and this process carries an 8s backstop that
      // force-exits with `process.exitCode || 0` — i.e. ALLOW. A slow network on
      // it turned a decided DENY into a permitted call. Measured at 8043ms, exit
      // 0, on a call DLP had already refused. Nothing slow may run before a
      // verdict is out.
      blockTool(reason);
    }
  } catch {}
  allowTool();
 } catch (e) {
  // SG_DONE is the normal terminator (exitCode already set); anything else is an
  // unexpected error — fail OPEN (exit 0) so a hook bug never wedges the agent.
  if (e !== SG_DONE) { process.exitCode = process.exitCode || 0; }
 }
})();

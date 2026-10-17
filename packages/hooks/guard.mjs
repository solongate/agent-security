#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

import { readFileSync, existsSync, statSync, readdirSync, writeFileSync, mkdirSync, chmodSync, renameSync, appendFileSync, rmSync, rmdirSync, openSync, readSync, closeSync, accessSync, constants } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { resolve, join, dirname, isAbsolute, normalize } from 'node:path';
import { homedir } from 'node:os';
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
    if (left.length === 0) { try { rmdirSync(dir); } catch {  } }
  } catch {  }
}

import { createHash, randomBytes } from 'node:crypto';

import { DLP_PATTERN_NAMES, dlpGlobToRe, dlpPatterns } from './dlp.mjs';
const HOOK_VERSION = 113;

const SG_DIR_MODE = 0o700;

const SG_FILE_MODE = 0o600;


const SG_STDIN = (() => {
  try { return readFileSync(0, 'utf-8'); } catch { return ''; }
})();

const SG_ORIGIN_MS = (() => {
  try { return Math.round(performance.timeOrigin); } catch { return Date.now(); }
})();

function sgGuardCandidates() {
  const out = [];
  if (process.env.SOLONGATE_GUARD_BIN) out.push(process.env.SOLONGATE_GUARD_BIN);
  const exe = process.platform === 'win32' ? 'solongate-guard.exe' : 'solongate-guard';
  out.push(resolve(homedir(), '.solongate', 'bin', exe));
  return out;
}

function sgTryGoGuard() {
  for (const bin of sgGuardCandidates()) {
    try {
      if (!existsSync(bin)) continue;
      if (process.platform !== 'win32') accessSync(bin, constants.X_OK);
    } catch { continue; }

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
        env: { ...process.env, SOLONGATE_HOOK_ORIGIN_MS: String(SG_ORIGIN_MS) },
        timeout: 10000,
      });
    } catch { return; }

    if (!r || r.error || r.signal) return;
    const status = r.status;
    const stdout = r.stdout || '';
    if (status !== 0 && status !== 2) return;
    if (status === 2 && stdout.trim() === '') return;

    try {
      if (stdout) process.stdout.write(stdout);
      if (r.stderr) process.stderr.write(r.stderr);
    } catch {
      return;
    }
    process.exit(status);
  }
}

if (process.env.SOLONGATE_NO_GO_GUARD !== '1') {
  try { sgTryGoGuard(); } catch {}
}

function loadLocalPolicyFile(cwd) {
  for (const p of [
    join(resolve(homedir(), '.solongate'), 'policy.json'),
    cwd ? resolve(cwd, 'policy.json') : '',
  ]) {
    if (!p || !existsSync(p)) continue;
    try {
      const obj = JSON.parse(readFileSync(p, 'utf-8'));
      if (!obj || typeof obj !== 'object') continue;
      const own = !cwd || p !== resolve(cwd, 'policy.json');
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
    } catch {  }
  }
  return null;
}

let _invalidPathNoted = false;
function resolveLocalLogDir(rawPath) {
  const dir = String(rawPath || '').trim().replace(/[\\/]+$/, '');
  if (!dir) return null;
  if (isAbsolute(dir)) return dir;
  const fallback = resolve(homedir(), '.solongate', 'local-logs');
  if (!_invalidPathNoted) {
    _invalidPathNoted = true;
    try {
      mkdirSync(resolve(homedir(), '.solongate'), { recursive: true, mode: SG_DIR_MODE });
      writeFileSync(resolve(homedir(), '.solongate', '.local-logs-invalid-path'),
        JSON.stringify({ configured: dir, fallback, ts: Date.now() }));
    } catch {  }
  }
  return fallback;
}


function writeLocalLog(security, entry) {
  try {
    const l = security && security.localLogs;
    if (!l || typeof l.path !== 'string' || !l.path.trim()) {
      const fallbackDir = resolve(homedir(), '.solongate', 'local-logs');
      const fallbackLine = JSON.stringify(entry) + '\n';
      const fallbackPayload = Buffer.from(JSON.stringify({ dir: fallbackDir, line: fallbackLine }), 'utf-8').toString('base64');
      spawn(process.execPath, [process.argv[1], '--sg-log-write', fallbackPayload], { detached: true, stdio: 'ignore' }).unref();
      return;
    }
    let dir = String(l.path).trim().replace(/[\\/]+$/, '');
    if (!dir) return;
    if (!isAbsolute(dir)) dir = resolve(homedir(), '.solongate', 'local-logs');
    const line = JSON.stringify(entry) + '\n';
    const payload = Buffer.from(JSON.stringify({ dir, line }), 'utf-8').toString('base64');
    spawn(process.execPath, [process.argv[1], '--sg-log-write', payload], { detached: true, stdio: 'ignore' }).unref();
  } catch {  }
}

const MAX_FILE_READ = 1024 * 1024;
function safeReadFileSync(filePath, encoding = 'utf-8') {
  try {
    const stat = statSync(filePath);
    if (stat.size > MAX_FILE_READ) return '';
    return readFileSync(filePath, encoding);
  } catch { return ''; }
}


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

const AGENT_TYPE = process.argv[2] || 'claude-code';
const POLICY_SELECTOR = process.env.SOLONGATE_AGENT_ID || '';
const AGENT_ID = POLICY_SELECTOR || AGENT_TYPE;
const AGENT_NAME = process.env.SOLONGATE_AGENT_NAME || process.argv[3] || AGENT_TYPE;

const SG_LOCK_NAME = '.solongate-audit.lock';
const SG_LOCK_STALE_MS = 5000;
const SG_LOCK_WAIT_MS = 2000;

function sgSleep(ms) {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch {  }
}

function sgLockLog(dir) {
  const lock = join(dir, SG_LOCK_NAME);
  const until = Date.now() + SG_LOCK_WAIT_MS;
  for (;;) {
    try {
      closeSync(openSync(lock, 'wx', SG_FILE_MODE));
      return () => { try { rmSync(lock, { force: true }); } catch {} };
    } catch {
      try {
        const st = statSync(lock);
        if (Date.now() - st.mtimeMs > SG_LOCK_STALE_MS) {
          try { rmSync(lock, { force: true }); } catch {}
          continue;
        }
      } catch {  }
      if (Date.now() >= until) return null;
      sgSleep(10);
    }
  }
}

{
  const _wi = process.argv.indexOf('--sg-log-write');
  if (_wi !== -1) {
    try {
      const _pl = JSON.parse(Buffer.from(process.argv[_wi + 1] || '', 'base64').toString('utf-8'));
      if (_pl && _pl.dir && _pl.line) {
        let _dir = _pl.dir;
        const _narrow = (f) => { try { chmodSync(f, SG_FILE_MODE); } catch {} };
        try {
          mkdirSync(_dir, { recursive: true, mode: SG_DIR_MODE });
          const _f = join(_dir, 'solongate-audit.jsonl');
          const _unlock = sgLockLog(_dir);
          try {
            appendFileSync(_f, _pl.line, { mode: SG_FILE_MODE });
            _narrow(_f);
          } finally {
            if (_unlock) _unlock();
          }
        } catch {
          const _fb = join(resolve(homedir(), '.solongate'), 'local-logs');
          try { mkdirSync(_fb, { recursive: true, mode: SG_DIR_MODE }); } catch {}
          try {
            const _f = join(_fb, 'solongate-audit.jsonl');
            const _unlock = sgLockLog(_fb);
            try {
              appendFileSync(_f, _pl.line, { mode: SG_FILE_MODE });
              _narrow(_f);
            } finally {
              if (_unlock) _unlock();
            }
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


const SG_DONE = Symbol('sg-done');
let _sgDone = false;
let _decisionEmitted = false;
function sgFinish(code) {
  if (!_sgDone) { _sgDone = true; process.exitCode = code; }
  throw SG_DONE;
}


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
  return 0;
}

const CLIENTS = {
  'claude-code': {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    reportsAfter: true,
    redactsOutput: true,
  },

  codex: {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    reportsAfter: true,
    redactsOutput: false,
  },

  opencode: {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    reportsAfter: true,
    redactsOutput: true,
  },

  antigravity: {
    reportsAfter: true,
    redactsOutput: false,
    parse(raw) {
      const tc = (raw.toolCall && typeof raw.toolCall === 'object') ? raw.toolCall : {};
      const a = (tc.args && typeof tc.args === 'object') ? tc.args : {};
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
        const msg = `[SolonGate] ${d.reason}`;
        process.stdout.write(JSON.stringify({ decision: 'deny', reason: msg, allow_tool: false, deny_reason: msg }));
        return 0;
      }
      if (d.type === 'rewrite') {
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

  generic: {
    reportsAfter: false,
    redactsOutput: false,
    parse(raw) {
      return (raw.toolCall && typeof raw.toolCall === 'object')
        ? CLIENTS.antigravity.parse(raw)
        : parseFlatPayload(raw);
    },
    emit: emitHookSpecific,
  },
};

const CLIENT = CLIENTS[AGENT_TYPE] || CLIENTS.generic;

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

function rewriteTool(patch) {
  emitDecision({ type: 'rewrite', patch });
}

let CALL_ID = '';
let CALL_FP = '';
function callFingerprint(s) {
  let h = 0x811c9dc5;
  const str = String(s || '');
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16);
}

function writeDenyFlag(toolName) {
  try {
    const flagDir = projectFlagDir();
    mkdirSync(flagDir, { recursive: true });
    writeFileSync(join(flagDir, '.last-deny'), JSON.stringify({
      tool: toolName, ts: Date.now(), id: CALL_ID, fp: CALL_FP,
    }));
  } catch {}
}



function isSafeRegex(pattern) {
  if (typeof pattern !== 'string' || pattern.length > 512) return false;
  if (/(\+|\*|\{[^}]+\})\s*(\+|\*|\{[^}]+\})/.test(pattern)) return false;
  if (/\([^)]*(\+|\*|\{[^}]+\})[^)]*\)\s*(\+|\*|\{[^}]+\})/.test(pattern)) return false;
  if ((pattern.match(/\|/g) || []).length > 10) return false;
  try { new RegExp(pattern); return true; } catch { return false; }
}









const SEARCH_WALK_MAX_FILES = 2000;
const SEARCH_WALK_MAX_DEPTH = 8;
const SEARCH_SKIP_DIRS = new Set([
  '.git', 'node_modules', '.venv', 'venv', 'vendor', 'dist', 'build', 'target',
  '__pycache__', '.next', '.turbo',
]);

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
        let re; try { re = new RegExp('^' + b.replace(/\*{2,}/g, '*').replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]') + '$'); } catch { continue; }
        let files; try { files = readdirSync(dir); } catch { continue; }
        for (const f of files) if (re.test(f)) out.push(join(dir, f).replace(/\\/g, '/'));
      }
    }
  } catch {  }
  return out;
}

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
const TAMPER_CX = '/.codex';
const TAMPER_AGY = '/.gemini/config';
const TAMPER_PROTECTED_ABS = [
  TAMPER_HOME + TAMPER_CC + '/settings.json',
  TAMPER_HOME + TAMPER_CC + '/settings.local.json',
  TAMPER_HOME + TAMPER_CX + '/hooks.json',
  TAMPER_HOME + TAMPER_CX + '/config.toml',
  TAMPER_HOME + TAMPER_AGY + '/hooks.json',
  TAMPER_HOME + TAMPER_SG + '/hooks',
  TAMPER_HOME + TAMPER_SG + '/bin',
  TAMPER_HOME + TAMPER_SG + '/policy.json',
  TAMPER_HOME + TAMPER_SG + '/.policy-cache.json',
  TAMPER_HOME + TAMPER_SG + '/cloud-guard.json',
  TAMPER_HOME + TAMPER_SG + '/accounts.json',
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
  '**' + TAMPER_SG + '/cloud-guard.json',
  '**' + TAMPER_SG + '/.ratelimit-*',
  '**' + TAMPER_SG + '/bin/**',
  '**' + TAMPER_SG + '/data/**',
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
  'solongate-guard',
  '.policy-cache', '.ratelimit-',
  'cloud-guard.json',
  'accounts.json',
  'solongate.db', 'solongate.exe',
];
const TAMPER_PATH_FIELDS = new Set([
  'file_path', 'path', 'target_file', 'notebook_path',
  'dest', 'destination', 'source', 'src', 'from', 'to',
  'directory', 'dir', 'folder',
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
  if (/\/\.solongate\/bin(\/|$)/.test(np)) return 'solongate-bin';
  if (/\/\.codex\/(hooks\.json|config\.toml)$/.test(np)) return 'codex-hooks';
  if (/\/\.gemini\/config\/hooks\.json$/.test(np)) return 'antigravity-hooks';
  if (/(^|\/)\.solongate\//.test(np)) {
    const base = np.slice(np.lastIndexOf('/') + 1);
    for (const b of TAMPER_BASENAMES) {
      if (base.startsWith(b.toLowerCase())) return b;
    }
  }
  return false;
}



const CLI_BASENAMES = new Set([
  'solongate', 'solongate.exe',
  'solongate-proxy', 'solongate-proxy.exe',
  'solongate-audit', 'solongate-audit.exe',
]);

const CLI_WRAPPERS = new Set([
  'sudo', 'doas', 'env', 'nohup', 'time',
  'command', 'exec', 'nice', 'ionice', 'stdbuf',
  'setsid', 'xargs', 'watch', 'timeout', 'builtin',
  'bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'csh', 'tcsh', 'ash', 'busybox',
  'script', 'unbuffer', 'expect', 'socat',
  'flock', 'chroot', 'su', 'runuser',
  'taskset', 'strace', 'ltrace', 'proot',
  'fakeroot', 'setarch', 'nsenter', 'systemd-run',
  'xvfb-run', 'dbus-run-session',
]);

const CLI_FLAG_TAKES_VALUE = new Set([
  '-u', '-g', '-U', '-n', '-i', '-I', '-s', '-w', '-t', '-p', '-C',
  '--user', '--group', '--chdir',
]);

const CLI_ALWAYS_RUNNERS = new Set(['npx', 'pnpx', 'bunx']);

const CLI_MAYBE_RUNNERS = new Set(['npm', 'pnpm', 'yarn', 'bun']);

const CLI_RUN_SUBCOMMANDS = new Set(['exec', 'dlx', 'x']);

const CLI_NUMBERISH = /^[0-9]+(?:\.[0-9]+)?[a-z]*$/;
const CLI_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

function commandInvokesCLI(cmd) {
  return commandInvokesCLIDepth(cmd, 0);
}

function commandInvokesCLIDepth(cmd, depth) {
  for (const fields of splitCLICommands(String(cmd || ''))) {
    if (fieldsInvokeCLI(fields, depth)) return true;
  }
  return false;
}

function splitCLICommands(cmd) {
  const out = [];
  let fields = [];
  let tok = '';
  let quote = '';

  const endToken = () => { if (tok) { fields.push(tok); tok = ''; } };
  const endCommand = () => {
    endToken();
    if (fields.length) { out.push(fields); fields = []; }
  };

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (quote) {
      if (ch === quote) quote = '';
      else if (ch === '\\' && quote === '"' && i + 1 < cmd.length) tok += cmd[++i];
      else tok += ch;
      continue;
    }
    if (ch === "'" || ch === '"') quote = ch;
    else if (ch === '$' && (cmd[i + 1] === '(' || cmd[i + 1] === '{')) { i++; endCommand(); }
    else if (ch === '<' && cmd[i + 1] === '<' && cmd[i + 2] !== '<') {
      const { delim, quoted, after } = readHeredocDelimiter(cmd, i + 2);
      if (!quoted) {
        i = after - 1;
      } else {
        endCommand();
        i = skipHeredocBody(cmd, after, delim) - 1;
      }
    }
    else if ('|&;\n\r`'.includes(ch)) endCommand();
    else if (ch === ' ' || ch === '\t') endToken();
    else tok += ch;
  }
  endCommand();
  return out;
}

function readHeredocDelimiter(cmd, i) {
  if (cmd[i] === '-') i++;
  while (i < cmd.length && (cmd[i] === ' ' || cmd[i] === '\t')) i++;
  if (i >= cmd.length) return { delim: '', quoted: false, after: i };
  const q = cmd[i];
  if (q === "'" || q === '"') {
    i++;
    const start = i;
    while (i < cmd.length && cmd[i] !== q) i++;
    const delim = cmd.slice(start, i);
    if (i < cmd.length) i++;
    return { delim, quoted: true, after: i };
  }
  const start = i;
  while (i < cmd.length && !' \t\n\r;|&'.includes(cmd[i])) i++;
  return { delim: cmd.slice(start, i), quoted: false, after: i };
}

function skipHeredocBody(cmd, i, delim) {
  if (!delim) return cmd.length;
  const nl = cmd.indexOf('\n', i);
  if (nl < 0) return cmd.length;
  i = nl + 1;
  while (i < cmd.length) {
    const end = cmd.indexOf('\n', i);
    const line = end < 0 ? cmd.slice(i) : cmd.slice(i, end);
    const next = end < 0 ? cmd.length : end + 1;
    if (line.replace(/^[ \t]+/, '').replace(/[ \t\r]+$/, '') === delim) return next;
    i = next;
  }
  return cmd.length;
}

function argsInvokeCLI(args) {
  if (!args || typeof args !== 'object') return false;
  for (const k of Object.keys(args)) {
    if (!CLI_COMMAND_FIELDS.has(k.toLowerCase())) continue;
    const v = args[k];
    if (typeof v === 'string' && commandInvokesCLI(v)) return true;
  }
  return false;
}

const CLI_COMMAND_FIELDS = new Set(['command', 'cmd', 'function', 'script', 'shell']);

function fieldsInvokeCLI(fields, depth) {
  let wrapped = false;
  for (let i = 0; i < fields.length; i++) {
    const tok = fields[i].replace(/^[(){}"']+/, '').replace(/[(){}"']+$/, '');
    if (!tok) continue;
    if (CLI_ASSIGNMENT.test(tok)) {
      wrapped = true;
      continue;
    }
    if (wrapped) {
      if (tok.startsWith('-')) {
        if (CLI_FLAG_TAKES_VALUE.has(tok.toLowerCase())) i++;
        continue;
      }
      if (CLI_NUMBERISH.test(tok)) continue;
    }
    if (wrapped && depth < 8 && /[ \t]/.test(tok)) {
      if (commandInvokesCLIDepth(tok, depth + 1)) return true;
    }

    const base = tok.replace(/\\/g, '/').split('/').pop().toLowerCase();
    if (CLI_WRAPPERS.has(base)) { wrapped = true; continue; }
    if (CLI_BASENAMES.has(base)) return true;
    if (CLI_ALWAYS_RUNNERS.has(base)) return restRunsCLIPackage(fields.slice(i + 1));
    if (CLI_MAYBE_RUNNERS.has(base)) return maybeRunnerRunsCLI(fields.slice(i + 1));
    if (/[/\\]/.test(tok)) continue;
    return false;
  }
  return false;
}

function maybeRunnerRunsCLI(rest) {
  for (let j = 0; j < rest.length; j++) {
    if (rest[j].startsWith('-')) continue;
    if (CLI_RUN_SUBCOMMANDS.has(rest[j].toLowerCase())) return restRunsCLIPackage(rest.slice(j + 1));
    return false;
  }
  return false;
}

function restRunsCLIPackage(rest) {
  return rest.some((t) => {
    const tl = t.toLowerCase();
    return tl.includes('solongate/proxy') || CLI_BASENAMES.has(tl);
  });
}

function commandTargetsProtected(cmd) {
  const c = String(cmd || '').toLowerCase();
  if (!c) return false;
  for (const b of TAMPER_BASENAMES) {
    if (c.includes(b.toLowerCase())) return b;
  }
  if (/\.claude[\\/]+settings(\.local)?\.json/.test(c)) return 'settings.json';
  if (/\.solongate[\\/]+hooks/.test(c)) return 'solongate-hooks';
  if (/\.solongate[\\/]+bin/.test(c)) return 'solongate-bin';
  if (/\.codex[\\/]+(hooks\.json|config\.toml)/.test(c)) return 'codex-hooks';
  if (/\.gemini[\\/]+config[\\/]+hooks\.json/.test(c)) return 'antigravity-hooks';
  if (/[\\/]solongate[\\/]+(compose|data|images|helm)[\\/]/.test(c)) return 'solongate-install';
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

function toolIsExec(toolName) {
  const tn = String(toolName || '').toLowerCase();
  return TAMPER_GUARD_TOOLS_EXEC.has(tn) || /bash|shell|exec|powershell|cmd|run|eval/.test(tn);
}

function tamperCheck(toolName, args) {
  const isExec = toolIsExec(toolName);
  for (const p of extractTargetPaths(args)) {
    const hit = isProtectedPath(p);
    if (hit) return 'Tamper protection: access to "' + p + '" is blocked (protected: ' + hit + ')';
  }
  if (isExec) {
    for (const cmd of extractCommands(args)) {
      const hit = commandTargetsProtected(cmd);
      if (hit) return 'Tamper protection: command references protected resource "' + hit + '", blocked';
    }
    if (argsInvokeCLI(args)) {
      return 'Tamper protection: command references protected resource "solongate-cli", blocked';
    }
  }
  return null;
}


function underProtected(raw, norm) {
  const s = String(raw || '').trim();
  if (!s) return '';
  const np = normTamperPath(normalize(s));
  for (const p of norm) {
    if (np === p || np.startsWith(p + '/')) return p;
  }
  return '';
}

function protectedReason(named, hit) {
  if (named === hit) {
    return 'Protected path: "' + hit + '" cannot be read, written or deleted by an agent';
  }
  return 'Protected path: "' + named + '" is inside "' + hit +
    '", which cannot be read, written or deleted by an agent';
}

function userProtectedCheck(toolName, args, sec) {
  const list = sec && Array.isArray(sec.protectedPaths) ? sec.protectedPaths : null;
  if (!list || list.length === 0) return null;
  const norm = [];
  for (const p of list) {
    const t = String(p || '').trim();
    if (t) norm.push(normTamperPath(normalize(t)));
  }
  if (norm.length === 0) return null;

  for (const raw of extractTargetPaths(args)) {
    const hit = underProtected(raw, norm);
    if (hit) return protectedReason(raw, hit);
  }

  const isExec = toolIsExec(toolName);
  for (const raw of extractPaths(args || {}, isExec)) {
    const hit = underProtected(raw, norm);
    if (hit) return protectedReason(raw, hit);
  }

  if (isExec) {
    for (const cmd of extractCommands(args || {})) {
      const c = normTamperPath(cmd);
      for (const p of norm) {
        if (c.includes(p)) return protectedReason(p, p);
      }
    }
  }
  return null;
}

function sandboxVerified(sec) {
  const marker = String(process.env.SOLONGATE_SANDBOX || '');
  if (marker === '') return { confined: false, conclusive: true };
  const mode = marker.includes(':') ? marker.slice(0, marker.indexOf(':')) : 'run';

  if (mode === 'box') {
    try {
      const init = readFileSync('/proc/1/comm', 'utf-8').trim();
      if (init === 'systemd' || init === 'init' || init === 'launchd') {
        return { confined: false, conclusive: true };
      }
      if (init === '') return { confined: false, conclusive: false };
      return { confined: true, conclusive: true };
    } catch {
      return { confined: false, conclusive: false };
    }
  }

  const paths = (sec && Array.isArray(sec.protectedPaths)) ? sec.protectedPaths : [];
  for (const raw of paths) {
    const pth = String(raw || '').trim();
    if (!pth) continue;
    try {
      accessSync(pth, constants.R_OK);
      return { confined: false, conclusive: true };
    } catch (e) {
      if (e && e.code === 'ENOENT') continue;
      return { confined: true, conclusive: true };
    }
  }
  return { confined: false, conclusive: false };
}

function sandboxRequired(sec) {
  if (!sec || sec.requireSandbox !== true) return null;
  const { confined, conclusive } = sandboxVerified(sec);
  if (confined && conclusive) return null;
  if (!conclusive) {
    return 'Refused: this machine requires agents to be started with `solongate run` or ' +
      '`solongate sandbox`, and there is no way to confirm that this one was. ' +
      'Add a protected path, or use `solongate sandbox`, which can be verified.';
  }
  if (String(process.env.SOLONGATE_SANDBOX || '') !== '') {
    return 'Refused: this process carries a sandbox marker but is not confined, ' +
      'the kernel says otherwise. Start the agent with `solongate run` or ' +
      '`solongate sandbox`, and remove SOLONGATE_SANDBOX from your shell profile.';
  }
  return 'Refused: this machine requires agents to be started with `solongate run` or ' +
    '`solongate sandbox`. Protected paths are enforced by the operating system there, ' +
    'and by string matching anywhere else.';
}


const DLP_PATTERNS = dlpPatterns('');


const DLP_MAX_FILE_BYTES = 1048576;

function dlpViews(text) {
  const views = [text];
  try {
    const dequoted = text.replace(/[`'"\\]/g, '');
    if (dequoted !== text) views.push(dequoted);
    const src = dequoted !== text ? text + '\n' + dequoted : text;
    const toks = src.match(/[A-Za-z0-9+/]{16,}={0,2}/g) || [];
    let decoded = '';
    for (const t of toks.slice(0, 60)) {
      try {
        const d = Buffer.from(t, 'base64').toString('latin1');
        if (/[ -~]{8,}/.test(d)) decoded += d + '\n';
      } catch {  }
    }
    if (decoded) views.push(decoded);
  } catch {  }
  return views;
}
function dlpScan(args, cfg) {
  if (!cfg) return null;
  let text = '';
  try { text = JSON.stringify(args || {}); } catch { return null; }
  text = text.replace(/\[REDACTED:[^\]]*\]/g, '');
  const views = dlpViews(text);
  const allow = new Set(Array.isArray(cfg.patterns) ? cfg.patterns : []);
  for (const p of DLP_PATTERNS) {
    if (allow.has(p.name) && views.some((v) => p.re.test(v))) return p.name;
  }
  for (const c of Array.isArray(cfg.custom) ? cfg.custom : []) {
    try { const re = dlpGlobToRe(c.re); if (views.some((v) => re.test(v))) return c.name || 'custom pattern'; } catch {  }
  }
  return null;
}

function egressSecretCheck(args, sec, cwd) {
  try {
    const dlp = sec && sec.dlpBlock;
    if (!dlp) return null;
    const base = cwd || process.cwd();
    for (const cmd of extractPipelines(args)) {
      const c = String(cmd || '');
      const lc = c.toLowerCase();
      if (!/\b(curl|wget|scp|rsync|sftp|ftp|nc|netcat)\b/.test(lc)) continue;
      if (!/https?:\/\//.test(lc) && !/@[\w.-]+:/.test(c) && !/\b\S+:\S/.test(c)) continue;
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
      if (/\b(scp|rsync|sftp)\b/.test(lc)) {
        for (const tok of c.split(/\s+/).slice(1)) {
          if (!tok || tok.startsWith('-')) continue;
          if (/^[\w.-]*@?[\w.-]+:/.test(tok)) continue;
          if (/^https?:\/\//.test(tok)) continue;
          files.add(tok.replace(/^@/, ''));
        }
      }
      for (let f of files) {
        if (f.startsWith('~')) f = homedir() + f.slice(1);
        let abs; try { abs = isAbsolute(f) ? f : resolve(base, f); } catch { continue; }
        let content = null;
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
  } catch {  }
  return null;
}

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

function dlpRedactReadPlan(toolName, args, dlp, cwd) {
  try {
    if (!dlp || !args) return null;
    const base = cwd || process.cwd();
    const abends = (f) => { let x = f; if (x.startsWith('~')) x = homedir() + x.slice(1); return isAbsolute(x) ? x : resolve(base, x); };
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
    for (const [k, v] of Object.entries(args)) {
      if (k === 'command' || typeof v !== 'string' || !v || !/[./]/.test(v)) continue;
      const r = redactCopy(abends(v));
      if (r === 'SKIP' || r === 'CLEAN') continue;
      if (r === 'FAILED') return { block: true };
      return { rewrite: { [k]: r } };
    }
    const GLOB_META = /[*?\[]/;
    const expandGlob = (absGlob) => {
      try {
        const dir = dirname(absGlob);
        const base = absGlob.slice(dir.length + 1);
        if (!GLOB_META.test(base)) return [absGlob];
        const re = new RegExp('^' + base.replace(/\*{2,}/g, '*').replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]') + '$');
        return readdirSync(dir).filter((f) => re.test(f)).map((f) => join(dir, f));
      } catch { return []; }
    };
    const cmd = typeof args.command === 'string' ? args.command : '';
    if (cmd && /\b(cat|less|more|head|tail|bat|nl|od|xxd|hexdump|strings|grep|egrep|fgrep|rg|ag|cut|awk|gawk|sed|tr|sort|uniq|paste|join|comm|column|fold|tac|rev|pr|expand|unexpand|base64|base32|dd|mapfile|readarray)\b/.test(cmd.toLowerCase())) {
      let newCmd = cmd, changed = false;
      for (const tok of cmd.split(/[\s'"|<>;&()]+/)) {
        if (!tok || tok.startsWith('-') || !/[./]/.test(tok)) continue;
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
  } catch { return { block: true }; }
  return null;
}

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
      if (hit) return 'Security layer (DLP): reading "' + f + '" is blocked, it contains a ' + hit + '. Blocked by SolonGate.';
    }
  } catch {  }
  return null;
}

function cleanShellToken(tok) {
  let t = String(tok || '').trim();
  t = t.replace(/^[<>|;&(]+/, '').replace(/[);&|]+$/, '');
  t = t.replace(/^['"]+/, '').replace(/['"]+$/, '');
  t = t.replace(/^\d*>>?/, '');
  return t.trim();
}

const RL_WINDOWS = [
  { key: 'perDay', ms: 86400000, label: 'day' },
  { key: 'perHour', ms: 3600000, label: 'hour' },
  { key: 'perMinute', ms: 60000, label: 'minute' },
];
const RL_STAMP = 13;
const RL_TOKEN = 10;
const RL_REC = RL_STAMP + RL_TOKEN + 1;
const RL_MAX_READ = 1_048_576;
const RL_MAX_FILE = 4_194_304;

function rlNewToken() {
  try {
    return randomBytes(RL_TOKEN / 2).toString('hex');
  } catch {
    return '0'.repeat(RL_TOKEN);
  }
}

function rateLimitCheck(agentKey, limits) {
  try {
    const dir = resolve(homedir(), '.solongate');
    const file = join(dir, '.ratelimit-' + agentKey + '.v2.log');
    const now = Date.now();
    try { mkdirSync(dir, { recursive: true }); } catch {}
    const token = rlNewToken();
    try {
      appendFileSync(file, String(now).padStart(RL_STAMP, '0') + token + '\n');
    } catch { return null; }

    let size = 0;
    try { size = statSync(file).size; } catch { return null; }
    const start = Math.max(0, size - RL_MAX_READ);
    const from = start - (start % RL_REC);
    let buf = '';
    try {
      const fd = openSync(file, 'r');
      const b = Buffer.alloc(size - from);
      readSync(fd, b, 0, b.length, from);
      closeSync(fd);
      buf = b.toString('latin1');
    } catch { return null; }

    const entries = [];
    let mine = -1;
    for (let i = 0; i + RL_REC <= buf.length; i += RL_REC) {
      const t = parseInt(buf.slice(i, i + RL_STAMP), 10);
      if (!Number.isFinite(t) || now - t >= 86400000) continue;
      const tok = buf.slice(i + RL_STAMP, i + RL_STAMP + RL_TOKEN);
      if (tok === token && mine < 0) mine = entries.length;
      entries.push({ ms: t, token: tok });
    }

    for (const w of RL_WINDOWS) {
      const limit = limits[w.key];
      if (!(limit > 0)) continue;
      if (mine >= 0) {
        const ahead = entries.slice(0, mine).reduce((n, e) => (now - e.ms < w.ms ? n + 1 : n), 0);
        if (ahead >= limit) return { window: w.label, limit };
        continue;
      }
      const count = entries.reduce((n, e) => (now - e.ms < w.ms ? n + 1 : n), 0);
      if (count > limit) return { window: w.label, limit };
    }

    if (size > RL_MAX_FILE) {
      try {
        const tmp = file + '.' + process.pid + '.tmp';
        writeFileSync(tmp, entries.map((e) => String(e.ms).padStart(RL_STAMP, '0') + e.token + '\n').join(''));
        renameSync(tmp, file);
      } catch {  }
    }
    return null;
  } catch {
    return null;
  }
}

function observingDLP(sec) {
  if (!sec) return null;
  if (sec.dlpRedact) return { cfg: sec.dlpRedact, mode: 'redact' };
  if (sec.dlpObserve) return { cfg: sec.dlpObserve, mode: 'detect' };
  return null;
}

function securityLayerCheck(toolName, args, cfg, agentKey) {
  if (!cfg) return null;
  try {
    if (cfg.dlpBlock) {
      const hit = dlpScan(args, cfg.dlpBlock);
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
  } catch {  }
  return null;
}


function applyPatchTargets(patch) {
  const out = [];
  if (typeof patch !== 'string' || !patch.includes('*** ')) return out;
  const re = /^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s*(.+?)\s*$/gm;
  let m;
  while ((m = re.exec(patch))) if (m[1]) out.push(m[1]);
  const mv = /^\*\*\*\s+Move\s+to:\s*(.+?)\s*$/gm;
  while ((m = mv.exec(patch))) if (m[1]) out.push(m[1]);
  return out;
}

function liftFreeformPatchPaths(call) {
  const cmd = call.command;
  if (call.tool !== 'apply_patch' && !(typeof cmd === 'string' && cmd.startsWith('*** Begin Patch'))) return;
  const targets = applyPatchTargets(cmd);
  if (!targets.length) return;
  call.args = { ...call.args };
  if (!call.args.file_path) call.args.file_path = targets[0];
  if (!Array.isArray(call.args.edits)) call.args.edits = targets.map((f) => ({ file_path: f }));
}

function normalizeToolCall(raw) {
  const parsed = CLIENT.parse(raw) || {};
  const tool = parsed.tool || '';
  const call = {
    client: AGENT_TYPE,
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

let input = '';
function readReferencedFiles(args, cwd) {
  const out = {};
  const MAX_FILES = 3, MAX_BYTES = 65536;
  const cands = new Set();
  const INTERP = /^(?:bash|sh|zsh|ksh|dash|ash|python3?|node|deno|bun|ruby|perl|php|pwsh|powershell|source|\.)$/i;
  if (args && typeof args === 'object') {
    for (const f of ['command', 'cmd', 'script', 'shell', 'code']) {
      const v = args[f];
      if (typeof v !== 'string') continue;
      const toks = v.split(/[\s'"();|&<>]+/).filter(Boolean);
      for (let i = 0; i < toks.length - 1; i++) {
        if (!INTERP.test(toks[i])) continue;
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

input += SG_STDIN;
;(async () => {
 try { setTimeout(() => { try { process.exit(process.exitCode || 0); } catch {} }, 8000).unref(); } catch {}
 try {
  const _evalStart = SG_ORIGIN_MS;
  try {
    const raw = JSON.parse(input);

    if (process.env.SOLONGATE_DEBUG) {
      try {
        const { appendFileSync: afs, mkdirSync: mds } = await import('node:fs');
        mds(resolve('.solongate'), { recursive: true });
        const debugLine = JSON.stringify({ ts: new Date().toISOString(), hook: 'guard', argv: process.argv.slice(2), tool_name: raw.tool_name || raw.toolName || raw.command, agent_id: AGENT_ID }) + '\n';
        afs(resolve('.solongate', '.debug-guard-log'), debugLine);
      } catch {}
    }

    CALL_ID = String(raw.tool_use_id || raw.toolUseId || raw.tool_call_id || '');
    try { CALL_FP = callFingerprint(JSON.stringify(raw.tool_input || raw.toolInput || raw.params || {})); } catch { CALL_FP = ''; }

    const call = normalizeToolCall(raw);
    const args = call.args;
    const toolName = call.tool;

    if (process.env.SOLONGATE_DEBUG) {
      try {
        process.stderr.write('[SolonGate CALL] ' + JSON.stringify({
          permission: call.permission, args: call.args, command: call.command,
          cwd: call.cwd, sessionId: call.sessionId,
        }) + '\n');
      } catch {}
    }



    const hookCwd = call.cwd || process.cwd();
    let policy;
    let selfProtectEnabled = true;
    let securityCfg = null;
    const agentKey = (AGENT_ID || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
    try {
      {
        const local = loadLocalPolicyFile(hookCwd);
        if (local) {
          policy = local.policy;
          if (local.security !== undefined) securityCfg = local.security;
          if (local.selfProtect !== undefined) selfProtectEnabled = local.selfProtect;
        }
      }
    } catch {
    }

    const policyInScope = (() => {
      const scope = (policy && Array.isArray(policy.agents) && policy.agents.length > 0)
        ? policy.agents
        : ['*'];
      return scope.includes('*') || scope.includes(AGENT_TYPE);
    })();

    let reason = selfProtectEnabled ? tamperCheck(toolName, args) : null;
    if (!reason) reason = sandboxRequired(securityCfg);
    if (!reason) reason = userProtectedCheck(toolName, args, securityCfg);
    if (!reason) reason = egressSecretCheck(args, securityCfg, call.cwd);
    if (!reason) reason = securityLayerCheck(toolName, args, securityCfg, agentKey);
    let opaRoute = 'white';
    if (reason) {
      opaRoute = 'black';
    } else if (policy && policy.rules && policyInScope) {
      const verdict = evaluate(policy, args, toolName, hookCwd);
      if (typeof verdict === 'string') {
        reason = verdict;
        opaRoute = 'black';
      } else {
        opaRoute = 'white';
      }
    }

    const dlpBlocking = !!(securityCfg && securityCfg.dlpBlock);
    if (!reason && securityCfg && (securityCfg.dlpBlock || securityCfg.dlpRedact)
        && (dlpBlocking || !CLIENT.redactsOutput)) {
      const dlpCfg = securityCfg.dlpBlock || securityCfg.dlpRedact;
      const plan = dlpRedactReadPlan(toolName, args, dlpCfg, hookCwd);
      if (plan && (plan.block || (dlpBlocking && plan.rewrite))) {
        reason = 'Security layer (DLP): reading a file that contains a secret is blocked. Blocked by SolonGate.';
        opaRoute = 'black';
      } else if (plan && plan.rewrite) {
        rewriteTool(plan.rewrite);
      }
    }

    if (AGENT_TYPE !== 'codex') process.stderr.write(`[SolonGate ROUTE] ${opaRoute.toUpperCase()} (${reason ? 'block' : 'allow'})\n`);

    try {
      const _fd = projectFlagDir(); mkdirSync(_fd, { recursive: true });
      sweepLegacyFlagDir();
      const _isExec = guessPermission(toolName) === 'EXECUTE';
      const _rec = {
        ms: Date.now() - _evalStart,
        ts: Date.now(),
        tool: toolName,
        session: call.sessionId,
        client: AGENT_TYPE,
        cwd: call.cwd,
        perm: guessPermission(toolName),
        args: Object.keys(call.args || {}).sort(),
        paths: extractPaths(call.args || {}, _isExec).length,
        cmds: extractCommands(call.args || {}).length,
        urls: extractUrls(call.args || {}).length,
        sandbox: process.env.SOLONGATE_SANDBOX || '',
      };
      writeFileSync(join(_fd, '.last-eval'), JSON.stringify(_rec));
      try {
        const ring = join(_fd, '.eval-ring.jsonl');
        appendFileSync(ring, JSON.stringify(_rec) + '\n');
        try { if (statSync(ring).size > 16384) writeFileSync(ring, readFileSync(ring, 'utf-8').split('\n').filter(Boolean).slice(-50).join('\n') + '\n'); } catch {}
      } catch {}
    } catch {}

    if (!reason && !CLIENT.reportsAfter && securityCfg && !securityCfg.dlpBlock) {
      try {
        const _obs = observingDLP(securityCfg);
        if (_obs) {
          const _hit = dlpScan(args, _obs.cfg);
          if (_hit) {
            writeLocalLog(securityCfg, {
              ts: new Date().toISOString(),
              tool: toolName, arguments: args,
              decision: 'ALLOW',
              reason: 'Security layer (DLP): detected - arguments contain a ' + _hit +
                '. Allowed: DLP is in ' + _obs.mode + ' mode.',
              permission: guessPermission(toolName),
              source: `${AGENT_TYPE}-guard`,
              agent_id: AGENT_TYPE, agent_name: AGENT_NAME,
              session_id: call.sessionId,
              evaluation_time_ms: Date.now() - _evalStart,
            });
          }
        }
      } catch {  }
    }

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
      blockTool(reason);
    }
  } catch {}
  allowTool();
 } catch (e) {
  if (e !== SG_DONE) { process.exitCode = process.exitCode || 0; }
 }
})();
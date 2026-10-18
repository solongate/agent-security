#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

import { readFileSync, existsSync, writeFileSync, mkdirSync, appendFileSync, chmodSync } from 'node:fs';
import { resolve, join, isAbsolute } from 'node:path';
import { homedir } from 'node:os';

import { DLP_PATTERN_NAMES, dlpGlobToRe, dlpPatterns } from './dlp.mjs';
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


const HOOK_VERSION = 33;


function readLastEvalMs(toolName, sessionId) {
  try {
    const ring = join(projectFlagDir(), '.eval-ring.jsonl');
    if (existsSync(ring)) {
      const now = Date.now();
      const recent = [];
      for (const line of readFileSync(ring, 'utf-8').split('\n')) {
        if (!line) continue;
        let r; try { r = JSON.parse(line); } catch { continue; }
        if (!r || typeof r.ms !== 'number' || typeof r.ts !== 'number') continue;
        if (now - r.ts > 2500) continue;
        if (r.session && sessionId && r.session !== sessionId) continue;
        recent.push(r.ms);
      }
      if (recent.length) return Math.max(0, Math.round(recent.reduce((a, b) => a + b, 0) / recent.length));
    }
  } catch {}
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

const DLP_PATTERNS = dlpPatterns('g');

const SG_DIR_MODE = 0o700;
const SG_FILE_MODE = 0o600;

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

function loadSecurity() {
  return localSecurity();
}

function loadDlpRedact() {
  try {
    const sec = loadSecurity();
    const d = (sec && sec.dlpRedact) || (sec && sec.dlpBlock);
    return d && Array.isArray(d.patterns) ? d : null;
  } catch { return null; }
}

function loadDlpScan() {
  try {
    const sec = loadSecurity();
    const d = (sec && sec.dlpRedact) || (sec && sec.dlpBlock) || (sec && sec.dlpObserve);
    return d && Array.isArray(d.patterns) ? d : null;
  } catch { return null; }
}


function dlpScanArgs(argsSummary, dlpCfg) {
  try {
    if (!dlpCfg || !Array.isArray(dlpCfg.patterns) || !dlpCfg.patterns.length) return [];
    const text = typeof argsSummary === 'string' ? argsSummary : JSON.stringify(argsSummary || {});
    if (!text) return [];
    const enabled = new Set(dlpCfg.patterns);
    const hits = [];
    for (const p of DLP_PATTERNS) {
      if (!enabled.has(p.name)) continue;
      try { p.re.lastIndex = 0; if (p.re.test(text)) hits.push(p.name); } catch {  }
      if (hits.length >= 5) break;
    }
    for (const c of (dlpCfg.custom || [])) {
      try { if (c && c.re && dlpGlobToRe(c.re, 'gi').test(text)) hits.push(c.name || 'custom'); } catch {  }
      if (hits.length >= 5) break;
    }
    return hits;
  } catch { return []; }
}

function loadRateLimitObserve() {
  try {
    const sec = loadSecurity();
    const r = sec && sec.rateLimitObserve;
    return r && typeof r === 'object' ? r : null;
  } catch { return null; }
}

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
    try { writeFileSync(file, JSON.stringify(stamps)); } catch {  }
    return burst;
  } catch { return false; }
}

function loadLocalLogs() {
  try {
    const sec = loadSecurity();
    const l = sec && sec.localLogs;
    if (l && typeof l.path === 'string' && l.path.trim()) return { path: l.path.trim() };
  } catch {  }
  return { path: resolve(homedir(), '.solongate', 'local-logs') };
}

function resolveLocalLogDir(rawPath) {
  const dir = String(rawPath || '').trim().replace(/[\\/]+$/, '');
  if (!dir) return null;
  if (isAbsolute(dir)) return dir;
  const fallback = resolve(homedir(), '.solongate', 'local-logs');
  try {
    mkdirSync(resolve(homedir(), '.solongate'), { recursive: true, mode: 0o700 });
    writeFileSync(resolve(homedir(), '.solongate', '.local-logs-invalid-path'),
      JSON.stringify({ configured: dir, fallback, ts: Date.now() }));
  } catch {  }
  return fallback;
}

function appendLocalLog(cfg, entry) {
  try {
    const dir = resolveLocalLogDir(cfg.path);
    if (!dir) return;
    const line = JSON.stringify(entry) + '\n';
    const narrow = (f) => { try { chmodSync(f, SG_FILE_MODE); } catch {  } };
    try {
      mkdirSync(dir, { recursive: true, mode: SG_DIR_MODE });
      const file = join(dir, 'solongate-audit.jsonl');
      appendFileSync(file, line, { mode: SG_FILE_MODE });
      narrow(file);
    } catch {
      const fb = resolve(homedir(), '.solongate', 'local-logs');
      try { mkdirSync(fb, { recursive: true, mode: SG_DIR_MODE }); } catch {  }
      try {
        const file = join(fb, 'solongate-audit.jsonl');
        appendFileSync(file, line, { mode: SG_FILE_MODE });
        narrow(file);
      } catch {  }
      try {
        writeFileSync(resolve(homedir(), '.solongate', '.local-logs-invalid-path'),
          JSON.stringify({ configured: dir, fallback: fb, ts: Date.now() }));
      } catch {  }
    }
  } catch {  }
}

const OUTPUT_DLP_HITS = new Set();

function dlpRedactText(text, cfg, found) {
  if (!cfg || typeof text !== "string" || !text) return text;
  const allow = new Set(Array.isArray(cfg.patterns) ? cfg.patterns : []);
  const NUL = String.fromCharCode(0);
  const labels = [];
  const stash = (label) => NUL + (labels.push(label) - 1) + NUL;
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
    if (Array.isArray(r.filenames)) {
      const t = r.filenames.filter((x) => typeof x === 'string').join('\n');
      if (t) return t;
    }
  }
  if (typeof toolOutput === 'string' && toolOutput) return toolOutput;
  return null;
}

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
  if (name === 'apply_patch' || name === 'applypatch') return 'WRITE';
  if (name.includes('exec') || name.includes('shell') || name.includes('run') || name.includes('eval') || name === 'bash') return 'EXECUTE';
  if (name.includes('fetch') || name.includes('http') || name.includes('request') || name.includes('curl') || name.includes('network') || name.includes('download') || name.includes('upload') || name === 'websearch') return 'NETWORK';
  if (name.includes('write') || name.includes('create') || name.includes('delete') || name.includes('update') || name.includes('set') || name.includes('edit') || name.includes('remove') || name.includes('insert')) return 'WRITE';
  return 'READ';
}

const AGENT_ID = process.argv[2] || 'claude-code';
const AGENT_NAME = process.argv[3] || 'Claude Code';


let input = '';
try { input += readFileSync(0, 'utf-8'); } catch {}
;(async () => {
  try { setTimeout(() => { try { process.exit(process.exitCode || 0); } catch {} }, 8000).unref(); } catch {}
  try {
    const data = JSON.parse(input);
    let EMITTED_PAYLOAD = null;

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
          else guardDenied = !flag.id && !flag.fp;
        }
      }
    } catch {}

    const toolResponse = data.tool_response || data.toolResponse || {};
    const toolOutput = data.tool_output || data.toolOutput || '';
    const resultJson = data.result_json ? (typeof data.result_json === 'string' ? data.result_json : JSON.stringify(data.result_json)) : '';

    try {
      const dlpCfg = loadDlpRedact();
      const redactName = (s) => (dlpCfg && typeof s === 'string') ? dlpRedactText(s, dlpCfg, OUTPUT_DLP_HITS) : s;

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
        let out = null;
        if (dlpCfg) {
          const base = extractOutputText(toolResponse, toolOutput);
          if (typeof base === 'string') {
            const redacted = dlpRedactText(base, dlpCfg, OUTPUT_DLP_HITS);
            if (redacted !== base) out = redacted;
          }
        }
        if (typeof out === 'string') {
          if (out === '') out = '\n';
          const tr = toolResponse;
          let updated;
          if (tr && typeof tr === 'object' && typeof tr.stdout === 'string') updated = { ...tr, stdout: out };
          else if (tr && typeof tr === 'object' && typeof tr.content === 'string') updated = { ...tr, content: out };
          else if (tr && typeof tr === 'object' && Array.isArray(tr.content)) updated = { ...tr, content: [{ type: 'text', text: out }] };
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

    const argsSummary = {};
    for (const [k, v] of Object.entries(toolInput)) {
      argsSummary[k] = typeof v === 'string' && v.length > 8000
        ? v.slice(0, 8000) + '…'
        : v;
    }

    if (AGENT_ID === 'codex' && typeof EMITTED_PAYLOAD === 'string') EMITTED_PAYLOAD = null;

    let flushed = (typeof EMITTED_PAYLOAD !== 'string');
    const maybeExit = () => { if (flushed) { process.exitCode = 0; } };
    if (typeof EMITTED_PAYLOAD === 'string') {
      try { process.stdout.write(EMITTED_PAYLOAD, () => { flushed = true; maybeExit(); }); }
      catch { flushed = true; }
    }

    const sessionId = data.session_id || data.sessionId || data.conversation_id || '';
    const decision = hasError ? 'DENY' : 'ALLOW';
    const reason = guardDenied ? 'blocked by policy guard' : hasError ? 'tool returned error' : '';
    const permission = guessPermission(toolName);
    const evaluationTimeMs = readLastEvalMs(toolName, sessionId);

    let dlpMatches = [];
    let rateLimitBurst = false;
    if (decision === 'ALLOW') {
      try { dlpMatches = dlpScanArgs(argsSummary, loadDlpScan()); } catch { dlpMatches = []; }
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
      } catch {  }
      try { rateLimitBurst = rateLimitObserveBurst(AGENT_ID, loadRateLimitObserve()); } catch { rateLimitBurst = false; }
    }

    appendLocalLog(loadLocalLogs(), {
      ts: new Date().toISOString(),
      tool: toolName, arguments: argsSummary, decision, reason, permission,
      evaluation_time_ms: evaluationTimeMs, agent_id: AGENT_ID, agent_name: AGENT_NAME, session_id: sessionId,
      ...(dlpMatches.length ? { dlp: dlpMatches } : {}),
      ...(rateLimitBurst ? { rate_limit_burst: true } : {}),
    });
    maybeExit();
    try { setTimeout(() => { try { process.exit(process.exitCode || 0); } catch {} }, 8000).unref(); } catch {}
  } catch {
    process.exitCode = 0;
  }
})().catch(() => { process.exitCode = process.exitCode || 0; });
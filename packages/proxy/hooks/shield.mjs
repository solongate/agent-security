#!/usr/bin/env node
/**
 * SolonGate Shield (standalone hook) — secret redaction on the LLM request path.
 *
 * Wraps a command (the real `claude`) with a local proxy that masks secrets in
 * the request body BEFORE it reaches the Anthropic API, so the model never sees
 * them. The model's RESPONSE is streamed back untouched. Lifecycle is tied to
 * the wrapped process — no daemon. FAIL OPEN everywhere: any parse/redact/upstream
 * error forwards the original bytes rather than breaking the model connection.
 *
 * Installed to ~/.solongate/hooks/shield.mjs and invoked by the `claude` shim
 * that `login` adds to the shell so every terminal session is masked automatically:
 *   node ~/.solongate/hooks/shield.mjs -- "<real claude>" <args...>
 *
 * Logic mirrors src/shield.ts — keep the two in sync.
 */
import { createServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { spawn } from 'node:child_process';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { homedir } from 'node:os';

// Bump on every shield.mjs change. The cloud serves the newest version; the
// guard hook installs it on its next run (no re-login needed).
const HOOK_VERSION = 7;

const log = (...a) => process.stderr.write(`[SolonGate shield] ${a.map(String).join(' ')}\n`);

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

// Find the policy cache to read. The guard writes one per agent
// (.policy-cache-<agent>.json) - the shield wraps `claude` and doesn't know the
// agent id, so unless SOLONGATE_AGENT_ID is set it picks the MOST RECENTLY
// written cache (the active session's). A fixed 'default' missed the guard's
// real cache, so custom patterns never reached the shield.
function findCacheFile() {
  const dir = resolve(homedir(), '.solongate');
  const envSel = process.env.SOLONGATE_AGENT_ID;
  if (envSel) {
    const f = resolve(dir, '.policy-cache-' + envSel.replace(/[^a-zA-Z0-9_-]/g, '_') + '.json');
    if (existsSync(f)) return f;
  }
  let best = null, bestTs = -1;
  try {
    for (const name of readdirSync(dir)) {
      if (name.startsWith('.policy-cache-') && name.endsWith('.json')) {
        const full = resolve(dir, name);
        const ts = statSync(full).mtimeMs;
        if (ts > bestTs) { bestTs = ts; best = full; }
      }
    }
  } catch { /* dir missing */ }
  return best;
}

function loadCfg() {
  try {
    const f = findCacheFile();
    if (f && existsSync(f)) {
      const c = JSON.parse(readFileSync(f, 'utf-8'));
      const d = c && c.security && c.security.dlpRedact;
      const g = c && c.security && c.security.ghost;
      const ghost = g && Array.isArray(g.patterns) ? g.patterns : [];
      if (d && Array.isArray(d.patterns)) return { patterns: d.patterns, custom: Array.isArray(d.custom) ? d.custom : [], ghost };
      return { patterns: DLP_PATTERNS.map((p) => p.name), custom: [], ghost };
    }
  } catch { /* default below */ }
  return { patterns: DLP_PATTERNS.map((p) => p.name), custom: [], ghost: [] };
}

// Ghost paths: hidden files/dirs the model must not even see exist. The audit
// PostToolUse hook strips them per tool shape, but that depends on parsing each
// tool's response. The shield sits on the request path where EVERY tool result
// is already a plain string, so stripping here catches every listing shape
// (Glob/LS/Grep/MCP/Bash) uniformly. Glob mirrors policy/audit: `*` = any run of
// non-slash, `**` = any run. Anchored, so a pattern matches a whole path segment.
function ghostGlobToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') { if (glob[i + 1] === '*') { re += '.*'; i++; } else re += '[^/]*'; }
    else if (c === '?') re += '[^/]';
    else if ('\\^$.|+()[]{}'.indexOf(c) !== -1) re += '\\' + c;
    else re += c;
  }
  try { return new RegExp('^' + re + '$'); } catch { return null; }
}
function ghostMatch(targetPath, patterns) {
  if (!targetPath || !Array.isArray(patterns) || patterns.length === 0) return false;
  const norm = String(targetPath).replace(/\\/g, '/').replace(/\/+$/, '');
  if (!norm) return false;
  const segments = norm.split('/').filter(Boolean);
  const base = segments.length ? segments[segments.length - 1] : norm;
  for (let pat of patterns) {
    pat = String(pat || '').trim();
    if (!pat) continue;
    let dirOnly = false;
    if (pat.endsWith('/')) { dirOnly = true; pat = pat.slice(0, -1); }
    if (!pat) continue;
    const hasSlash = pat.indexOf('/') !== -1;
    const hasWild = /[*?]/.test(pat);
    const re = ghostGlobToRegExp(pat);
    if (!re) continue;
    if (dirOnly) {
      if (!hasSlash && !hasWild) { if (segments.indexOf(pat) !== -1) return true; continue; }
      let acc = '';
      for (const s of segments) { acc = acc ? acc + '/' + s : s; if (re.test(acc) || re.test(s)) return true; }
      continue;
    }
    if (!hasSlash) {
      if (re.test(base)) return true;
      if (segments.some((s) => re.test(s))) return true;
      continue;
    }
    if (re.test(norm)) return true;
  }
  return false;
}
function ghostCleanToken(tok) {
  let t = String(tok || '').trim();
  t = t.replace(/^[<>|;&(]+/, '').replace(/[);&|]+$/, '');
  t = t.replace(/^['"]+/, '').replace(/['"]+$/, '');
  t = t.replace(/^\d*>>?/, '');
  return t.trim();
}
// Drop any line that references a ghost entry (full-path listings, ls -l rows,
// space-separated names). Same logic as audit.mjs ghostStripLines.
function ghostStripLines(text, pats) {
  if (!Array.isArray(pats) || pats.length === 0) return text;
  const lines = String(text).split('\n');
  const kept = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) { kept.push(line); continue; }
    if (ghostMatch(trimmed, pats)) continue;
    const toks = trimmed.split(/\s+/);
    const anyHit = toks.some((t) => ghostMatch(ghostCleanToken(t), pats));
    if (!anyHit) { kept.push(line); continue; }
    if (toks.length > 3) continue;
    const remaining = toks.filter((t) => !ghostMatch(ghostCleanToken(t), pats));
    if (remaining.length === 0) continue;
    kept.push(remaining.join('  '));
  }
  return kept.join('\n');
}

// Custom patterns are GLOBs: `*` = any run of non-whitespace, same as policy/ghost.
function dlpGlobToRe(glob, flags) {
  let re = '';
  for (const ch of String(glob || '')) {
    if (ch === '*') re += '[^\\s]*';
    else if ('.+?^${}()|[]\\'.indexOf(ch) !== -1) re += '\\' + ch;
    else re += ch;
  }
  return new RegExp(re, flags);
}
function redactString(s, cfg) {
  if (!cfg || typeof s !== "string" || !s) return s;
  const allow = new Set(cfg.patterns);
  const NUL = String.fromCharCode(0);
  const labels = [];
  const stash = (label) => NUL + (labels.push(label) - 1) + NUL;
  let out = s;
  for (const p of DLP_PATTERNS) if (allow.has(p.name)) out = out.replace(p.re, () => stash(`[REDACTED: ${p.name}]`));
  for (const c of cfg.custom) {
    try { out = out.replace(dlpGlobToRe(c.re, "gi"), () => stash(`[REDACTED: ${c.name || "custom"}]`)); } catch {}
  }
  return out.replace(new RegExp(NUL + "(\\d+)" + NUL, "g"), (_, i) => labels[+i] || "");
}

function redactDeep(value, cfg) {
  const ghost = cfg && Array.isArray(cfg.ghost) ? cfg.ghost : null;
  if (typeof value === 'string') {
    let out = redactString(value, cfg);
    if (ghost && ghost.length) out = ghostStripLines(out, ghost);
    return out;
  }
  if (Array.isArray(value)) {
    // Drop array elements that are themselves a whole ghost path (e.g. a Glob
    // result delivered as one-path-per-element), so no empty husk remains.
    const arr = ghost && ghost.length
      ? value.filter((v) => !(typeof v === 'string' && ghostMatch(v.trim(), ghost)))
      : value;
    return arr.map((v) => redactDeep(v, cfg));
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v, cfg);
    return out;
  }
  return value;
}

function pickUpstream() {
  const raw = process.env.SOLONGATE_SHIELD_UPSTREAM || process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com';
  try { return new URL(raw); } catch { return new URL('https://api.anthropic.com'); }
}

function startProxy(upstream) {
  const forward = upstream.protocol === 'https:' ? httpsRequest : httpRequest;
  const server = createServer((req, res) => {
    // Re-read the DLP config on every request (cheap: a small JSON) so changing
    // DLP mode / patterns in the dashboard takes effect WITHOUT restarting claude —
    // the guard rewrites this cache within ~one call, matching how the audit hook
    // already re-reads per call. Loading once at startup left the shield stale.
    const cfg = loadCfg();
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = Buffer.concat(chunks);
      try {
        if (body.length && String(req.headers['content-type'] || '').includes('json')) {
          const parsed = JSON.parse(body.toString('utf-8'));
          // Redact EVERY request, not just the last message. Claude Code re-sends
          // the ORIGINAL (unredacted) conversation on every call — it stores the raw
          // history and rebuilds the request each time, so the shield must re-scan
          // it every request. Redacting only the newest message leaked any secret
          // sitting in an earlier message: the user's own turn often lands at
          // messages[0] with later messages after it, and a one-shot `-p` run has no
          // prior request in which history could have been redacted. Scan the system
          // prompt and every USER-role message (fresh input + tool results like an
          // `ls`/Read result); skip ASSISTANT-role messages (model-generated prose —
          // the bulk of a long session and not a secret source) so cost stays low.
          if (parsed && typeof parsed === 'object' && Array.isArray(parsed.messages)) {
            if (parsed.system !== undefined) parsed.system = redactDeep(parsed.system, cfg);
            for (let i = 0; i < parsed.messages.length; i++) {
              const m = parsed.messages[i];
              if (m && m.role !== 'assistant') parsed.messages[i] = redactDeep(m, cfg);
            }
            body = Buffer.from(JSON.stringify(parsed), 'utf-8');
          } else {
            // Non-messages payload (rare) → redact it whole.
            body = Buffer.from(JSON.stringify(redactDeep(parsed, cfg)), 'utf-8');
          }
        }
      } catch { /* fail open */ }
      const headers = { ...req.headers };
      delete headers['host']; delete headers['content-length']; delete headers['accept-encoding'];
      headers['content-length'] = String(body.length);
      const upReq = forward({
        protocol: upstream.protocol,
        hostname: upstream.hostname,
        port: upstream.port || (upstream.protocol === 'https:' ? 443 : 80),
        method: req.method,
        path: req.url,
        headers: { ...headers, host: upstream.host },
      }, (upRes) => { res.writeHead(upRes.statusCode || 502, upRes.headers); upRes.pipe(res); });
      upReq.on('error', (e) => {
        log('upstream error:', e.message);
        if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
        res.end('shield upstream error');
      });
      upReq.end(body);
    });
    req.on('error', () => { try { res.destroy(); } catch { /* ignore */ } });
  });
  return new Promise((resolveP) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolveP({ port: addr && typeof addr === 'object' ? addr.port : 0, close: () => server.close() });
    });
  });
}

async function main() {
  const sep = process.argv.indexOf('--');
  const cmd = sep !== -1 ? process.argv.slice(sep + 1) : [];
  if (cmd.length === 0) { log('usage: node shield.mjs -- <command> [args...]'); process.exit(1); }
  const upstream = pickUpstream();
  const { port, close } = await startProxy(upstream);
  const child = spawn(cmd[0], cmd.slice(1), {
    stdio: 'inherit',
    env: { ...process.env, ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}` },
    shell: process.platform === 'win32',
  });
  const shutdown = () => { try { close(); } catch { /* ignore */ } };
  child.on('exit', (code, signal) => { shutdown(); if (signal) process.kill(process.pid, signal); else process.exit(code ?? 0); });
  child.on('error', (e) => { log('failed to launch command:', e.message); shutdown(); process.exit(1); });
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { try { child.kill(sig); } catch { /* ignore */ } });
}

main();

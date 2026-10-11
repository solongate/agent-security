#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

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
 * There is no second implementation of this one: the Go guard covers the tool path,
 * and the LLM path is this file alone. (It used to say "logic mirrors src/shield.ts";
 * that file is gone.)
 */
import { createServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';

import { DLP_PATTERN_NAMES, dlpGlobToRe, dlpPatterns } from './dlp.mjs';
// Bump on every shield.mjs change. The cloud serves the newest version; the
// guard hook installs it on its next run (no re-login needed).
// 10 stops this writing into the agent's terminal. Everything after the child
// is launched goes to ~/.solongate/shield.log, because the frame on screen
// belongs to the agent and a line printed into it is corruption rather than a
// message: it lands in the input box and the next keystroke overwrites half
// of it. See log().
//
// 8 collapses a run of `*` in a custom DLP glob before compiling it. That is a
// HANG fix on the path every prompt travels, so an installed shield must pick it
// up: see dlpGlobToRe.
const HOOK_VERSION = 10;

// WHERE THIS WRITES CHANGES THE MOMENT THE AGENT STARTS, and it has to.
//
// Before the child is launched this process owns the terminal and stderr is
// exactly right: a usage line or a failure to launch is the only thing the
// person is waiting for.
//
// After the child is launched the terminal belongs to the AGENT, which is a
// full-screen program drawing its own frame. A line written into that frame is
// not a log message, it is corruption: it lands in the input box, the next
// keystroke overwrites half of it, and it survives until something redraws.
// One of these arrived as `[SolonGate shield] upstream error: read ECONNRESET`
// in the middle of somebody's prompt.
//
// So the file takes over. The proxy runs for the whole session and an upstream
// reset is a thing that happens on a long one; it is worth recording and it is
// not worth interrupting anybody for.
let liveChild = false;

const log = (...a) => {
  const line = `[SolonGate shield] ${a.map(String).join(' ')}\n`;
  if (!liveChild) { process.stderr.write(line); return; }
  try {
    const dir = join(homedir(), '.solongate');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = join(dir, 'shield.log');
    // Trimmed rather than rotated. A reset per minute on a long session would
    // otherwise be an unbounded file nobody ever looks at, and the only part
    // worth having is the recent end.
    try { if (statSync(file).size > 262144) writeFileSync(file, '', { mode: 0o600 }); } catch { /* first write */ }
    appendFileSync(file, `${new Date().toISOString()} ${line}`, { mode: 0o600 });
  } catch { /* a shield that cannot log still shields */ }
};
// THE PATTERN LIST LIVES IN ./dlp.mjs, one copy for the three hooks that scan.
//
// Each of them carried its own, and they had drifted: the guard had 70 and each hook had
// 14 — so on a machine without the Go binary, which is the default, a policy asking for
// most of the list was enforcing nothing. Compiled here with the flags THIS hook needs:
// `g`, because this REPLACES every occurrence — without it only the first
// secret in a file is masked and the rest reach the model.
const DLP_PATTERNS = dlpPatterns('g');

// ── What to redact comes from the policy file ────────────────────────────────
//
// This used to hunt for a policy CACHE: `.policy-cache-<agent>.json`, and because the
// shield wraps `claude` and does not know the agent id, it picked the most recently
// written one of them unless SOLONGATE_AGENT_ID named one. Nothing writes that cache
// any more, and the fallback when it found none was
//
//     return { patterns: DLP_PATTERNS.map((p) => p.name), custom: [] };
//
// — every built-in pattern and NO CUSTOM ONES. So a custom pattern in somebody's
// policy was enforced by the guard, enforced by the audit hook, and silently ignored
// on the one surface that sees the prompt itself. A custom pattern is what somebody
// adds for a secret shaped like their own company's tokens, which is exactly the
// thing the built-in list cannot know about.
//
// The file is read in both spellings the guard accepts, and `dlpBlock` counts as
// redaction: a file written by hand usually carries only `dlpBlock`, which reads as
// "refuse secrets", and taking `dlpRedact` alone gave that file no masking here.
//
// DETECT RETURNS NULL, and that is a different answer from "nothing configured".
//
// The fallback below masks with EVERY built-in pattern, and it is right for the
// case it was written for. But `dlpObserve` is DLP CONFIGURED, in a mode whose
// whole content is that it records a hit and changes nothing anybody sees, and
// falling through to the default made detect mask MORE than redact does: every
// built-in instead of the chosen list. That is the loudest possible way to get a
// mode backwards, and it is why a detect-mode read still came back masked after
// the guard and the post-tool hook had both been taught to leave it alone.
// Three redactors, and the third had an opinion of its own.
//
// Null means "do not touch the text". Absent config still means "mask
// everything": an unconfigured machine has made no choice to respect.
//
// The fallback is unchanged and deliberate: WITH NO POLICY AT ALL, every built-in
// pattern is masked. The shield is the LLM path — there is no call to allow or deny,
// only text on its way to a model — so the safe default is to mask, and a machine
// that has not configured anything still does not leak its keys into a prompt.
function loadCfg() {
  const defaults = () => ({ patterns: DLP_PATTERNS.map((p) => p.name), custom: [] });
  try {
    const p = resolve(homedir(), '.solongate', 'policy.json');
    if (!existsSync(p)) return defaults();
    const obj = JSON.parse(readFileSync(p, 'utf-8'));
    if (!obj || typeof obj !== 'object') return defaults();
    const sec = (obj.security && typeof obj.security === 'object') ? obj.security
      : (obj.policy && obj.policy.security && typeof obj.policy.security === 'object') ? obj.policy.security
        : null;
    if (!sec) return defaults();
    const d = sec.dlpRedact || sec.dlpBlock;
    if (!d || !Array.isArray(d.patterns)) {
      // Configured, and the mode says do not rewrite anything.
      if (sec.dlpObserve && Array.isArray(sec.dlpObserve.patterns)) return null;
      return defaults();
    }
    return { patterns: d.patterns, custom: Array.isArray(d.custom) ? d.custom : [] };
  } catch { return defaults(); }
}

// dlpGlobToRe is in ./dlp.mjs too: three copies of one converter, and the reason it
// collapses a run of stars is a HANG on a pattern somebody types.
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
  if (typeof value === 'string') return redactString(value, cfg);
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, cfg));
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
    // Re-read the DLP config on every request (cheap: a small JSON) so editing the
    // policy file takes effect WITHOUT restarting claude — the audit hook re-reads per
    // call for the same reason. Loading once at startup left the shield stale for the
    // life of a session, which can be a whole day.
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
  // From here the terminal is the agent's. See log().
  liveChild = true;

  const shutdown = () => { try { close(); } catch { /* ignore */ } };
  child.on('exit', (code, signal) => { shutdown(); if (signal) process.kill(process.pid, signal); else process.exit(code ?? 0); });
  // Back to stderr for this one: a child that never started never took the
  // terminal, and the person is still looking at a shell prompt waiting to be
  // told why nothing happened.
  child.on('error', (e) => { liveChild = false; log('failed to launch command:', e.message); shutdown(); process.exit(1); });
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { try { child.kill(sig); } catch { /* ignore */ } });
}

main();

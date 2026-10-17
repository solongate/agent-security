#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

import { createServer, request as httpRequest } from 'node:http';
import { createServer as createTLSServer } from 'node:tls';
import { execFileSync } from 'node:child_process';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';

import { DLP_PATTERN_NAMES, dlpGlobToRe, dlpPatterns } from './dlp.mjs';
const HOOK_VERSION = 10;

let liveChild = false;

const log = (...a) => {
  const line = `[SolonGate shield] ${a.map(String).join(' ')}\n`;
  if (!liveChild) { process.stderr.write(line); return; }
  try {
    const dir = join(homedir(), '.solongate');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = join(dir, 'shield.log');
    try { if (statSync(file).size > 262144) writeFileSync(file, '', { mode: 0o600 }); } catch {  }
    appendFileSync(file, `${new Date().toISOString()} ${line}`, { mode: 0o600 });
  } catch {  }
};
const DLP_PATTERNS = dlpPatterns('g');

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
      if (sec.dlpObserve && Array.isArray(sec.dlpObserve.patterns)) return null;
      return defaults();
    }
    return { patterns: d.patterns, custom: Array.isArray(d.custom) ? d.custom : [] };
  } catch { return defaults(); }
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

const SHIELD_TOKEN = randomBytes(32).toString('hex');

function tokenOK(url) {
  const want = '/' + SHIELD_TOKEN;
  if (typeof url !== 'string' || url.length < want.length + 1) return false;
  if (url[want.length] !== '/' && url[want.length] !== '?') return false;
  const got = Buffer.from(url.slice(0, want.length), 'utf-8');
  const exp = Buffer.from(want, 'utf-8');
  if (got.length !== exp.length) return false;
  try { return timingSafeEqual(got, exp); } catch { return false; }
}


function makeCert(dir) {
  const key = join(dir, 'shield-key.pem');
  const crt = join(dir, 'shield-cert.pem');
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', key, '-out', crt,
      '-days', '1',
      '-subj', '/CN=127.0.0.1',
      '-addext', 'subjectAltName=IP:127.0.0.1',
    ], { stdio: 'ignore', timeout: 10000 });
    const k = readFileSync(key);
    const c = readFileSync(crt);
    rmSync(key, { force: true });
    return { key: k, cert: c, certPath: crt };
  } catch (e) {
    log('no certificate (' + (e && e.message ? e.message : 'openssl failed') + '), the local hop is http');
    rmSync(key, { force: true });
    rmSync(crt, { force: true });
    return null;
  }
}

function startProxy(upstream, tls) {
  const forward = upstream.protocol === 'https:' ? httpsRequest : httpRequest;
  const handler = (req, res) => {
    if (!tokenOK(req.url)) {
      log('refused a request without the run token:', String(req.method || '?'));
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
      req.resume();
      return;
    }
    const cfg = loadCfg();
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = Buffer.concat(chunks);
      try {
        if (body.length && String(req.headers['content-type'] || '').includes('json')) {
          const parsed = JSON.parse(body.toString('utf-8'));
          if (parsed && typeof parsed === 'object' && Array.isArray(parsed.messages)) {
            if (parsed.system !== undefined) parsed.system = redactDeep(parsed.system, cfg);
            for (let i = 0; i < parsed.messages.length; i++) {
              const m = parsed.messages[i];
              if (m && m.role !== 'assistant') parsed.messages[i] = redactDeep(m, cfg);
            }
            body = Buffer.from(JSON.stringify(parsed), 'utf-8');
          } else {
            body = Buffer.from(JSON.stringify(redactDeep(parsed, cfg)), 'utf-8');
          }
        }
      } catch {  }
      const headers = { ...req.headers };
      delete headers['host']; delete headers['content-length']; delete headers['accept-encoding'];
      headers['content-length'] = String(body.length);
      const upReq = forward({
        protocol: upstream.protocol,
        hostname: upstream.hostname,
        port: upstream.port || (upstream.protocol === 'https:' ? 443 : 80),
        method: req.method,
        path: req.url.slice(1 + SHIELD_TOKEN.length) || '/',
        headers: { ...headers, host: upstream.host },
      }, (upRes) => { res.writeHead(upRes.statusCode || 502, upRes.headers); upRes.pipe(res); });
      upReq.on('error', (e) => {
        log('upstream error:', e.message);
        if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
        res.end('shield upstream error');
      });
      upReq.end(body);
    });
    req.on('error', () => { try { res.destroy(); } catch {  } });
  };

  const server = createServer(tls ? { key: tls.key, cert: tls.cert } : {}, handler);
  if (tls) {
    const secure = createTLSServer({ key: tls.key, cert: tls.cert });
    secure.on('secureConnection', (socket) => server.emit('connection', socket));
    return new Promise((resolveP) => {
      secure.listen(0, '127.0.0.1', () => {
        const addr = secure.address();
        resolveP({
          port: addr && typeof addr === 'object' ? addr.port : 0,
          scheme: 'https',
          close: () => { try { secure.close(); } catch {  } server.close(); },
        });
      });
    });
  }
  return new Promise((resolveP) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolveP({
        port: addr && typeof addr === 'object' ? addr.port : 0,
        scheme: 'http',
        close: () => server.close(),
      });
    });
  });
}

async function main() {
  const sep = process.argv.indexOf('--');
  const cmd = sep !== -1 ? process.argv.slice(sep + 1) : [];
  if (cmd.length === 0) { log('usage: node shield.mjs -- <command> [args...]'); process.exit(1); }
  const upstream = pickUpstream();

  const tls = makeCert(join(homedir(), '.solongate'));
  const { port, scheme, close } = await startProxy(upstream, tls);
  const child = spawn(cmd[0], cmd.slice(1), {
    stdio: 'inherit',
    env: {
      ...process.env,
      ANTHROPIC_BASE_URL: `${scheme}://127.0.0.1:${port}/${SHIELD_TOKEN}`,
      ...(tls ? { NODE_EXTRA_CA_CERTS: tls.certPath } : {}),
    },
    shell: process.platform === 'win32',
  });
  liveChild = true;

  const shutdown = () => {
    try { close(); } catch {  }
    if (tls) { try { rmSync(tls.certPath, { force: true }); } catch {  } }
  };
  child.on('exit', (code, signal) => { shutdown(); if (signal) process.kill(process.pid, signal); else process.exit(code ?? 0); });
  child.on('error', (e) => { liveChild = false; log('failed to launch command:', e.message); shutdown(); process.exit(1); });
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { try { child.kill(sig); } catch {  } });
}

main().catch((e) => { log('fatal:', e.message); process.exit(1); });
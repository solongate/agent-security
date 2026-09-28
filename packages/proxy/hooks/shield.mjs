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
// 8 collapses a run of `*` in a custom DLP glob before compiling it. That is a
// HANG fix on the path every prompt travels, so an installed shield must pick it
// up: see dlpGlobToRe.
const HOOK_VERSION = 9;

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

  // Kept in step with packages/guard-go/dlp.go, name for name and
  // expression for expression. The two lists had drifted to 14 here
  // against 74 there, and a name this list does not carry silently stops
  // being enforced on every machine that runs the hook rather than the
  // binary — which is every machine by default. dlp-parity.mjs holds them
  // together now.
  { name: 'Google API key', re: /AIza[0-9A-Za-z_-]{35}/g },
  { name: 'Slack webhook', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/_+-]{40,}/g },
  { name: 'Twilio account SID', re: /AC[0-9a-fA-F]{32}/g },
  { name: 'Mailgun key', re: /key-[0-9a-f]{32}/g },
  { name: 'Mailchimp key', re: /[0-9a-f]{32}-us[0-9]{1,2}/g },
  { name: 'DigitalOcean token', re: /dop_v1_[0-9a-f]{64}/g },
  { name: 'Databricks token', re: /dapi[0-9a-f]{32}/g },
  { name: 'Shopify token', re: /shp(at|ca|pa|ss)_[0-9a-fA-F]{32}/g },
  { name: 'Square token', re: /sq0(atp|csp)-[0-9A-Za-z_-]{22,43}/g },
  { name: 'Telegram bot token', re: /[0-9]{8,10}:AA[0-9A-Za-z_-]{33}/g },
  { name: 'Postman key', re: /PMAK-[0-9a-f]{24}-[0-9a-f]{34}/g },
  { name: 'Doppler token', re: /dp\.(pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}/g },
  { name: 'HashiCorp Vault token', re: /hvs\.[A-Za-z0-9_-]{24,}/g },
  { name: 'New Relic key', re: /NRAK-[A-Z0-9]{27}/g },
  { name: 'Grafana token', re: /glc_[A-Za-z0-9+\/=_-]{32,}/g },
  { name: 'Razorpay key', re: /rzp_(live|test)_[0-9A-Za-z]{14}/g },
  { name: 'Linear key', re: /lin_api_[0-9A-Za-z]{40,}/g },
  { name: 'Figma token', re: /figd_[0-9A-Za-z_-]{40,}/g },
  { name: 'Atlassian token', re: /ATATT3[0-9A-Za-z_=.-]{20,}/g },
  { name: 'Google OAuth token', re: /ya29\.[0-9A-Za-z_-]{50,}/g },
  { name: 'Google OAuth refresh', re: /1\/\/0[0-9A-Za-z_-]{30,}/g },
  { name: 'Alibaba access key', re: /LTAI[0-9A-Za-z]{20}/g },
  { name: 'Tencent secret id', re: /AKID[0-9A-Za-z]{13,40}/g },
  { name: 'Hugging Face token', re: /hf_[0-9A-Za-z]{34,}/g },
  { name: 'Replicate token', re: /r8_[0-9A-Za-z]{37,}/g },
  { name: 'Groq key', re: /gsk_[0-9A-Za-z]{48,}/g },
  { name: 'OpenRouter key', re: /sk-or-v1-[0-9a-f]{64}/g },
  { name: 'Perplexity key', re: /pplx-[0-9A-Za-z]{40,}/g },
  { name: 'xAI key', re: /xai-[0-9A-Za-z]{40,}/g },
  { name: 'LangSmith key', re: /lsv2_(pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}/g },
  { name: 'Stripe webhook secret', re: /whsec_[0-9A-Za-z]{32,}/g },
  { name: 'Plaid token', re: /access-(sandbox|development|production)-[0-9a-f-]{36}/g },
  { name: 'Braintree token', re: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g },
  { name: 'Discord bot token', re: /[MNO][0-9A-Za-z_-]{23}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27}/g },
  { name: 'Discord webhook', re: /https:\/\/discord(app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[0-9A-Za-z_-]{60,}/g },
  { name: 'Slack app token', re: /xapp-[0-9]-[0-9A-Za-z]+-[0-9]+-[0-9a-f]+/g },
  { name: 'Sentry DSN', re: /https:\/\/[0-9a-f]{32}@[0-9a-z.-]+sentry\.io\/[0-9]+/g },
  { name: 'Supabase token', re: /sbp_[0-9a-f]{40}/g },
  { name: 'PlanetScale token', re: /pscale_tkn_[0-9A-Za-z._-]{32,}/g },
  { name: 'PlanetScale password', re: /pscale_pw_[0-9A-Za-z._-]{32,}/g },
  { name: 'Airtable token', re: /pat[0-9A-Za-z]{14}\.[0-9a-f]{64}/g },
  { name: 'Cloudinary URL', re: /cloudinary:\/\/[0-9]{12,}:[0-9A-Za-z_-]{20,}@[0-9a-z-]+/g },
  { name: 'MongoDB SRV URI', re: /mongodb\+srv:\/\/[^\s:@]+:[^\s:@]+@[0-9a-z.-]+/g },
  { name: 'Terraform Cloud token', re: /[0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z_-]{60,}/g },
  { name: 'PyPI token', re: /pypi-AgEIcHlwaS[0-9A-Za-z_-]{50,}/g },
  { name: 'RubyGems key', re: /rubygems_[0-9a-f]{48}/g },
  { name: 'NuGet key', re: /oy2[a-z0-9]{43}/g },
  { name: 'Docker Hub token', re: /dckr_pat_[0-9A-Za-z_-]{27,}/g },
  { name: 'Notion token', re: /ntn_[0-9A-Za-z]{40,}/g },
  { name: 'Dropbox token', re: /sl\.[0-9A-Za-z_-]{130,}/g },
  { name: 'Sentry auth token', re: /sntrys_[0-9A-Za-z_=+\/-]{40,}/g },
  { name: 'Contentful token', re: /CFPAT-[0-9A-Za-z_-]{40,}/g },
  { name: 'Typeform token', re: /tfp_[0-9A-Za-z_-]{40,}/g },
  { name: 'Pinecone key', re: /pcsk_[0-9A-Za-z_-]{40,}/g },
  { name: 'WooCommerce key', re: /c[ks]_[0-9a-f]{40}/g },
  { name: 'PostHog key', re: /ph[cs]_[0-9A-Za-z]{40,}/g },
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
      if (d && Array.isArray(d.patterns)) return { patterns: d.patterns, custom: Array.isArray(d.custom) ? d.custom : [] };
      return { patterns: DLP_PATTERNS.map((p) => p.name), custom: [] };
    }
  } catch { /* default below */ }
  return { patterns: DLP_PATTERNS.map((p) => p.name), custom: [] };
}

// Custom patterns are GLOBs: `*` = any run of non-whitespace, same as the policy layer.
//
// A RUN of `*` collapses to one, and that is a fix rather than a tidy-up. `*`
// becomes `[^\s]*`, so `**` became two unbounded quantifiers over the same
// character class back to back, which backtracks catastrophically: measured on
// this converter, six stars cost 0.9s and ten cost four minutes. The shield is
// the worst place for it — this runs over the whole REQUEST BODY on its way to
// the model, prompt included — and the pattern is one somebody types.
// Collapsing changes nothing about what a glob accepts, because `[^\s]*[^\s]*`
// matches exactly the strings `[^\s]*` matches. Kept identical in the guard and
// the audit hook, which carry the same converter.
function dlpGlobToRe(glob, flags) {
  let re = '';
  for (const ch of String(glob || '').replace(/\*{2,}/g, '*')) {
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

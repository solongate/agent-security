#!/usr/bin/env node
/**
 * Record what the live API answers on every route, so a cutover can be judged
 * by comparison instead of by looking at it and feeling fine.
 *
 * The route list is READ OUT OF apps/system rather than typed here, so a route
 * this file does not know about cannot quietly go unchecked.
 *
 *   node tools/api-snapshot.mjs before.json          # record
 *   node tools/api-snapshot.mjs after.json           # record again
 *   node tools/api-snapshot.mjs --diff before.json after.json
 *
 * Runs UNAUTHENTICATED on purpose. That sounds like it tests nothing, but it is
 * most of what a wrong deploy breaks: the shape of a 401, whether a missing key
 * is 401 or 500, whether CORS headers survive, whether an unknown path is 404
 * rather than a stack trace. Every caller in this system hits that surface on
 * its way in, and it needs no credentials to check.
 *
 * What it deliberately does NOT do: send a real API key. Authenticated bodies
 * carry a project's audit rows and policies, and a snapshot file is the wrong
 * place for those.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BASE = process.env.API_BASE || 'http://127.0.0.1:3002';

function routes() {
  const out = execFileSync('grep', [
    '-rhno', '--include=*.go',
    '-e', '"\\(GET\\|POST\\|PUT\\|PATCH\\|DELETE\\) /[^"]*"',
    join(repo, 'apps/system'),
  ]).toString();
  const seen = new Set();
  for (const line of out.split('\n')) {
    const m = line.match(/"((?:GET|POST|PUT|PATCH|DELETE) \/[^"]*)"/);
    if (m) seen.add(m[1]);
  }
  return [...seen].sort();
}

// A wildcard needs SOME value to be requested. These are deliberately values no
// project owns, so a route that answers 200 to them is the finding.
const FILLERS = { id: 'sg-snapshot-nonexistent', ruleId: 'sg-snapshot-nonexistent', name: 'sg-snapshot-nonexistent' };
const fill = (p) => p.replace(/\{(\w+)\}/g, (_, k) => FILLERS[k] ?? 'x');

async function probe(method, path) {
  const url = BASE + fill(path);
  const started = Date.now();
  try {
    const res = await fetch(url, {
      method,
      redirect: 'manual',
      headers: { 'content-type': 'application/json', origin: process.env.ORIGIN || 'http://127.0.0.1:3005' },
      // A body on the write methods so a handler that parses one is reached
      // rather than short-circuiting on an empty stream.
      body: ['POST', 'PUT', 'PATCH'].includes(method) ? '{}' : undefined,
      signal: AbortSignal.timeout(20000),
    });
    const text = await res.text();
    return {
      status: res.status,
      // The body shape, not the body: ids and timestamps differ between two
      // runs for reasons that are not a regression.
      body: shape(text),
      cors: res.headers.get('access-control-allow-origin') ?? null,
      type: (res.headers.get('content-type') ?? '').split(';')[0],
      ms: Date.now() - started,
    };
  } catch (e) {
    return { status: 0, body: 'ERROR: ' + e.message, cors: null, type: '', ms: Date.now() - started };
  }
}

/**
 * Reduce a response to something two deploys can be expected to agree on.
 *
 * Keys and the SHAPE of values, with every scalar replaced by its type. An
 * error message stays verbatim because its wording is the contract a caller
 * reads; that is the one place a port is most likely to drift and most likely
 * to be noticed by a user.
 */
function shape(text) {
  let v;
  try { v = JSON.parse(text); } catch { return 'non-json:' + text.slice(0, 120); }
  const walk = (x, depth = 0) => {
    if (x === null) return 'null';
    if (Array.isArray(x)) return depth > 4 ? '[…]' : (x.length ? [walk(x[0], depth + 1)] : []);
    if (typeof x === 'object') {
      if (depth > 4) return '{…}';
      const o = {};
      for (const k of Object.keys(x).sort()) {
        o[k] = (k === 'error' || k === 'message' || k === 'code') && typeof x[k] === 'string' ? x[k] : walk(x[k], depth + 1);
      }
      return o;
    }
    return typeof x;
  };
  return JSON.stringify(walk(v));
}

if (process.argv[2] === '--diff') {
  const a = JSON.parse(readFileSync(process.argv[3], 'utf-8'));
  const b = JSON.parse(readFileSync(process.argv[4], 'utf-8'));
  const keys = [...new Set([...Object.keys(a.routes), ...Object.keys(b.routes)])].sort();
  let same = 0;
  const diffs = [];
  for (const k of keys) {
    const x = a.routes[k], y = b.routes[k];
    if (!x || !y) { diffs.push({ route: k, why: !x ? 'only in after' : 'only in before' }); continue; }
    const changed = [];
    if (x.status !== y.status) changed.push(`status ${x.status} -> ${y.status}`);
    if (x.body !== y.body) changed.push(`body ${x.body} -> ${y.body}`);
    if (x.cors !== y.cors) changed.push(`cors ${x.cors} -> ${y.cors}`);
    if (x.type !== y.type) changed.push(`type ${x.type} -> ${y.type}`);
    if (changed.length) diffs.push({ route: k, changed }); else same++;
  }
  console.log(`${same} identical, ${diffs.length} changed\n`);
  for (const d of diffs) {
    console.log('  ' + d.route);
    for (const c of d.changed ?? [d.why]) console.log('      ' + c);
  }
  process.exit(diffs.length ? 1 : 0);
}

const list = routes();
console.error(`probing ${list.length} routes at ${BASE} …`);
const result = { base: BASE, routes: {} };
// Serial on purpose: this points at production and a burst of 80 requests is
// the kind of thing a rate limiter is supposed to notice.
for (const r of list) {
  const [method, path] = r.split(' ');
  result.routes[r] = await probe(method, path);
  process.stderr.write('.');
}
process.stderr.write('\n');

const codes = {};
for (const v of Object.values(result.routes)) codes[v.status] = (codes[v.status] ?? 0) + 1;
console.error('status codes:', Object.entries(codes).map(([k, v]) => `${k}×${v}`).join(' '));

writeFileSync(process.argv[2], JSON.stringify(result, null, 1));
console.error('wrote', process.argv[2]);

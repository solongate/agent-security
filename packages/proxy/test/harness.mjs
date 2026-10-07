// SPDX-License-Identifier: Apache-2.0

/**
 * Shared rig for the conformance suite.
 *
 * Everything here talks to the guard the way a CLIENT does — spawn it, write a
 * payload on stdin, read the exit code — so the tests keep working against any
 * implementation that honours the same contract. `SG_HOOK` points the suite at
 * a candidate build; with it unset the installed hook is used.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// THE HOOK IN THIS CHECKOUT, not the one installed on the machine.
//
// It used to default the other way round, and the result was a suite whose
// answer depended on a file outside the repository. Both directions have now
// cost real time: a runner has no installed hook, so five files failed against a
// path that does not exist and read as the guard being broken; and a laptop with
// an OLD installed hook reported three tamper failures for a fix that was
// present in the source all along.
//
// The bundled build is what ships — readGuard in global-install.ts prefers it,
// with opa-wasm inlined, and writes it out as the installed hook — so it is also
// what should be under test. SG_HOOK still points this at an installed copy on
// purpose, which is how you check an actual installation.
const BUNDLED = join(dirname(dirname(fileURLToPath(import.meta.url))), 'hooks', 'gu' + 'ard' + '.bundled.mjs');
export const HOOK = process.env.SG_HOOK
  || (existsSync(BUNDLED) ? BUNDLED : join(homedir(), '.solongate', 'hooks', 'gu' + 'ard' + '.mjs'));
export const AGENT = 'conformance';

// A key has to look real: the hook refuses to enforce anything without one, and
// a rejected key makes every test silently pass by allowing everything. That
// mistake cost an afternoon once — the first green run was measuring nothing.
export const FAKE_KEY = 'sg_live_' + 'abcdef0123456789'.repeat(3);

let failures = 0;
let current = '';

export function suite(name) {
  current = name;
  console.log(`\n${name}`);
}

export function check(label, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${label}${ok ? '' : `  got=${JSON.stringify(got)} want=${JSON.stringify(want)}`}`);
  return ok;
}

export function note(msg) {
  console.log(`       ${msg}`);
}

export function done() {
  console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILED`);
  return failures;
}

/** A throwaway HOME with a credential and a policy cache the guard will trust. */
/**
 * A machine set up the way the guard reads one: a policy file.
 *
 * It used to write a POLICY CACHE — `_ts`, a policy, a security block, the hook
 * versions a service reported — because that is where the guard looked first. There
 * is no cache any more: nothing writes one, so nothing reads one, and the file is
 * the single source. Seeding the file is also what a person does.
 *
 * `apiUrl` is still written into a credential, because a few tests point the hook
 * at a stub to prove NOTHING is sent to it.
 */
export function sandbox(name, { security = {}, policy = null, apiUrl = 'http://127.0.0.1:9' } = {}) {
  const home = join(tmpdir(), 'sg-conformance', name);
  try { rmSync(home, { recursive: true, force: true }); } catch { /* fresh anyway */ }
  mkdirSync(join(home, '.solongate'), { recursive: true });
  writeFileSync(join(home, '.solongate', 'cloud' + '-guard.json'), JSON.stringify({ apiKey: FAKE_KEY, apiUrl }));
  writeFileSync(join(home, '.solongate', 'poli' + 'cy.json'), JSON.stringify({
    policy, security, selfProtect: false,
  }));
  return home;
}

const payloadFor = (tool, input, cwd) => JSON.stringify({
  tool_name: tool, tool_input: input, session_id: 'conformance', tool_use_id: 'c1', cwd,
});

// The suite has to be able to point at either implementation, so how the hook is
// launched is derived from what it is: a script needs an interpreter, a compiled
// binary is the interpreter. Nothing else in the tests changes between them —
// that is the whole reason they are worth having.
const launch = HOOK.endsWith('.mjs') || HOOK.endsWith('.js')
  ? [process.execPath, [HOOK, AGENT, AGENT]]
  : [HOOK, [AGENT, AGENT]];

/** One tool call, synchronously. Never use this when a stub cloud is running. */
export function call(home, tool = 'bash', input = { command: 'echo x' }, cwd = home, extraEnv = {}) {
  const r = spawnSync(launch[0], launch[1], {
    input: payloadFor(tool, input, cwd),
    env: { ...process.env, HOME: home, SOLONGATE_AGENT_ID: AGENT, ...extraEnv },
    encoding: 'utf-8',
    timeout: 25000,
    cwd,
  });
  return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

/**
 * One tool call, asynchronously. Required whenever a stub cloud is involved:
 * spawnSync blocks the event loop the stub server runs on, so the guard's fetch
 * hangs on a server that cannot answer and the 8s backstop gets measured.
 */
export function callAsync(home, tool = 'bash', input = { command: 'echo x' }, cwd = home, extraEnv = {}) {
  return new Promise((resolve) => {
    const c = spawn(launch[0], launch[1], {
      env: { ...process.env, HOME: home, SOLONGATE_AGENT_ID: AGENT, ...extraEnv },
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd,
    });
    let stdout = '', stderr = '';
    c.stdout.on('data', (d) => { stdout += d; });
    c.stderr.on('data', (d) => { stderr += d; });
    c.on('close', (code) => resolve({ code, stdout, stderr }));
    c.stdin.end(payloadFor(tool, input, cwd));
  });
}

/** N calls fired at once — the shape that breaks counters. */
export function burst(home, n, tool = 'bash', input = { command: 'echo x' }) {
  return Promise.all(Array.from({ length: n }, () => callAsync(home, tool, input)));
}

/** Records every audit POST. `delayMs` stands in for a slow or distant API. */
export async function stubCloud({ delayMs = 0 } = {}) {
  const received = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      if (req.method === 'POST' && req.url.includes('audit')) {
        try { received.push(JSON.parse(body)); } catch { received.push({ raw: body.slice(0, 120) }); }
        setTimeout(() => { res.writeHead(200); res.end('{}'); }, delayMs);
        return;
      }
      if (req.url.includes('policies/active')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ policy: null, self_protection_enabled: false, security: {}, hook_versions: {} }));
        return;
      }
      res.writeHead(404); res.end('{}');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    received,
    close: () => server.close(),
  };
}

export function localLines(home, dir) {
  const f = join(dir ?? join(home, '.solongate', 'local-logs'), 'solongate-audit.jsonl');
  return existsSync(f) ? readFileSync(f, 'utf-8').split('\n').filter(Boolean) : [];
}

/**
 * Wait for the local audit log to reach `n` lines.
 *
 * The record is written by a DETACHED child — deliberately, so it survives the
 * client killing the guard mid-denial — which means "look once, right after the
 * call returned" measures the race and not the behaviour.
 */
export async function awaitLocalLines(home, n, dir, ms = 5000) {
  const until = Date.now() + ms;
  for (;;) {
    const lines = localLines(home, dir);
    if (lines.length >= n || Date.now() > until) return lines;
    await new Promise((r) => setTimeout(r, 50));
  }
}

export const DLP_AWS = { patterns: ['AWS access key'], custom: [] };
// Split so this file is not itself a DLP hit when an agent edits it.
export const AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';

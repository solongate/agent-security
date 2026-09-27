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
import { join } from 'node:path';

export const HOOK = process.env.SG_HOOK || join(homedir(), '.solongate', 'hooks', 'gu' + 'ard' + '.mjs');
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
export function sandbox(name, { security = {}, policy = null, apiUrl = 'http://127.0.0.1:9' } = {}) {
  const home = join(tmpdir(), 'sg-conformance', name);
  try { rmSync(home, { recursive: true, force: true }); } catch { /* fresh anyway */ }
  mkdirSync(join(home, '.solongate'), { recursive: true });
  writeFileSync(join(home, '.solongate', 'cloud' + '-guard.json'), JSON.stringify({ apiKey: FAKE_KEY, apiUrl }));
  writeFileSync(join(home, '.solongate', '.policy' + '-cache-' + AGENT + '.json'), JSON.stringify({
    _ts: Date.now(), policy, selfProtect: false, security, hookVersions: null,
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
export function call(home, tool = 'bash', input = { command: 'echo x' }, cwd = home) {
  const r = spawnSync(launch[0], launch[1], {
    input: payloadFor(tool, input, cwd),
    env: { ...process.env, HOME: home, SOLONGATE_AGENT_ID: AGENT },
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
export function callAsync(home, tool = 'bash', input = { command: 'echo x' }, cwd = home) {
  return new Promise((resolve) => {
    const c = spawn(launch[0], launch[1], {
      env: { ...process.env, HOME: home, SOLONGATE_AGENT_ID: AGENT },
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

export const DLP_AWS = { patterns: ['AWS access key'], custom: [] };
// Split so this file is not itself a DLP hit when an agent edits it.
export const AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';

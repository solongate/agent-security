#!/usr/bin/env node
/**
 * Brings the API up locally on its own port.
 *
 * It is built before it is started because a binary that was never compiled is
 * the classic way to spend twenty minutes on a change that never ran.
 *
 * Usage:
 *   node tools/dev-go.mjs
 *
 * Ctrl-C stops it.
 */
import { spawn, execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const only = argv.includes('--only') ? argv[argv.indexOf('--only') + 1] : null;

// The Go toolchain is not on the default PATH on every machine.
const HOME = process.env.HOME;
const env = {
  ...process.env,
  GOPATH: process.env.GOPATH || `${HOME}/go`,
  PATH: `${HOME}/go/bin:${HOME}/.local/go/bin:${HOME}/.local/opt/go/bin:${process.env.PATH}`,
};

// The port is the app's own default, so anything already pointed at a local
// install keeps working.
const APPS = [
  { name: 'api', dir: 'apps/api-go', port: 3002 },
];

const children = [];
const stopAll = () => {
  for (const c of children) { try { c.kill('SIGTERM'); } catch { /* already gone */ } }
};
process.on('SIGINT', () => { stopAll(); process.exit(0); });
process.on('exit', stopAll);

function build(app) {
  const dir = join(repo, app.dir);
  if (!existsSync(dir)) return { ok: false, why: 'no such directory' };
  try {
    execFileSync('go', ['build', '-o', '.dev-server', '.'], { cwd: dir, env, stdio: 'pipe' });
  } catch (e) {
    return { ok: false, why: `go build: ${(e.stderr || e.stdout || e.message).toString().trim().split('\n').slice(-6).join(' ')}` };
  }
  return { ok: true };
}

function start(app) {
  const dir = join(repo, app.dir);
  const c = spawn(join(dir, '.dev-server'), [], {
    cwd: dir,
    // PORT is the convention the app reads, and what a container sets too.
    env: { ...env, PORT: String(app.port) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  c.stdout.on('data', (d) => process.stdout.write(`[${app.name}] ${d}`));
  c.stderr.on('data', (d) => process.stderr.write(`[${app.name}] ${d}`));
  children.push(c);
}

/**
 * "Up" means something answered, whatever it answered.
 *
 * Not "answered below 500": a server that is listening and refusing every
 * request for want of configuration is still up, and calling it DOWN sends you
 * looking for the wrong problem.
 */
const up = async (port, tries = 60) => {
  for (let i = 0; i < tries; i++) {
    try {
      await fetch(`http://localhost:${port}/`, { signal: AbortSignal.timeout(1500) });
      return true;
    } catch { /* not listening yet */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
};

const wanted = APPS.filter((a) => !only || a.name === only);
const running = [];

for (const app of wanted) {
  const b = build(app);
  if (!b.ok) {
    console.log(`skip  ${app.name}: ${b.why}`);
    continue;
  }
  start(app);
  running.push(app);
}

console.log('\nwaiting for servers…\n');
for (const app of running) {
  const ok = await up(app.port);
  console.log(`  ${ok ? 'up  ' : 'DOWN'}  ${app.name}     http://localhost:${app.port}`);
}

console.log('\nleft running. Ctrl-C to stop everything.');

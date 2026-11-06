// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

// Tests for opencode-plugin.mjs. Instead of mocking child_process, each test
// points the plugin at a tiny shell script standing in for the guard binary:
// it records the argv and stdin it got, then prints a canned response and
// exits with a canned code. That exercises the real spawn/stdin/stdout path
// the plugin uses in production.
//
// Run with: node --test packages/hooks/opencode-plugin.test.mjs

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const PLUGIN_SRC = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'opencode-plugin.mjs'),
  'utf8',
);

// The fake guard is a POSIX shell script, so these tests need a POSIX host.
const skip = process.platform === 'win32' ? 'fake guard is a POSIX shell script' : false;

let root;
let seq = 0;

before(() => { root = mkdtempSync(join(tmpdir(), 'sg-opencode-plugin-')); });
after(() => { rmSync(root, { recursive: true, force: true }); });

function scratch() {
  const dir = join(root, String(++seq));
  mkdirSync(dir, { recursive: true });
  return dir;
}

// Writes a fake guard binary at path. Every call records its argv and stdin
// next to itself, then replies with `response` (an object, a raw string, or
// nothing) and exits with `code`.
function fakeGuard(path, { code = 0, response } = {}) {
  mkdirSync(dirname(path), { recursive: true });
  const dir = dirname(path);
  const body = response === undefined ? ''
    : typeof response === 'string' ? response
      : JSON.stringify(response);
  writeFileSync(join(dir, 'response'), body);
  writeFileSync(path, [
    '#!/bin/sh',
    'd=$(dirname "$0")',
    'printf "%s\\n" "$@" > "$d/args"',
    'cat > "$d/stdin"',
    'cat "$d/response"',
    `exit ${code}`,
    '',
  ].join('\n'));
  chmodSync(path, 0o755);
  return {
    called: () => existsSync(join(dir, 'stdin')),
    args: () => readFileSync(join(dir, 'args'), 'utf8').trim().split('\n'),
    stdin: () => JSON.parse(readFileSync(join(dir, 'stdin'), 'utf8')),
  };
}

// Loads a fresh copy of the plugin. `baked` mimics the install step
// substituting the guard path; leave it out to load the plugin unbaked, as a
// repo checkout would be. `home` and `platform` are in effect while the module
// evaluates, which is when it resolves the guard path.
async function loadPlugin({ baked, home, platform } = {}) {
  const src = baked === undefined
    ? PLUGIN_SRC
    : PLUGIN_SRC.replace('__SOLONGATE_GUARD_BIN__', baked);
  const file = join(scratch(), 'opencode-plugin.mjs');
  writeFileSync(file, src);

  const savedHome = process.env.HOME;
  const savedPlatform = Object.getOwnPropertyDescriptor(process, 'platform');
  if (home !== undefined) process.env.HOME = home;
  if (platform !== undefined) Object.defineProperty(process, 'platform', { ...savedPlatform, value: platform });
  try {
    const mod = await import(pathToFileURL(file).href);
    return await mod.SolonGate({ directory: '/work/project' });
  } finally {
    if (savedHome === undefined) delete process.env.HOME; else process.env.HOME = savedHome;
    Object.defineProperty(process, 'platform', savedPlatform);
  }
}

async function waitFor(cond, ms = 3000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('timed out waiting for the fake guard to be called');
}

describe('guard binary resolution', { skip }, () => {
  test('uses the baked path when it exists', async () => {
    const bin = join(scratch(), 'bin', 'solongate-guard');
    const guard = fakeGuard(bin);
    const hooks = await loadPlugin({ baked: bin, home: scratch() });
    await hooks['tool.execute.before']({ tool: 'bash' }, { args: {} });
    assert.ok(guard.called());
  });

  test('falls back to ~/.solongate/bin/solongate-guard when the plugin is unbaked', async () => {
    const home = scratch();
    const guard = fakeGuard(join(home, '.solongate', 'bin', 'solongate-guard'));
    const hooks = await loadPlugin({ home, platform: 'linux' });
    await hooks['tool.execute.before']({ tool: 'bash' }, { args: {} });
    assert.ok(guard.called());
  });

  test('falls back when the baked path no longer exists', async () => {
    const home = scratch();
    const guard = fakeGuard(join(home, '.solongate', 'bin', 'solongate-guard'));
    const hooks = await loadPlugin({ baked: join(scratch(), 'gone', 'solongate-guard'), home, platform: 'darwin' });
    await hooks['tool.execute.before']({ tool: 'bash' }, { args: {} });
    assert.ok(guard.called());
  });

  test('the fallback carries .exe on Windows (#191)', async () => {
    const home = scratch();
    const plain = fakeGuard(join(home, '.solongate', 'bin', 'plain', 'solongate-guard'));
    const exe = fakeGuard(join(home, '.solongate', 'bin', 'solongate-guard.exe'));
    const hooks = await loadPlugin({ home, platform: 'win32' });
    await hooks['tool.execute.before']({ tool: 'bash' }, { args: {} });
    assert.ok(exe.called(), 'expected the .exe guard to be spawned');
    assert.ok(!plain.called());
  });
});

describe('tool.execute.before', { skip }, () => {
  async function setup(guardOpts) {
    const bin = join(scratch(), 'solongate-guard');
    const guard = fakeGuard(bin, guardOpts);
    const hooks = await loadPlugin({ baked: bin });
    return { guard, before: hooks['tool.execute.before'] };
  }

  test('sends the OpenCode tool call to the guard', async () => {
    const { guard, before } = await setup();
    await before(
      { tool: 'bash', sessionID: 's1', callID: 'c1' },
      { args: { command: 'ls' } },
    );
    assert.deepEqual(guard.args(), ['opencode', 'OpenCode']);
    assert.deepEqual(guard.stdin(), {
      tool_name: 'bash',
      tool_input: { command: 'ls' },
      session_id: 's1',
      tool_use_id: 'c1',
      cwd: '/work/project',
    });
  });

  test('exit code 2 blocks the call with the guard reason', async () => {
    const { before } = await setup({
      code: 2,
      response: { hookSpecificOutput: { permissionDecision: 'deny', permissionDecisionReason: 'no rm -rf' } },
    });
    await assert.rejects(before({ tool: 'bash' }, { args: {} }), { message: 'no rm -rf' });
  });

  test('exit code 2 without a reason still blocks', async () => {
    const { before } = await setup({ code: 2 });
    await assert.rejects(before({ tool: 'bash' }, { args: {} }), { message: '[SolonGate] Blocked by policy' });
  });

  test('an allow with updatedInput rewrites the args in place', async () => {
    const { before } = await setup({
      response: { hookSpecificOutput: { permissionDecision: 'allow', updatedInput: { command: 'ls -a' } } },
    });
    const output = { args: { command: 'ls', timeout: 5 } };
    await before({ tool: 'bash' }, output);
    assert.deepEqual(output.args, { command: 'ls -a', timeout: 5 });
  });

  test('updatedInput is ignored unless the decision is allow', async () => {
    const { before } = await setup({
      response: { hookSpecificOutput: { permissionDecision: 'ask', updatedInput: { command: 'ls -a' } } },
    });
    const output = { args: { command: 'ls' } };
    await before({ tool: 'bash' }, output);
    assert.deepEqual(output.args, { command: 'ls' });
  });

  test('non-JSON guard output fails open', async () => {
    const { before } = await setup({ response: 'not json' });
    const output = { args: { command: 'ls' } };
    await before({ tool: 'bash' }, output);
    assert.deepEqual(output.args, { command: 'ls' });
  });

  test('a missing guard binary fails open', async () => {
    const hooks = await loadPlugin({ baked: '/nonexistent/solongate-guard', home: scratch() });
    const output = { args: { command: 'ls' } };
    await hooks['tool.execute.before']({ tool: 'bash' }, output);
    assert.deepEqual(output.args, { command: 'ls' });
  });
});

describe('tool.execute.after', { skip }, () => {
  async function run(updatedToolOutput, output) {
    const bin = join(scratch(), 'solongate-guard');
    const guard = fakeGuard(bin, {
      response: updatedToolOutput === undefined ? {} : { hookSpecificOutput: { updatedToolOutput } },
    });
    const hooks = await loadPlugin({ baked: bin });
    await hooks['tool.execute.after']({ tool: 'bash', args: { command: 'env' }, sessionID: 's1', callID: 'c1' }, output);
    return guard;
  }

  test('sends an audit record to the guard', async () => {
    const guard = await run(undefined, { output: 'SECRET=1' });
    assert.deepEqual(guard.args(), ['audit', 'opencode', 'OpenCode']);
    assert.deepEqual(guard.stdin(), {
      tool_name: 'bash',
      tool_input: { command: 'env' },
      tool_response: 'SECRET=1',
      session_id: 's1',
      tool_use_id: 'c1',
      cwd: '/work/project',
    });
  });

  test('leaves the output alone when nothing was redacted', async () => {
    const output = { output: 'SECRET=1' };
    await run(undefined, output);
    assert.equal(output.output, 'SECRET=1');
  });

  test('a redacted string replaces the output', async () => {
    const output = { output: 'SECRET=1' };
    await run('SECRET=[REDACTED]', output);
    assert.equal(output.output, 'SECRET=[REDACTED]');
  });

  test('a redacted stdout replaces the output', async () => {
    const output = { output: 'SECRET=1' };
    await run({ stdout: 'SECRET=[REDACTED]' }, output);
    assert.equal(output.output, 'SECRET=[REDACTED]');
  });

  test('a redacted content replaces the output', async () => {
    const output = { output: 'SECRET=1' };
    await run({ content: 'SECRET=[REDACTED]' }, output);
    assert.equal(output.output, 'SECRET=[REDACTED]');
  });

  test('other redacted shapes merge into metadata', async () => {
    const output = { metadata: { exit: 0, diff: 'SECRET=1' } };
    await run({ diff: 'SECRET=[REDACTED]' }, output);
    assert.deepEqual(output.metadata, { exit: 0, diff: 'SECRET=[REDACTED]' });
  });
});

describe('event', { skip }, () => {
  async function setup() {
    const bin = join(scratch(), 'solongate-guard');
    const guard = fakeGuard(bin);
    const hooks = await loadPlugin({ baked: bin });
    return { guard, event: hooks.event };
  }

  test('reports token usage for a completed assistant message', async () => {
    const { guard, event } = await setup();
    await event({
      event: {
        type: 'message.updated',
        properties: {
          info: {
            id: 'm1',
            sessionID: 's1',
            role: 'assistant',
            time: { completed: 1700000000000 },
            tokens: { input: 10, output: 5, reasoning: 2, cache: { read: 3, write: 1 } },
          },
        },
      },
    });
    await waitFor(guard.called);
    assert.deepEqual(guard.args(), ['tokens', 'opencode', 'OpenCode']);
    assert.deepEqual(guard.stdin(), {
      opencode: true,
      tokens: true,
      session_id: 's1',
      turn_key: 'm1',
      agent_name: 'OpenCode',
      input: 10,
      output: 5,
      reasoning: 2,
      cache_read: 3,
      cache_write: 1,
      total: 21,
      at: 1700000000000,
    });
  });

  test('ignores user messages and assistant messages still streaming', async () => {
    const { guard, event } = await setup();
    const tokens = { input: 10, output: 5 };
    await event({ event: { type: 'message.updated', properties: { info: { role: 'user', time: { completed: 1 }, tokens } } } });
    await event({ event: { type: 'message.updated', properties: { info: { role: 'assistant', time: {}, tokens } } } });
    await event({ event: { type: 'message.part.updated' } });
    await event({});
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(!guard.called());
  });
});

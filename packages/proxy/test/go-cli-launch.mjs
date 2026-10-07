// SPDX-License-Identifier: Apache-2.0

/**
 * The `solongate` bin picks the Go CLI, and gives it back when it must.
 *
 * Two things are worth pinning here, and neither is about the CLI being fast.
 *
 * WHAT IS DELEGATED. The launcher hands human subcommands to Go and keeps the
 * MCP proxy runtime on TypeScript, because the proxy sits in front of every tool
 * call an agent makes and its Go implementation has no conformance suite. That
 * line is a deliberate one and this file is what stops it moving by accident —
 * a `--` invocation reaching the Go binary would be a silent change of what
 * enforces an agent's traffic.
 *
 * THAT THE LAUNCHER STAYS SMALL. It exists only because ESM hoists imports:
 * code at the top of index.ts runs after its whole module graph is evaluated, so
 * a prelude there would pay the cost it is trying to skip. A bundler that inlines
 * the fallback turns this file back into index.ts with extra steps, and the only
 * visible symptom is that nothing got faster. It happened once already, at
 * 690 KB, so the size is asserted rather than assumed.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { suite, check, note, done } from './harness.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const proxyDir = resolve(here, '..');
const LAUNCH = join(proxyDir, 'dist', 'cli-launch.js');
const rig = join(tmpdir(), 'sg-cli-launch');

if (!existsSync(LAUNCH)) {
  console.log('\ngo cli launch');
  console.log(`  SKIP  ${LAUNCH} is not built; run \`pnpm build\` in packages/proxy`);
  process.exit(0);
}

try { rmSync(rig, { recursive: true, force: true }); } catch { /* fresh anyway */ }
mkdirSync(rig, { recursive: true });

const marker = join(rig, 'called');
/** A stand-in CLI that records the argv it was handed, then exits `code`. */
function fakeCli(code = 0) {
  const p = join(rig, 'fake-solongate');
  writeFileSync(p, `#!/bin/sh\nprintf '%s\\n' "$@" > "${marker}"\nexit ${code}\n`);
  chmodSync(p, 0o755);
  return p;
}

function run(argv, env = {}) {
  try { rmSync(marker, { force: true }); } catch { /* not there */ }
  const r = spawnSync(process.execPath, [LAUNCH, ...argv], {
    encoding: 'utf-8', timeout: 30000, env: { ...process.env, ...env },
  });
  return {
    code: r.status,
    stdout: r.stdout || '',
    stderr: r.stderr || '',
    delegatedArgv: existsSync(marker) ? readFileSync(marker, 'utf-8').split('\n').filter(Boolean) : null,
  };
}

// ────────────────────────────────────────────────────────────────────────────

suite('go cli — the launcher stays a launcher');

{
  const bytes = statSync(LAUNCH).size;
  check('it is small enough to be worth having', bytes < 32 * 1024, true);
  note(`${(bytes / 1024).toFixed(1)} KB — index.js is ${(statSync(join(proxyDir, 'dist', 'index.js')).size / 1024).toFixed(0)} KB and must NOT be inlined into it`);
  const src = readFileSync(LAUNCH, 'utf-8');
  check('the fallback is still a runtime import', /import\(/.test(src), true);
}

suite('go cli — human subcommands are handed over');

{
  const bin = fakeCli(0);
  for (const argv of [[], ['doctor'], ['policy', 'list'], ['audit'], ['--version']]) {
    const r = run(argv, { SOLONGATE_CLI_BIN: bin });
    check(`\`solongate ${argv.join(' ') || '(no args)'}\` reaches the binary`, r.delegatedArgv !== null, true);
    if (r.delegatedArgv) check('  with its arguments intact', r.delegatedArgv, argv);
  }
}

suite('go cli — the MCP proxy runtime does NOT go to Go');

{
  const bin = fakeCli(0);
  const r = run(['--', 'node', 'server.js'], { SOLONGATE_CLI_BIN: bin, SOLONGATE_NO_GO_CLI: '' });
  check('a proxy invocation never reaches the binary', r.delegatedArgv, null);
  note('the Go MCP proxy exists; it has no conformance suite, and this is what enforces that distinction');
}

suite('go cli — the exit code is the binary\'s own');

{
  for (const code of [0, 1, 3]) {
    const r = run(['doctor'], { SOLONGATE_CLI_BIN: fakeCli(code) });
    check(`exit ${code} is passed through`, r.code, code);
  }
}

suite('go cli — 69 means "not mine", and falls through');

{
  // The binary's own signal for a command it does not implement. It must not
  // surface as a failure: the TypeScript can still run it.
  const r = run(['doctor'], { SOLONGATE_CLI_BIN: fakeCli(69) });
  check('the binary was asked', r.delegatedArgv, ['doctor']);
  check('but 69 was not reported as the answer', r.code === 69, false);
}

/**
 * Proof that the TypeScript entry ran.
 *
 * Not "a version was printed", which is what this test asserted at first and got
 * wrong. `solongate` is human-only: it refuses an AI agent or any
 * non-interactive process, and the suite usually runs under exactly that. The
 * refusal is not a failure to fall back — it is index.js speaking, and only
 * index.js can produce either of these lines. Both outcomes mean the fallback
 * worked; which one appears depends on who is running the tests.
 */
const reachedTypeScript = (r) => /SolonGate is human-only/.test(r.stdout + r.stderr)
  || /^\s*\d+\.\d+\.\d+\s*$/m.test(r.stdout);

suite('go cli — a missing binary falls back rather than failing');

{
  const r = run(['--version'], { SOLONGATE_CLI_BIN: join(rig, 'not-here') });
  check('the binary was not reached', r.delegatedArgv, null);
  check('the TypeScript CLI answered instead', reachedTypeScript(r), true);
  note('under an agent that answer is the human-only refusal, which only index.js prints');
}

suite('go cli — the escape hatch pins execution to TypeScript');

{
  const r = run(['--version'], { SOLONGATE_CLI_BIN: fakeCli(0), SOLONGATE_NO_GO_CLI: '1' });
  check('the binary was never touched', r.delegatedArgv, null);
  check('the TypeScript CLI answered', reachedTypeScript(r), true);
}

process.exitCode = done();

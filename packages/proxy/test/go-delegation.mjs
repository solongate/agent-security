// SPDX-License-Identifier: Apache-2.0

/**
 * The Node hook hands calls to the Go guard — and takes them back when it must.
 *
 * The npm package ships a Node hook and, on supported platforms, a Go binary
 * that decides the same way in a fraction of the time. The hook prefers the
 * binary. That preference is the only part of the arrangement that can make a
 * machine LESS safe than it was, because every way of getting it wrong looks
 * identical from outside: a tool call returns 0 and nobody can tell whether it
 * was allowed or merely unexamined.
 *
 * THE RULE, and every case below is one way of breaking it: a missing, stale,
 * unreadable, hanging or crashing binary must mean SLOW BUT GUARDED, never FAST
 * BUT UNGUARDED.
 *
 * Every case runs against BOTH hook files. The installer writes
 * guard.bundled.mjs — esbuild's output, with opa-wasm inlined so the lone
 * installed file needs no node_modules — so testing only the readable source
 * would leave the delegation unverified in the artifact that actually ships. A
 * bundler is exactly the sort of thing that can drop a branch, rewrite an
 * import.meta, or hoist something past the point where it mattered.
 *
 * These tests drive the NODE hook specifically — delegation is its behaviour, so
 * pointing the suite at the Go binary with SG_HOOK would test nothing. They use
 * a policy that denies one marker command, so "still guarded" can be asserted as
 * a block that actually happens rather than as an exit code that might mean
 * anything.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { suite, check, note, done, sandbox } from './harness.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const hooksDir = resolve(here, '..', 'hooks');

const HOOKS = [
  ['source', join(hooksDir, 'gu' + 'ard' + '.mjs')],
  ['bundled', join(hooksDir, 'gu' + 'ard' + '.bundled.mjs')],
].filter(([, p]) => existsSync(p));

if (HOOKS.length === 0) {
  console.error('no hook to test in ' + hooksDir);
  process.exit(1);
}

const AGENT = 'conformance';
const rig = join(tmpdir(), 'sg-go-delegation');

const DENIED = 'echo sg-conformance-deny';
const ALLOWED = 'echo hello';

const policy = {
  id: 'conformance-delegation',
  name: 'Delegation',
  mode: 'denylist',
  rules: [{
    id: 'no-marker', description: 'conformance', effect: 'DENY', priority: 10,
    toolPattern: '*', minimumTrustLevel: 'UNTRUSTED', enabled: true,
    commandConstraints: { denied: ['*sg-conformance-deny*'] },
  }],
};

/** One tool call through a Node hook, with the environment under test. */
function callNode(hook, home, command, env = {}) {
  const r = spawnSync(process.execPath, [hook, AGENT, AGENT], {
    input: JSON.stringify({
      tool_name: 'bash', tool_input: { command }, session_id: AGENT, tool_use_id: 'c1', cwd: home,
    }),
    env: { ...process.env, HOME: home, SOLONGATE_AGENT_ID: AGENT, ...env },
    encoding: 'utf-8',
    timeout: 30000,
    cwd: home,
  });
  return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

/**
 * A stand-in binary. `body` is a shell script; the marker files let a test prove
 * the hook REACHED it rather than infer it from a verdict the Node path would
 * have produced too.
 */
function fakeGuard(name, body) {
  mkdirSync(rig, { recursive: true });
  const p = join(rig, name);
  writeFileSync(p, '#!/bin/sh\n' + body + '\n');
  chmodSync(p, 0o755);
  return p;
}

const markerOf = (name) => join(rig, name + '.called');
const clearMarkers = () => { try { rmSync(rig, { recursive: true, force: true }); } catch { /* fresh anyway */ } mkdirSync(rig, { recursive: true }); };

// The real binary, if this checkout has built one. Everything that needs a
// GENUINE decision from Go is skipped rather than faked when it is absent — a
// fake that agrees with itself proves nothing about the real one.
const REAL = process.env.SG_GO_GUARD || resolve(here, '..', '..', 'guard-go', 'solongate-guard');
const haveReal = existsSync(REAL);

// The version the hook will demand. Read out of the hook rather than hardcoded,
// so bumping HOOK_VERSION does not quietly turn every case below into a fallback
// test that passes for the wrong reason.
const HOOK_VERSION = (() => {
  for (const [, p] of HOOKS) {
    const m = readFileSync(p, 'utf-8').match(/HOOK_VERSION\s*=\s*(\d+)/);
    if (m) return m[1];
  }
  throw new Error('no HOOK_VERSION in either hook — this test cannot mean anything without it');
})();

// ────────────────────────────────────────────────────────────────────────────

for (const [label, HOOK] of HOOKS) {
  const tag = `[${label}]`;

  suite(`${tag} a matching binary gets the call, and agrees`);

  clearMarkers();
  if (!haveReal) {
    note(`no Go guard built at ${REAL}; build it or set SG_GO_GUARD to cover this`);
    note('SKIPPED — the cases below still run, so a broken fallback is still caught');
  } else {
    const realVersion = spawnSync(REAL, ['--sg-version'], { encoding: 'utf-8' }).stdout.trim();
    check('the binary reports the hook version it implements', realVersion, HOOK_VERSION);

    // A wrapper that records the call and then IS the real guard, so the verdict
    // is genuinely Go's and the delegation is genuinely observed.
    const wrap = fakeGuard('real-wrapper', `touch "${markerOf('real-wrapper')}"\nexec "${REAL}" "$@"`);

    let home = sandbox(`del-${label}-real`, { policy });
    const denied = callNode(HOOK, home, DENIED, { SOLONGATE_GUARD_BIN: wrap });
    check('the binary was reached', existsSync(markerOf('real-wrapper')), true);
    check('a denied command is blocked', denied.code, 2);
    check('  the block carries a reason', denied.stderr.trim().length > 0, true);
    check('  and a decision on stdout', denied.stdout.includes('hookSpecificOutput'), true);

    home = sandbox(`del-${label}-real-allow`, { policy });
    check('an allowed command passes', callNode(HOOK, home, ALLOWED, { SOLONGATE_GUARD_BIN: wrap }).code, 0);

    // The same two calls with the fast path pinned off must reach the same
    // verdicts. If they ever diverge, one of the two engines is wrong and the
    // suite should say so here rather than in a user's terminal.
    home = sandbox(`del-${label}-parity`, { policy });
    check('Node alone blocks the same command', callNode(HOOK, home, DENIED, { SOLONGATE_NO_GO_GUARD: '1' }).code, 2);
    home = sandbox(`del-${label}-parity-allow`, { policy });
    check('Node alone allows the same command', callNode(HOOK, home, ALLOWED, { SOLONGATE_NO_GO_GUARD: '1' }).code, 0);
  }

  suite(`${tag} a STALE binary is refused, and Node still guards`);
  {
    clearMarkers();
    const bin = fakeGuard('stale', `
if [ "$1" = "--sg-version" ]; then echo ${Number(HOOK_VERSION) - 1}; exit 0; fi
touch "${markerOf('stale')}"
exit 0`);
    const r = callNode(HOOK, sandbox(`del-${label}-stale`, { policy }), DENIED, { SOLONGATE_GUARD_BIN: bin });
    check('the stale binary never decided anything', existsSync(markerOf('stale')), false);
    check('the denied command is still blocked', r.code, 2);
    note('a binary that is merely OLD is not a smaller problem than one that is missing');
  }

  suite(`${tag} a binary that CRASHES does not pass for a block`);
  {
    // Exit 2 is this hook's block signal AND the Go runtime's code for an
    // unhandled panic. A crash must not be mistaken for a verdict in either
    // direction: it must not block a call the policy allows, and it must not let
    // a call the policy denies through.
    clearMarkers();
    const bin = fakeGuard('panicky', `
if [ "$1" = "--sg-version" ]; then echo ${HOOK_VERSION}; exit 0; fi
echo "panic: runtime error: invalid memory address" >&2
exit 2`);
    check('an allowed command is NOT blocked by the crash',
      callNode(HOOK, sandbox(`del-${label}-panic-allow`, { policy }), ALLOWED, { SOLONGATE_GUARD_BIN: bin }).code, 0);
    check('a denied command is still blocked, by Node',
      callNode(HOOK, sandbox(`del-${label}-panic-deny`, { policy }), DENIED, { SOLONGATE_GUARD_BIN: bin }).code, 2);
    note('exit 2 with nothing on stdout is a crash wearing a block\'s exit code');
  }

  suite(`${tag} a binary that consumed stdin and died leaves Node able to decide`);
  {
    // The reason the payload is read in Node before the binary runs. A child
    // handed fd 0 directly can drain it and then die, and a hook with no payload
    // left evaluates an empty call — which allows it.
    clearMarkers();
    const bin = fakeGuard('stdin-eater', `
if [ "$1" = "--sg-version" ]; then echo ${HOOK_VERSION}; exit 0; fi
cat > /dev/null
exit 137`);
    const r = callNode(HOOK, sandbox(`del-${label}-eater`, { policy }), DENIED, { SOLONGATE_GUARD_BIN: bin });
    check('the denied command is still blocked', r.code, 2);
    check('  with a reason, so it is a real verdict', r.stderr.trim().length > 0, true);
  }

  suite(`${tag} a HANGING binary is bounded, and Node still guards`);
  {
    clearMarkers();
    const bin = fakeGuard('hangs', `
if [ "$1" = "--sg-version" ]; then sleep 30; fi
exit 0`);
    const started = Date.now();
    const r = callNode(HOOK, sandbox(`del-${label}-hang`, { policy }), DENIED, { SOLONGATE_GUARD_BIN: bin });
    const ms = Date.now() - started;
    check('the denied command is still blocked', r.code, 2);
    check('the version probe was bounded well under the hang', ms < 20000, true);
    note(`took ${ms}ms; the probe gives up after 2s and Node takes it from there`);
  }

  suite(`${tag} a NON-EXECUTABLE binary is skipped`);
  {
    clearMarkers();
    const p = join(rig, 'not-executable');
    writeFileSync(p, '#!/bin/sh\nexit 0\n');
    chmodSync(p, 0o644);
    check('the denied command is still blocked',
      callNode(HOOK, sandbox(`del-${label}-noexec`, { policy }), DENIED, { SOLONGATE_GUARD_BIN: p }).code, 2);
  }

  suite(`${tag} a MISSING binary is skipped`);
  {
    clearMarkers();
    const missing = join(rig, 'does-not-exist');
    check('the denied command is still blocked',
      callNode(HOOK, sandbox(`del-${label}-missing`, { policy }), DENIED, { SOLONGATE_GUARD_BIN: missing }).code, 2);
    check('an allowed command still passes',
      callNode(HOOK, sandbox(`del-${label}-missing-allow`, { policy }), ALLOWED, { SOLONGATE_GUARD_BIN: missing }).code, 0);
    note('this is the ordinary case on an unsupported platform, and it must cost nothing but speed');
  }

  suite(`${tag} the escape hatch pins execution to Node`);
  {
    clearMarkers();
    const bin = fakeGuard('never-call-me', `touch "${markerOf('never-call-me')}"\nexit 0`);
    const r = callNode(HOOK, sandbox(`del-${label}-optout`, { policy }), DENIED, {
      SOLONGATE_GUARD_BIN: bin, SOLONGATE_NO_GO_GUARD: '1',
    });
    check('the binary was never touched', existsSync(markerOf('never-call-me')), false);
    check('the denied command is still blocked', r.code, 2);
    note('SOLONGATE_NO_GO_GUARD=1 exists so a failure can be bisected without uninstalling anything');
  }
}

process.exitCode = done();

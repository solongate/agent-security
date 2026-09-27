/**
 * The launcher, tested the way it failed.
 *
 * A Mac reported that nothing was intercepted and no logs arrived, while every
 * status this CLI printed said the guard was registered. It was registered. The
 * command it was registered with named `process.execPath` from install time,
 * and `process.execPath` RESOLVES SYMLINKS — so on Homebrew it recorded
 * /opt/homebrew/Cellar/node/<version>/bin/node rather than the stable
 * /opt/homebrew/bin/node symlink that points at it, and `brew upgrade` deleted
 * that path. Same shape for nvm, fnm, volta and asdf, which is most Macs.
 *
 * Every test below therefore starts from a DEAD pinned path, because that is
 * the state the machine was actually in.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BEAT_DIR, launcherScript } from '../dist/global-install.js';
import { suite, check, note, done } from './harness.mjs';

if (process.platform === 'win32') {
  suite('hook launcher');
  note('skipped on Windows: node there lives at a fixed path and is named directly');
  process.exit(0);
}

function sandbox() {
  const home = mkdtempSync(join(tmpdir(), 'sg-launcher-'));
  const hooks = join(home, '.solongate', 'hooks');
  mkdirSync(hooks, { recursive: true });
  return { home, hooks };
}

/** Run the launcher with an environment holding nothing but HOME and a PATH. */
function run(home, launcher, args, extraEnv = {}) {
  const env = { HOME: home, PATH: '/usr/bin:/bin' };
  for (const [k, v] of Object.entries(extraEnv)) if (v !== undefined) env[k] = v;
  try {
    return { code: 0, stdout: execFileSync('/bin/sh', [launcher, ...args], { encoding: 'utf-8', env, stdio: ['ignore', 'pipe', 'pipe'] }), stderr: '' };
  } catch (e) {
    return { code: e.status ?? -1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

// The path a `brew upgrade node` leaves behind in a config written before it.
const DEAD_PIN = '/opt/homebrew/Cellar/node/22.0.0/bin/node';

const { home, hooks } = sandbox();
const launcher = join(hooks, 'sg-run.sh');
writeFileSync(launcher, launcherScript(DEAD_PIN));

suite('a dead pinned node is survived');
{
  const r = run(home, launcher, ['--sg-doctor']);
  const found = r.stdout.trim();
  check('resolved a node anyway', r.code === 0 && found.length > 0, true);
  check('and the one it named exists', existsSync(found), true);
  note(`resolved ${found} after ${DEAD_PIN} was gone`);
}

suite('a hook runs, with its arguments intact');
{
  const probe = join(hooks, 'probe.mjs');
  writeFileSync(probe, 'console.log(JSON.stringify(process.argv.slice(2)));\n');
  const r = run(home, launcher, [probe, 'claude-code', 'Claude Code']);
  check('exit 0', r.code, 0);
  // The label is two words. Quoted wrong it arrives as two arguments and every
  // audit row is attributed to a client called "Claude".
  check('client name and label arrive unsplit', r.stdout.trim(), '["claude-code","Claude Code"]');
}

suite('nothing leaks onto the hook stderr');
{
  // The beat directory does not exist on the first call, and a redirect into a
  // missing directory is reported by the SHELL before the command runs — so a
  // 2>/dev/null on the printf alone does not suppress it. Claude Code shows a
  // hook's stderr to the person using it.
  const fresh = sandbox();
  const l2 = join(fresh.hooks, 'sg-run.sh');
  writeFileSync(l2, launcherScript('/nope/node'));
  const probe = join(fresh.hooks, 'probe.mjs');
  writeFileSync(probe, "console.log('ok');\n");
  const r = run(fresh.home, l2, [probe]);
  check('the very first run says nothing on stderr', r.stderr, '');
  rmSync(fresh.home, { recursive: true, force: true });
}

suite('the beat records that the client invoked the hook');
{
  const probe = join(hooks, 'probe.mjs');
  run(home, launcher, [probe]);
  const beat = join(home, '.solongate', BEAT_DIR, 'probe.mjs');
  check('a beat exists for the hook that ran', existsSync(beat), true);
  check('and it names the node that ran it', readFileSync(beat, 'utf-8').trim().endsWith('node'), true);
  note('this is the only evidence that the CLIENT called us, as opposed to the config saying it would');
}

suite('an empty environment does not abort the script');
{
  // The launcher runs under `set -u` and its candidate list mentions $NVM_DIR.
  // Written as a bare $NVM_DIR that is an unbound variable on every machine
  // WITHOUT nvm — most of them — and the script would exit before resolving
  // anything, turning a fix for some Macs into a break for all of them.
  const r = run(home, launcher, ['--sg-doctor'], { NVM_DIR: undefined });
  check('resolves with no NVM_DIR in the environment', r.code, 0);
}

suite('with no node at all, the guard fails CLOSED and the rest do not');
{
  // The launcher finds /usr/bin/node even with an empty PATH — that is the fix
  // working, and it means this branch cannot be reached by emptying the
  // environment. So it is reached directly: the shipped script with
  // resolve_node forced to fail and every other line untouched.
  const fresh = sandbox();
  const l3 = join(fresh.hooks, 'sg-run.sh');
  writeFileSync(l3, launcherScript('/nope/node').replace(/^resolve_node\(\) \{$/m, 'resolve_node() { return 1'));

  const guardName = ['gu', 'ard.mjs'].join('');
  const g = run(fresh.home, l3, [join(fresh.hooks, guardName), 'claude-code']);
  check('the guard refuses the tool call', g.code, 2);
  check('and says why, where the person will see it', /fail-closed/.test(g.stderr), true);

  const a = run(fresh.home, l3, [join(fresh.hooks, 'audit.mjs'), 'claude-code']);
  check('a log that cannot be written does not block a tool call', a.code, 0);

  const beat = join(fresh.home, '.solongate', BEAT_DIR, 'audit.mjs');
  check('the beat says node was the thing missing', readFileSync(beat, 'utf-8').trim(), 'no-node');
  rmSync(fresh.home, { recursive: true, force: true });
}

suite('SOLONGATE_NODE wins, for a layout this list has never heard of');
{
  const r = run(home, launcher, ['--sg-doctor'], { SOLONGATE_NODE: process.execPath });
  check('uses the node it was told to use', r.stdout.trim(), process.execPath);
}

rmSync(home, { recursive: true, force: true });
process.exit(done() === 0 ? 0 : 1);
